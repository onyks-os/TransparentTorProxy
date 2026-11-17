#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Real Tor-over-WireGuard qualification, entirely inside two disposable VMs."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import shlex
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from qemu import Agent, create_overlay, inspect_capture, qmp

ROOT = Path(__file__).resolve().parents[3]
MAC = bytes.fromhex("525400123402")
UUID = "12345678-1234-4234-8234-123456789012"
ENDPOINT = "172.31.250.1"  # peer on the IPv4 underlay; also the DHCPv4 server
ENDPOINT6 = "fd31:250::1"  # fd00::/8 stays outside Tor's reserved fc00::/8 automap range
CLIENT4 = "172.31.250.20"
CLIENT6 = "fd31:250::20"
CANARY = {4: "198.51.100.7", 6: "2001:db8:100::7"}  # peer loopback, reachable directly
TUNNEL_CANARY = {4: "10.9.0.1", 6: "fd09::1"}  # peer inside the tunnel
BRIDGE = "198.51.100.8"
BRIDGE_PORT = 4443
SUSPEND_SECONDS = 200  # longer than the DHCP lease and WireGuard's 180 s session limit


@dataclass(frozen=True)
class Topology:
    underlay4: bool
    underlay6: bool
    endpoint6: bool
    tunnel6: bool

    @property
    def families(self) -> list[int]:
        return [4] * self.underlay4 + [6] * self.underlay6

    @property
    def tunnel_families(self) -> list[int]:
        return [4] + [6] * self.tunnel6

    def describe(self) -> str:
        underlay = {(True, False): "IPv4", (False, True): "IPv6", (True, True): "dual-stack"}
        return f"{underlay[self.underlay4, self.underlay6]} underlay, IPv{6 if self.endpoint6 else 4} endpoint, " + (
            "dual-stack tunnel" if self.tunnel6 else "IPv4 tunnel with --no-ipv6"
        )


TOPOLOGIES = {
    "v4-v4": Topology(True, False, False, False),
    "v4-dual": Topology(True, False, False, True),
    "v6-v4": Topology(False, True, True, False),
    "v6-dual": Topology(False, True, True, True),
    "dual-v4": Topology(True, True, False, False),
    "dual-dual": Topology(True, True, True, True),
}


def run(*args, **kwargs):
    kwargs.setdefault("timeout", 120)
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def image_digest(base: Path, checksums: Path) -> str:
    entries = [
        parts[0]
        for line in checksums.read_text().splitlines()
        if len(parts := line.split()) == 2 and parts[1].lstrip("*") == base.name
    ]
    with base.open("rb") as source:
        digest = hashlib.file_digest(source, "sha512").hexdigest()
    if entries != [digest]:
        raise ValueError(f"Image {base.name} does not match its SHA512 checksum")
    return digest


def copy_to_guest(vm, source: Path, destination: str):
    subprocess.run(
        [
            "scp",
            "-q",
            "-i",
            str(vm.key),
            "-P",
            str(vm.port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            str(source),
            f"ttp@127.0.0.1:{destination}",
        ],
        check=True,
        timeout=60,
    )


class VM:
    def __init__(
        self,
        name: str,
        work: Path,
        control: Path,
        base: Path,
        key: Path,
        network: str,
        *,
        memory: int = 1536,
        extra_packages: tuple[str, ...] = (),
        firmware_code: Path | None = None,
        firmware_vars: Path | None = None,
    ):
        self.work = work / name
        self.work.mkdir()
        self.control = control / name
        self.control.mkdir()
        self.agent = Agent(self.control / "agent")
        self.port = free_port()
        self.key = key
        self.process = None
        create_overlay(base, self.work / "disk.qcow2")
        (self.work / "meta-data").write_text(
            f"instance-id: ttp-vpn-{name}-{time.time_ns()}\nlocal-hostname: vpn-{name}\n"
        )
        packages = ", ".join(
            (
                "qemu-guest-agent",
                "network-manager",
                "wireguard-tools",
                "nftables",
                "dnsmasq",
                "tor",
                "apparmor",
                "python3-venv",
                "curl",
                *extra_packages,
            )
        )
        (self.work / "user-data").write_text(f"""#cloud-config
users:
  - name: ttp
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - {key.with_suffix(".pub").read_text().strip()}
package_update: true
apt:
  conf: |
    APT::Install-Recommends "false";
    Acquire::Languages "none";
packages: [{packages}]
runcmd:
  - [systemctl, start, qemu-guest-agent]
""")
        run(
            "genisoimage",
            "-quiet",
            "-output",
            str(self.work / "seed.iso"),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            str(self.work / "user-data"),
            str(self.work / "meta-data"),
        )
        self.command = [
            "qemu-system-x86_64",
            "-machine",
            "pc,accel=kvm",
            "-cpu",
            "host",
            "-m",
            str(memory),
            "-smp",
            "2",
            "-global",
            "PIIX4_PM.disable_s3=0",
            "-display",
            "none",
            "-drive",
            f"file={self.work}/disk.qcow2,if=virtio",
            "-drive",
            f"file={self.work}/seed.iso,if=virtio,format=raw,readonly=on",
            "-netdev",
            f"user,id=wan,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device",
            "virtio-net-pci,netdev=wan,mac=52:54:00:12:34:10",
            "-netdev",
            f"socket,id=physical,{network}",
            "-device",
            f"virtio-net-pci,netdev=physical,mac=52:54:00:12:34:{'01' if name == 'peer' else '02'}",
            "-device",
            "virtio-serial",
            "-chardev",
            f"socket,path={self.control}/agent,server=on,wait=off,id=qga",
            "-device",
            "virtserialport,chardev=qga,name=org.qemu.guest_agent.0",
            "-qmp",
            f"unix:{self.control}/qmp,server=on,wait=off",
            "-serial",
            f"file:{self.work}/console.log",
        ]
        if (firmware_code is None) != (firmware_vars is None):
            raise ValueError("Both firmware code and variable template are required")
        if firmware_code is not None:
            shutil.copyfile(firmware_vars, self.work / "firmware-vars.fd")
            self.command.extend(
                [
                    "-drive",
                    f"if=pflash,format=raw,unit=0,readonly=on,file={firmware_code}",
                    "-drive",
                    f"if=pflash,format=raw,unit=1,file={self.work}/firmware-vars.fd",
                ]
            )

    def boot(self):
        with (self.work / "qemu.log").open("w") as log:
            self.process = subprocess.Popen(self.command, stdout=log, stderr=log)

    def ready(self):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError((self.work / "qemu.log").read_text())
            try:
                self.agent.call("guest-ping")
                break
            except (OSError, RuntimeError):
                time.sleep(3)
        else:
            raise TimeoutError(f"{self.work.name}: QGA not ready; see console.log")
        code, output = self.agent.run("cloud-init status --wait --long", timeout=900, check=False)
        (self.work / "cloud-init.txt").write_text(output)
        if code:
            raise RuntimeError(f"cloud-init failed ({code}): {output}")

    def status(self) -> str:
        return qmp(self.control / "qmp", "query-status")["status"]

    def wait_status(self, expected: set[str], timeout: float):
        deadline = time.monotonic() + timeout
        while (status := self.status()) not in expected:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{self.work.name}: status {status}, expected {sorted(expected)}")
            time.sleep(0.5)

    def wait_agent(self, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.agent.call("guest-ping")
                return
            except (OSError, RuntimeError, ValueError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{self.work.name}: QGA unavailable; see console.log") from None
                time.sleep(2)

    def capture(self, name):
        path = self.work / f"{name}.pcap"
        qmp(
            self.control / "qmp",
            "object-add",
            {"qom-type": "filter-dump", "id": "capture", "netdev": "physical", "file": str(path), "maxlen": 768},
        )
        return path

    def stop_capture(self):
        qmp(self.control / "qmp", "object-del", {"id": "capture"})

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


INTERFACES = """
physical=$(for d in /sys/class/net/*; do
  [ "$(cat "$d/address")" != MAC_ADDRESS ] || basename "$d"
done)
test -n "$physical"
"""


def peer_script(t: Topology) -> str:
    network = ["[Match]", "Name=$physical", "[Network]"]
    network += ["Address=172.31.250.1/24"] * t.underlay4 + [f"Address={ENDPOINT6}/64"] * t.underlay6
    network += ["DHCP=no", "IPv6AcceptRA=no", f"LinkLocalAddressing={'ipv6' if t.underlay6 else 'no'}"]
    dnsmasq = ["--keep-in-foreground", "--port=0", "--bind-interfaces", '--interface="$physical"', "--log-dhcp"]
    if t.underlay4:
        dnsmasq += [
            "--dhcp-range=172.31.250.20,172.31.250.20,255.255.255.0,120s",
            "--dhcp-option=3,172.31.250.1",
            "--dhcp-option=6,1.1.1.1",
        ]
    if t.underlay6:
        # Stateful DHCPv6 with a 120 s lease renews like DHCPv4; RAs make the
        # peer the underlay's IPv6 default router, as a real LAN would.
        dnsmasq += [f"--dhcp-range={CLIENT6},{CLIENT6},64,120s", "--enable-ra", '--ra-param="$physical",10,1800']
    return (
        'nmcli device set "$physical" managed no\nmkdir -p /run/systemd/network\n'
        "cat > /run/systemd/network/00-qualification.network <<NETWORK\n"
        + "\n".join(network)
        + '\nNETWORK\nnetworkctl reload\nnetworkctl reconfigure "$physical"\nip link set "$physical" up\n'
        + 'ip addr replace 172.31.250.1/24 dev "$physical"\n' * t.underlay4
        + f'ip -6 addr replace {ENDPOINT6}/64 dev "$physical" nodad\n' * t.underlay6
        + f"ip addr add {CANARY[4]}/32 dev lo\nip -6 addr add {CANARY[6]}/128 dev lo\n"
        + r"""sysctl -w net.ipv4.ip_forward=1
wan=$(ip -j route show default | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["dev"])')
nft add table ip qualification
nft 'add chain ip qualification nat { type nat hook postrouting priority srcnat; }'
nft add rule ip qualification nat oifname "$wan" masquerade
# Response-independent counters: tunnel arrivals at the inner canary must stay
# zero while protected; forwarded TCP shows whether Tor reached public relays.
nft -f - <<'NFT'
table inet observe {
  chain input {
    type filter hook input priority -300; policy accept;
    iifname "wgpeer" meta nfproto ipv4 tcp dport 8000 counter comment "tunnel4"
    iifname "wgpeer" meta nfproto ipv6 tcp dport 8000 counter comment "tunnel6"
    iifname "wgpeer" ip daddr BRIDGE tcp dport BRIDGE_PORT counter comment "bridge"
  }
  chain forward {
    type filter hook forward priority -300; policy accept;
    iifname "wgpeer" meta l4proto tcp counter comment "forward_tcp"
  }
}
NFT
wg genkey > /root/peer.key
chmod 600 /root/peer.key
wg pubkey < /root/peer.key > /root/peer.pub
ip link add wgpeer type wireguard
ip address add 10.9.0.1/24 dev wgpeer
""".replace("BRIDGE_PORT", str(BRIDGE_PORT)).replace("BRIDGE", BRIDGE)
        + f"ip -6 address add {TUNNEL_CANARY[6]}/64 dev wgpeer\n" * t.tunnel6
        + """wg set wgpeer private-key /root/peer.key listen-port 51820
ip link set wgpeer up
systemctl stop dnsmasq
systemd-run --unit=qualification-dhcp /usr/sbin/dnsmasq """
        + " ".join(dnsmasq)
        + "\nsystemd-run --unit=qualification-canary python3 -m http.server 8000 --bind ::\n"
    )


# A private, unpublished obfs4 bridge on the peer: deterministic, and every
# client relay connection must reach it through the tunnel. Its own Tor
# connections to the public network leave from the peer, never the client.
BRIDGE_SETUP = r"""
ip addr add BRIDGE/32 dev lo
test -x /usr/bin/obfs4proxy
install -d -o debian-tor -g debian-tor -m 700 /var/lib/qualification-bridge
cat > /root/bridge.torrc <<'TORRC'
DataDirectory /var/lib/qualification-bridge
User debian-tor
BridgeRelay 1
PublishServerDescriptor 0
AssumeReachable 1
Address BRIDGE
ORPort BRIDGE:9001
ExtORPort auto
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 BRIDGE:BRIDGE_PORT
SocksPort 0
Log notice stdout
TORRC
systemd-run --unit=qualification-bridge /usr/bin/tor -f /root/bridge.torrc
for _ in $(seq 300); do
    if journalctl -u qualification-bridge --no-pager | grep -q 'Bootstrapped 100%' &&
        test -s /var/lib/qualification-bridge/pt_state/obfs4_bridgeline.txt; then
        break
    fi
    sleep 1
done
journalctl -u qualification-bridge --no-pager | grep -q 'Bootstrapped 100%'
fingerprint=$(cut -d' ' -f2 /var/lib/qualification-bridge/fingerprint)
cert=$(grep -o 'cert=[^ ]*' /var/lib/qualification-bridge/pt_state/obfs4_bridgeline.txt)
echo "obfs4 BRIDGE:BRIDGE_PORT $fingerprint $cert iat-mode=0"
""".replace("BRIDGE_PORT", str(BRIDGE_PORT)).replace("BRIDGE", BRIDGE)


def underlay_ready(t: Topology) -> str:
    """Wait for the underlay's DHCP/DHCPv6 addresses; fail if they never appear."""
    ready = ['ip -4 -o addr show dev "$physical" | grep -q " 172.31.250.20/"'] * t.underlay4
    ready += [f'ip -6 -o addr show dev "$physical" | grep " {CLIENT6}/" | grep -vq tentative'] * t.underlay6
    condition = " && ".join(ready)
    return f"""for _ in $(seq 90); do
    if {condition}; then break; fi
    sleep 1
done
{condition}
"""


def client_script(t: Topology) -> str:
    return f"""systemctl disable --now tor.service tor@default.service || true
if [ "$(systemctl show systemd-networkd.service -p LoadState --value)" = loaded ]; then
    systemctl disable --now systemd-networkd.service systemd-networkd.socket
fi
systemctl start NetworkManager
nmcli device set "$physical" managed yes
nmcli con add type ethernet ifname "$physical" con-name qualification-underlay \\
    ipv4.method {"auto" if t.underlay4 else "disabled"} ipv6.method {"auto" if t.underlay6 else "disabled"}
nmcli con up qualification-underlay
{underlay_ready(t)}wg genkey > /root/client.key
chmod 600 /root/client.key
wg pubkey < /root/client.key > /root/client.pub
"""


def canary(family: int, *, user: str | None = None) -> str:
    """A direct request routed over the underlay; reachable only without protection."""
    source, url = (CLIENT4, f"http://{CANARY[4]}:8000/") if family == 4 else (CLIENT6, f"http://[{CANARY[6]}]:8000/")
    command = f"curl -g --noproxy '*' --interface {source} --max-time 3 -o /dev/null '{url}'"
    return f"runuser -u {user} -- {command}" if user else command


def tunnel_canary(family: int, *, user: str | None = None) -> str:
    """A non-Tor request routed into the tunnel; it must never arrive in cleartext."""
    host = TUNNEL_CANARY[family] if family == 4 else f"[{TUNNEL_CANARY[family]}]"
    command = f"curl -g --noproxy '*' --max-time 3 -o /dev/null 'http://{host}:8000/'"
    return f"runuser -u {user} -- {command}" if user else command


ROUTES = {
    4: f"ip route replace {CANARY[4]}/32 via {ENDPOINT}\n",
    6: f"ip -6 route replace {CANARY[6]}/128 via {ENDPOINT6}\n",
}
CANARY_KEY = {family: f"{CANARY[family]}/proto6/port8000" for family in (4, 6)}


def denied(command: str) -> str:
    return f"if {command}; then echo 'A forbidden path was reachable' >&2; exit 1; fi\n"


def probe_script(t: Topology) -> str:
    """Continuous stimulus across transitions: root (redirected), an ordinary
    user, and Tor's UID on the underlay route, which only the guard stops.
    Tor's UID is deliberately absent from the tunnel canary: that path is the
    allowed one."""
    lines = []
    for family in t.families:
        lines += [canary(family), canary(family, user="nobody"), canary(family, user="debian-tor")]
    for family in t.tunnel_families:
        lines += [tunnel_canary(family), tunnel_canary(family, user="nobody")]
    # Parallel, short attempts: a dropped request must not stall the stimulus.
    body = "".join(f"    {line.replace('--max-time 3', '--max-time 1')} >/dev/null 2>&1 &\n" for line in lines)
    return (
        "cat > /root/probe.sh <<'PROBE'\n#!/bin/bash\nwhile :; do\n"
        + body
        + "    wait\n    sleep 0.5\ndone\nPROBE\nchmod 700 /root/probe.sh\n"
        # Stop as late as possible: after NetworkManager and TTP's own units.
        + "systemd-run --unit=qualification-probe -p DefaultDependencies=no -p Before=NetworkManager.service "
        + "-p Before=ttp-tor.service -p Before=ttp-watchdog.service /root/probe.sh\n"
    )


# A link-layer control remains observable when emergency rules silence IP.
# This adds no IP/firewall exception to the policy under test.
ARP_TICK = """python3 - <<'PY'
import socket, struct
from pathlib import Path
mac = bytes.fromhex("525400123402")
iface = next(p.name for p in Path("/sys/class/net").iterdir() if p.joinpath("address").read_text().strip() == "52:54:00:12:34:02")
frame = bytes.fromhex("ffffffffffff") + mac + bytes.fromhex("0806")
frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
frame += mac + socket.inet_aton("172.31.250.20") + bytes(6) + socket.inet_aton("172.31.250.1")
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as stream:
    stream.bind((iface, 0))
    stream.send(frame)
PY
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True, help="Debian 13 genericcloud qcow2")
    parser.add_argument("--checksums", type=Path, required=True, help="Published SHA512SUMS matching the base")
    parser.add_argument("--work", type=Path, required=True, help="New directory, never reused")
    parser.add_argument("--topology", choices=sorted(TOPOLOGIES), default="v4-v4", help="Underlay/tunnel IP families")
    parser.add_argument("--bridge", action="store_true", help="Bootstrap Tor only through a private obfs4 bridge")
    parser.add_argument(
        "--transitions", action="store_true", help="Also qualify suspend/resume and reboot with a continuous probe"
    )
    parser.add_argument("--client-base", type=Path, help="Optional separately prepared client image")
    parser.add_argument("--client-checksums", type=Path, help="SHA512SUMS of that prepared client image")
    parser.add_argument(
        "--client-os", choices=("debian", "parrot"), default="debian", help="Expected /etc/os-release ID"
    )
    parser.add_argument("--client-memory", type=int, default=2048, help="Client memory in MiB")
    parser.add_argument("--client-firmware-code", type=Path, help="Optional read-only raw UEFI code image")
    parser.add_argument("--client-firmware-vars", type=Path, help="Matching raw UEFI variable template, copied per run")
    parser.add_argument(
        "--client-deb", type=Path, help="Install this native TTP development DEB instead of a source venv"
    )
    parser.add_argument(
        "--require-apparmor", action="store_true", help="Require active AppArmor and test real confinement loss"
    )
    args = parser.parse_args()
    args.base = args.base.resolve()
    if (args.client_base is None) != (args.client_checksums is None):
        parser.error("--client-base requires its matching --client-checksums")
    if (args.client_firmware_code is None) != (args.client_firmware_vars is None):
        parser.error("UEFI code and variable template must be provided together")
    if args.client_os == "parrot" and (args.client_base is None or args.client_deb is None):
        parser.error("Parrot qualification requires a prepared client image and native --client-deb")
    if args.client_memory < 1024:
        parser.error("Client memory must be at least 1024 MiB")
    try:
        digest = image_digest(args.base, args.checksums)
        client_base = args.client_base.resolve() if args.client_base else args.base
        client_digest = image_digest(client_base, args.client_checksums or args.checksums)
    except ValueError as exc:
        parser.error(str(exc))
    topology = TOPOLOGIES[args.topology]
    endpoint = ENDPOINT6 if topology.endpoint6 else ENDPOINT
    dhcp_server = ENDPOINT if topology.underlay4 else None
    work = args.work.resolve()
    work.mkdir(mode=0o700)  # refuse old disks, PIDs and stale evidence
    report = {
        "started": datetime.now(UTC).isoformat(),
        "commit": run("git", "rev-parse", "HEAD", cwd=ROOT),
        "base_sha512": digest,
        "client_base_sha512": client_digest,
        "client_os": args.client_os,
        "install_mode": "native_deb" if args.client_deb else "source_venv",
        "topology_id": args.topology,
        "topology": topology.describe(),
        "bridge": "private obfs4 bridge through the tunnel" if args.bridge else None,
        "transitions": args.transitions,
        "checks": {},
    }
    report_path = work / "results.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")

    def record(name, data):
        report["checks"][name] = data
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{name}: {data}", flush=True)

    with tempfile.TemporaryDirectory(prefix="ttp-vpn-") as sockets, contextlib.ExitStack() as stack:
        control = Path(sockets)
        key = control / "key"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        port = free_port()
        bridge_packages = ("obfs4proxy",) if args.bridge else ()
        peer = VM("peer", work, control, args.base, key, f"listen=127.0.0.1:{port}", extra_packages=bridge_packages)
        client = VM(
            "client",
            work,
            control,
            client_base,
            key,
            f"connect=127.0.0.1:{port}",
            memory=args.client_memory,
            extra_packages=bridge_packages,
            firmware_code=args.client_firmware_code,
            firmware_vars=args.client_firmware_vars,
        )
        stack.callback(peer.close)
        stack.callback(client.close)

        def counters():
            """Peer-side packet counters; these do not depend on any reply."""
            data = json.loads(peer.agent.run("nft -j list table inet observe")[1])["nftables"]
            values = {}
            for item in data:
                rule = item.get("rule", {})
                for expression in rule.get("expr", []):
                    if "counter" in expression and "comment" in rule:
                        values[rule["comment"]] = expression["counter"]["packets"]
            if set(values) != {"tunnel4", "tunnel6", "bridge", "forward_tcp"}:
                raise RuntimeError(f"Peer observation counters incomplete: {values}")
            return values

        def delta(before, after):
            return {name: after[name] - before[name] for name in after}

        try:
            peer.boot()
            deadline = time.monotonic() + 20
            while True:
                try:
                    qmp(peer.control / "qmp", "query-status")
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Peer's network backend did not become ready")
                    time.sleep(0.2)
            client.boot()
            for vm in (peer, client):
                print(f"Provisioning {vm.work.name}...", flush=True)
                vm.ready()
            info = json.loads(
                client.agent.run(
                    "python3 -c 'import json,platform; print(json.dumps(platform.freedesktop_os_release()))'"
                )[1]
            )
            if info["ID"] != args.client_os:
                raise RuntimeError(f"Expected {args.client_os}, found {info['ID']}")
            report["client_os_release"] = info
            peer.agent.run(INTERFACES.replace("MAC_ADDRESS", "52:54:00:12:34:01") + peer_script(topology))
            bridge_line = None
            if args.bridge:
                print("Bootstrapping the private bridge...", flush=True)
                # QGA returns stdout followed by stderr; select the one bridge line.
                output = peer.agent.run(BRIDGE_SETUP, timeout=360)[1]
                lines = [line for line in output.splitlines() if line.startswith(f"obfs4 {BRIDGE}:{BRIDGE_PORT} ")]
                if len(lines) != 1:
                    raise RuntimeError(f"Expected exactly one bridge line: {output}")
                bridge_line = lines[0]
                report["bridge_line_prefix"] = " ".join(bridge_line.split()[:3])
            # Transfer only tracked repository files; never copy local handoffs or VM images.
            archive = work / "source.tar.gz"
            names = run("git", "ls-files", cwd=ROOT).splitlines()
            with tarfile.open(archive, "w:gz") as output:
                for name in names:
                    output.add(ROOT / name, arcname=name, recursive=False)
            with archive.open("rb") as source:
                report["source_archive_sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
            report["harness_sha256"] = {
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in ("run.py", "qemu.py")
            }
            # QGA carries commands during protection; SSH is used only for provisioning.
            if args.client_deb:
                with args.client_deb.open("rb") as package:
                    report["native_deb_sha256"] = hashlib.file_digest(package, "sha256").hexdigest()
                copy_to_guest(client, args.client_deb, "/tmp/ttp.deb")
                _, installation = client.agent.run(
                    'test "$(dpkg-deb -f /tmp/ttp.deb Package)" = transparent-tor-proxy\n'
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/ttp.deb\n"
                    "dpkg-query -W transparent-tor-proxy python3 python3-typer python3-rich python3-stem "
                    "python3-transitions nftables tor\npython3 -c 'import ttp; print(ttp.__file__)'",
                    timeout=300,
                )
                (client.work / "package-install.txt").write_text(installation)
                guest_python = "/usr/bin/python3"
            else:
                copy_to_guest(client, archive, "/tmp/source.tar.gz")
                client.agent.run(
                    "mkdir /opt/ttp; tar -xzf /tmp/source.tar.gz -C /opt/ttp; python3 -m venv /opt/ttp/venv\n"
                    "bash /opt/ttp/scripts/install_locked.sh /opt/ttp/venv/bin/python runtime /opt/ttp\n"
                    "ln -s /opt/ttp/venv/bin/ttp /usr/local/bin/ttp",
                    timeout=300,
                )
                guest_python = "/opt/ttp/venv/bin/python"
            # Install and copy first: handing the interfaces from networkd to
            # NM deliberately removes the provisioning NIC's IP configuration.
            client.agent.run(
                INTERFACES.replace("MAC_ADDRESS", "52:54:00:12:34:02") + client_script(topology), timeout=180
            )
            public = client.agent.run("cat /root/client.pub")[1].strip()
            allowed_peer = "10.9.0.2/32" + (",fd09::2/128" if topology.tunnel6 else "")
            peer.agent.run(f"wg set wgpeer peer {shlex.quote(public)} allowed-ips {allowed_peer}")
            remote = peer.agent.run("cat /root/peer.pub")[1].strip()
            private = client.agent.run("cat /root/client.key")[1].strip()
            profile = f"""[connection]
id=qualification-vpn
uuid={UUID}
type=wireguard
interface-name=wgtest
autoconnect=false
[wireguard]
private-key={private}
fwmark=51820
[wireguard-peer.{remote}]
endpoint={f"[{ENDPOINT6}]" if topology.endpoint6 else ENDPOINT}:51820
allowed-ips=0.0.0.0/0;{"::/0;" if topology.tunnel6 else ""}
persistent-keepalive=15
[ipv4]
method=manual
address1=10.9.0.2/24
dns=1.1.1.1;
dns-search=~.;
[ipv6]
""" + ("method=manual\naddress1=fd09::2/64\n" if topology.tunnel6 else "method=disabled\n")
            # The provisioning NIC is outside the observed path. Unmanage it
            # persistently: NetworkManager re-manages a runtime-unmanaged device
            # on wake and would reactivate it after reboot.
            provisioning_down = (
                "cat > /etc/NetworkManager/conf.d/99-qualification.conf <<'CONF'\n"
                "[keyfile]\nunmanaged-devices=mac:52:54:00:12:34:10\nCONF\n"
                "nmcli general reload conf\n"
                'ip link set $(for d in /sys/class/net/*; do [ "$(cat "$d/address")" != 52:54:00:12:34:10 ] '
                '|| basename "$d"; done) down\n'
            )
            client.agent.run(
                "umask 077\ncat > /etc/NetworkManager/system-connections/qualification.nmconnection <<'PROFILE'\n"
                + profile
                + "PROFILE\nnmcli con load /etc/NetworkManager/system-connections/qualification.nmconnection\n"
                + f"nmcli con up uuid {UUID}\n"
                + provisioning_down
                + "curl --fail --silent --show-error --max-time 30 https://deb.debian.org/debian/README"
            )
            record("vpn_internet_positive_control", "pass")
            record(
                "guest_versions",
                client.agent.run(
                    "cat /etc/os-release\nuname -r\nNetworkManager --version\nwg --version\ntor --version\n"
                    + ("/usr/bin/obfs4proxy -version || true\n" if args.bridge else "")
                    + f"{guest_python} -c 'import ttp; print(ttp.__version__)'"
                )[1],
            )

            def phase(name, script=None, *, action=None, protected=True, timeout=60, tick=True):
                path = client.capture(name)
                try:
                    if action is not None:
                        code, output = action()
                    else:
                        code, output = client.agent.run(script, timeout=timeout, check=False)
                    (client.work / f"{name}.txt").write_text(output)
                    if tick:
                        client.agent.run(ARP_TICK, timeout=5)
                finally:
                    client.stop_capture()
                evidence = inspect_capture(path, client_mac=MAC, endpoint=endpoint, dhcp_server=dhcp_server)
                record(name, {"protected": protected, "exitcode": code, **evidence})
                if code or (protected and evidence["violations"]):
                    raise RuntimeError(f"{name} failed; see {client.work / (name + '.txt')}")
                return evidence

            def require_direct_paths(name, evidence):
                missing = [CANARY_KEY[f] for f in topology.families if not evidence["violations"].get(CANARY_KEY[f])]
                if missing:
                    raise RuntimeError(f"{name}: capture did not detect reachable direct canaries {missing}")

            no_ipv6 = "" if topology.tunnel6 else " --no-ipv6"
            bridge_args = f" --use-bridges --bridge {shlex.quote(bridge_line)}" if bridge_line else ""
            start = (
                f"ttp start --require-vpn {UUID} --watchdog --no-lan-bypass{no_ipv6} --bootstrap-timeout 300"
                + bridge_args
            )
            # Force physical routing before/after protection for an honest leak control.
            routes = "".join(ROUTES[f] for f in topology.families)
            direct = "".join(canary(f) + "\n" for f in topology.families)
            evidence = phase("clear_control", routes + direct, protected=False)
            require_direct_paths("clear_control", evidence)
            before = counters()
            phase(
                "tunnel_control",
                "".join(tunnel_canary(f) + "\n" for f in topology.tunnel_families),
                protected=False,
            )
            arrived = delta(before, counters())
            record("tunnel_control_counters", arrived)
            if any(arrived[f"tunnel{f}"] <= 0 for f in topology.tunnel_families):
                raise RuntimeError("Peer did not count cleartext tunnel requests: observer inconclusive")
            before = counters()
            phase("tor_start", start, timeout=400)
            # A public Tor circuit can fail a TLS request (EOF, broken pipe)
            # without any containment fault. Up to three attempts, each logged
            # with its address family; leak verdicts come only from captures
            # and peer counters, never from this functional check.
            verified_request = (
                "for attempt in 1 2 3; do\n"
                "    if runuser -u ttp -- curl --fail --silent --show-error --max-time 60 "
                "-w '\\n%{stderr}remote=%{remote_ip}\\n' https://check.torproject.org/api/ip "
                '> /tmp/istor.json && python3 -c \'import json,sys; r=json.loads(open("/tmp/istor.json")'
                '.read().splitlines()[0]); print(r); assert r["IsTor"] is True\'; then\n'
                '        echo "IsTor verified on attempt $attempt"; break\n'
                "    fi\n"
                '    echo "IsTor attempt $attempt failed" >&2\n'
                '    if [ "$attempt" = 3 ]; then exit 1; fi\n'
                "    sleep 10\n"
                "done\n"
            )
            phase(
                "tor_dns",
                "set -o pipefail\n" + verified_request + "ttp check\nttp status --json",
                timeout=120,
            )
            startup = delta(before, counters())
            record("tor_start_counters", startup)
            if bridge_line:
                # Every Tor connection must reach the private bridge, none a public relay.
                if startup["bridge"] <= 0 or startup["forward_tcp"]:
                    raise RuntimeError(f"Tor did not use only the bridge through the tunnel: {startup}")
            elif startup["forward_tcp"] <= 0:
                raise RuntimeError("Peer did not count Tor's relay traffic: forward counter inconclusive")
            if startup["tunnel4"] or startup["tunnel6"]:
                raise RuntimeError(f"Cleartext application traffic entered the tunnel: {startup}")
            if args.require_apparmor:
                client.agent.run(
                    f"{guest_python} - <<'PY'\n"
                    "from ttp.apparmor import active\n"
                    "from ttp.session_report import observe_session\n"
                    "assert active()\n"
                    'assert observe_session()["apparmor"]["state"] == "enforced"\n'
                    "PY"
                )
            # New encrypted packets are required; silence alone cannot pass startup.
            if not report["checks"]["tor_dns"]["counts"].get("wireguard"):
                raise RuntimeError("No encrypted traffic during real Tor/DNS request")
            _, security = client.agent.run(
                "set +e\ncat /sys/module/apparmor/parameters/enabled\n"
                "systemctl is-active apparmor\n"
                "pid=$(systemctl show ttp-tor -p MainPID --value)\n"
                'printf "Tor PID %s confinement: " "$pid"\ncat "/proc/$pid/attr/current"\n'
                + ("pgrep -a obfs4proxy\ncat /proc/$(pgrep -o obfs4proxy)/attr/current\n" if bridge_line else "")
                + "if command -v aa-status >/dev/null; then aa-status --json; fi\ntrue",
                timeout=15,
                check=False,
            )
            (client.work / "security-state.txt").write_text(security)
            report["security_state_file"] = "client/security-state.txt"
            all_denied = "".join(denied(canary(f)) for f in topology.families) + "".join(
                denied(tunnel_canary(f)) for f in topology.tunnel_families
            )

            def tunnel_untouched(name, before):
                seen = delta(before, counters())
                record(f"{name}_counters", seen)
                if any(seen[f"tunnel{f}"] for f in (4, 6)):
                    raise RuntimeError(f"{name}: cleartext application traffic entered the tunnel: {seen}")

            before = counters()
            phase("tunnel_denied", all_denied, timeout=60)
            tunnel_untouched("tunnel_denied", before)
            phase(
                "dhcp_renewal",
                "set -o pipefail\nsleep 135\n" + verified_request + "ttp status --json",
                timeout=190,
            )
            counts = report["checks"]["dhcp_renewal"]["counts"]
            if topology.underlay4 and not counts.get("dhcp_renewals_acknowledged"):
                raise RuntimeError("No matching DHCP renewal request/ACK observed")
            if topology.underlay6 and not counts.get("dhcpv6_renewals_acknowledged"):
                raise RuntimeError("No matching DHCPv6 Renew/Reply observed")
            # The physical fallback exists; a re-created WG link is a new identity.
            emergency = (
                f"{guest_python} -c "
                "'from ttp.session_report import observe_session; r=observe_session(); print(r); "
                'assert r["health"] == "emergency_verified"; '
                'assert r["emergency"]["requested"] and r["emergency"]["verified"]\'\n'
            )
            denied_direct = "".join(denied(canary(f)) for f in topology.families)
            phase("tunnel_loss", f"nmcli con down uuid {UUID}\n" + denied_direct + "sleep 35\n" + emergency, timeout=65)
            phase(
                "reconnect_latched",
                f"nmcli con up uuid {UUID}\nsleep 5\n" + all_denied + emergency,
                timeout=60,
            )
            stopped = (
                "ttp stop\nif nft list table inet ttp_vpn; then exit 1; fi\ntest ! -e /run/ttp/vpn-intent.json\n"
                'test "$(systemctl show ttp-tor -p MainPID --value)" = 0\n'
                'test "$(systemctl show ttp-tor -p ControlPID --value)" = 0\n'
            )
            phase(
                "explicit_stop",
                stopped,
                # Explicit stop intentionally ends the guarantee. Restored
                # resolver services can immediately emit physical LLMNR, etc.
                protected=False,
            )
            evidence = phase("stop_control", routes + direct, protected=False)
            require_direct_paths("stop_control", evidence)
            if args.require_apparmor:
                phase("apparmor_start", start, timeout=400)
                phase(
                    "apparmor_loss",
                    "apparmor_parser --replace --skip-cache --Complain /run/ttp/ttp-tor.apparmor\n"
                    + (ROOT / "scripts/vm/vpn/apparmor-check.sh").read_text(),
                    timeout=65,
                )
                phase("apparmor_stop", "ttp stop", protected=False)
            if args.transitions:
                transitions(
                    client,
                    phase,
                    record,
                    counters,
                    delta,
                    tunnel_untouched,
                    require_direct_paths,
                    topology=topology,
                    start=start,
                    routes=routes,
                    verified_request=verified_request,
                    all_denied=all_denied,
                    emergency=emergency,
                    stopped=stopped,
                    guest_python=guest_python,
                    provisioning_down=provisioning_down,
                )
            report["finished"] = datetime.now(UTC).isoformat()
            record("result", "pass")
        except BaseException as exc:
            record("result", f"failed: {exc}")
            with contextlib.suppress(Exception):
                _, output = client.agent.run(
                    "cat /tmp/ttp*log 2>/dev/null || true\n"
                    # Separate journals: Tor's bootstrap must not crowd out the
                    # watchdog's exact integrity reason.
                    # TTP's own log carries the exact integrity reason.
                    "echo '== /run/ttp/ttp.log'; tail -n 200 /run/ttp/ttp.log\n"
                    "echo '== ttp-watchdog'; journalctl -b -u ttp-watchdog -n 300 --no-pager\n"
                    "echo '== resolver'; journalctl -b -u systemd-resolved -u NetworkManager -n 80 --no-pager\n"
                    "echo '== ttp-tor'; journalctl -b -u ttp-tor -n 100 --no-pager\n"
                    "echo '== inet ttp with counters'; nft list table inet ttp\n"
                    "nft list ruleset\nip route show table all\nip -6 route show table all\nip rule\nip -6 rule\n"
                    "ip addr\ncat /etc/resolv.conf\n"
                    "wg show wgtest latest-handshakes\nwg show wgtest transfer\nttp status --json",
                    check=False,
                )
                (client.work / "failure.txt").write_text(output)
            with contextlib.suppress(Exception):
                _, output = peer.agent.run(
                    "ip addr\nip route\nip -6 route\nnft list ruleset\nwg show wgpeer transfer\n"
                    "journalctl -u qualification-dhcp -n 40 --no-pager\n"
                    "journalctl -u qualification-bridge -n 60 --no-pager",
                    check=False,
                )
                (peer.work / "failure.txt").write_text(output)
            raise


def transitions(
    client,
    phase,
    record,
    counters,
    delta,
    tunnel_untouched,
    require_direct_paths,
    *,
    topology,
    start,
    routes,
    verified_request,
    all_denied,
    emergency,
    stopped,
    guest_python,
    provisioning_down,
):
    """Suspend/resume and reboot with a continuous stimulus (ADR 0015 gates).

    The probe first proves it emits observable direct and tunnel traffic. It
    then runs, protected, across S3 suspend/resume and across shutdown until
    QEMU pauses the guest at its reboot request, so the capture covers the
    whole shutdown sequence. Resume may keep the session or latch emergency;
    either is acceptable only with zero violations and a state that matches
    what the client can actually reach.
    """
    qmp_path = client.control / "qmp"
    probe = probe_script(topology)
    stop_probe = "systemctl stop qualification-probe\n"

    def probe_control():
        client.agent.run(probe)
        time.sleep(12)
        return client.agent.run(stop_probe)

    before = counters()
    evidence = phase("probe_control", action=probe_control, protected=False)
    require_direct_paths("probe_control", evidence)
    seen = delta(before, counters())
    record("probe_control_counters", seen)
    if any(seen[f"tunnel{f}"] <= 0 for f in topology.tunnel_families):
        raise RuntimeError("Probe did not reach the tunnel canary without protection: probe inconclusive")

    phase("suspend_start", start, timeout=400)
    before = counters()

    def suspend():
        client.agent.run(probe)
        time.sleep(10)
        client.agent.run("systemd-run --on-active=2 --unit=qualification-suspend systemctl suspend")
        client.wait_status({"suspended"}, 60)
        time.sleep(SUSPEND_SECONDS)
        qmp(qmp_path, "system_wakeup")
        client.wait_agent(120)
        time.sleep(45)  # NetworkManager and the watchdog react to the resume
        # Diagnostics precede the JSON observation; report_line selects it.
        return client.agent.run(
            "journalctl -b -u ttp-watchdog -u NetworkManager -u systemd-suspend --since=-10min "
            "--no-pager -o short-monotonic | tail -n 150\n"
            "systemctl is-active qualification-probe\n"
            f"{guest_python} -c 'import json; from ttp.session_report import observe_session; "
            "print(json.dumps(observe_session(), default=str))'\n",
            check=False,
        )

    phase("suspend_resume", action=suspend, timeout=SUSPEND_SECONDS + 200)
    observed = json.loads(report_line(client.work / "suspend_resume.txt"))
    outcome = "emergency_verified" if observed["health"] == "emergency_verified" else "session_kept"
    record("suspend_resume_outcome", {"outcome": outcome, "health": observed["health"], "vpn": observed.get("vpn")})
    if outcome == "emergency_verified":
        phase("after_resume", all_denied + emergency, timeout=60)
    else:
        phase("after_resume", "set -o pipefail\n" + verified_request + "ttp status --json", timeout=120)
    tunnel_untouched("suspend_resume", before)
    phase("suspend_stop", stop_probe + stopped, protected=False)

    # A fresh session for reboot. Reactivation runs unprotected: between the
    # old tunnel's removal and the new one, the host routes physically.
    phase("reboot_prepare", f"nmcli con up uuid {UUID}\nsleep 3\n", protected=False)
    phase("reboot_start", start + "\n" + verified_request, timeout=460)
    before = counters()

    def reboot():
        client.agent.run(probe)
        time.sleep(10)
        # QEMU pauses at the guest's reboot request instead of resetting, so the
        # capture ends exactly when the guest's shutdown sequence has finished.
        qmp(qmp_path, "set-action", {"reboot": "shutdown", "shutdown": "pause"})
        client.agent.run(ARP_TICK, timeout=5)
        client.agent.run("systemd-run --on-active=2 --unit=qualification-reboot systemctl reboot")
        client.wait_status({"shutdown", "paused"}, 240)
        return 0, "Guest paused at its reboot request\n"

    phase("reboot_shutdown", action=reboot, tick=False, timeout=300)
    tunnel_untouched("reboot_shutdown", before)
    qmp(qmp_path, "set-action", {"reboot": "reset", "shutdown": "poweroff"})
    qmp(qmp_path, "system_reset")
    qmp(qmp_path, "cont")
    client.wait_agent(600)
    # The boot ends the session (ADR 0015): no retained table, intent or lock.
    phase(
        "after_reboot",
        # The unmanaged-devices file persists; only wait for NetworkManager.
        "for _ in $(seq 60); do systemctl is-active -q NetworkManager && break; sleep 1; done\n"
        + "systemctl is-active -q NetworkManager\n"
        + provisioning_down.split("nmcli general reload conf\n", 1)[1]
        + "test ! -e /run/ttp/vpn-intent.json\n"
        + "if nft list table inet ttp_vpn >/dev/null 2>&1; then exit 1; fi\n"
        + "if nft list table inet ttp >/dev/null 2>&1; then exit 1; fi\n"
        + f"{guest_python} -c 'from ttp.session_report import observe_session; r=observe_session(); print(r); "
        + 'assert r["phase"] == "absent"\'\n'
        + "ttp status --json || true\n",
        protected=False,
        timeout=60,
    )
    # A new session works after reboot without manual recovery.
    phase(
        "restart_prepare",
        INTERFACES.replace("MAC_ADDRESS", "52:54:00:12:34:02")
        + underlay_ready(topology)
        + routes
        + f"nmcli con up uuid {UUID}\nsleep 3\n",
        protected=False,
        timeout=150,
    )
    phase("restart_after_reboot", start + "\n" + verified_request + "ttp status --json", timeout=460)
    phase("restart_stop", stopped, protected=False)


def report_line(path: Path) -> str:
    """The last JSON object line: QGA appends stderr after stdout."""
    lines = [line for line in path.read_text().splitlines() if line.startswith("{")]
    if not lines:
        raise RuntimeError(f"No JSON observation in {path}")
    return lines[-1]


if __name__ == "__main__":

    def terminate(signum, _frame):
        raise SystemExit(f"Controller received signal {signum}")

    signal.signal(signal.SIGTERM, terminate)
    main()
