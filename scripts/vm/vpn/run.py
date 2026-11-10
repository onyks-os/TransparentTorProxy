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
from datetime import UTC, datetime
from pathlib import Path

from qemu import Agent, create_overlay, inspect_capture, qmp

ROOT = Path(__file__).resolve().parents[3]
MAC = bytes.fromhex("525400123402")
UUID = "12345678-1234-4234-8234-123456789012"
ENDPOINT = "172.31.250.1"


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
        packages = (
            "qemu-guest-agent, network-manager, wireguard-tools, nftables, dnsmasq, tor, apparmor, python3-venv, curl"
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

PEER = r"""
nmcli device set "$physical" managed no
mkdir -p /run/systemd/network
cat > /run/systemd/network/00-qualification.network <<NETWORK
[Match]
Name=$physical
[Network]
Address=172.31.250.1/24
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
NETWORK
networkctl reload
networkctl reconfigure "$physical"
ip link set "$physical" up
ip addr replace 172.31.250.1/24 dev "$physical"
ip addr add 198.51.100.7/32 dev lo
sysctl -w net.ipv4.ip_forward=1
wan=$(ip -j route show default | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["dev"])')
nft add table ip qualification
nft 'add chain ip qualification nat { type nat hook postrouting priority srcnat; }'
nft add rule ip qualification nat oifname "$wan" masquerade
wg genkey > /root/peer.key
chmod 600 /root/peer.key
wg pubkey < /root/peer.key > /root/peer.pub
ip link add wgpeer type wireguard
ip address add 10.9.0.1/24 dev wgpeer
wg set wgpeer private-key /root/peer.key listen-port 51820
ip link set wgpeer up
systemctl stop dnsmasq
systemd-run --unit=qualification-dhcp /usr/sbin/dnsmasq --keep-in-foreground --port=0 \
  --bind-interfaces --interface="$physical" --dhcp-range=172.31.250.20,172.31.250.20,255.255.255.0,120s \
  --dhcp-option=3,172.31.250.1 --dhcp-option=6,1.1.1.1 --log-dhcp
systemd-run --unit=qualification-canary python3 -m http.server 8000 --bind 0.0.0.0
"""

CLIENT = r"""
systemctl disable --now tor.service tor@default.service || true
if [ "$(systemctl show systemd-networkd.service -p LoadState --value)" = loaded ]; then
    systemctl disable --now systemd-networkd.service systemd-networkd.socket
fi
systemctl start NetworkManager
nmcli device set "$physical" managed yes
nmcli con add type ethernet ifname "$physical" con-name qualification-underlay ipv4.method auto ipv6.method disabled
nmcli con up qualification-underlay
wg genkey > /root/client.key
chmod 600 /root/client.key
wg pubkey < /root/client.key > /root/client.pub
"""

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
    work = args.work.resolve()
    work.mkdir(mode=0o700)  # refuse old disks, PIDs and stale evidence
    report = {
        "started": datetime.now(UTC).isoformat(),
        "commit": run("git", "rev-parse", "HEAD", cwd=ROOT),
        "base_sha512": digest,
        "client_base_sha512": client_digest,
        "client_os": args.client_os,
        "install_mode": "native_deb" if args.client_deb else "source_venv",
        "topology": "IPv4 underlay and IPv4 tunnel, --no-ipv6",
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
        peer = VM("peer", work, control, args.base, key, f"listen=127.0.0.1:{port}")
        client = VM(
            "client",
            work,
            control,
            client_base,
            key,
            f"connect=127.0.0.1:{port}",
            memory=args.client_memory,
            firmware_code=args.client_firmware_code,
            firmware_vars=args.client_firmware_vars,
        )
        stack.callback(peer.close)
        stack.callback(client.close)
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
            peer.agent.run(INTERFACES.replace("MAC_ADDRESS", "52:54:00:12:34:01") + PEER)
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
            client.agent.run(INTERFACES.replace("MAC_ADDRESS", "52:54:00:12:34:02") + CLIENT)
            public = client.agent.run("cat /root/client.pub")[1].strip()
            peer.agent.run(f"wg set wgpeer peer {shlex.quote(public)} allowed-ips 10.9.0.2/32")
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
endpoint={ENDPOINT}:51820
allowed-ips=0.0.0.0/0;
persistent-keepalive=15
[ipv4]
method=manual
address1=10.9.0.2/24
dns=1.1.1.1;
dns-search=~.;
[ipv6]
method=disabled
"""
            client.agent.run(
                "umask 077\ncat > /etc/NetworkManager/system-connections/qualification.nmconnection <<'PROFILE'\n"
                + profile
                + "PROFILE\nnmcli con load /etc/NetworkManager/system-connections/qualification.nmconnection\n"
                + f"nmcli con up uuid {UUID}\n"
                + 'ip link set $(for d in /sys/class/net/*; do [ "$(cat "$d/address")" != 52:54:00:12:34:10 ] || basename "$d"; done) down\n'
                + "curl --fail --silent --show-error --max-time 30 https://deb.debian.org/debian/README"
            )
            record("vpn_internet_positive_control", "pass")
            record(
                "guest_versions",
                client.agent.run(
                    "cat /etc/os-release\nuname -r\nNetworkManager --version\nwg --version\ntor --version\n"
                    f"{guest_python} -c 'import ttp; print(ttp.__version__)'"
                )[1],
            )

            def phase(name, script, *, protected=True, timeout=60):
                path = client.capture(name)
                try:
                    code, output = client.agent.run(script, timeout=timeout, check=False)
                    (client.work / f"{name}.txt").write_text(output)
                    client.agent.run(ARP_TICK, timeout=5)
                finally:
                    client.stop_capture()
                evidence = inspect_capture(path, client_mac=MAC, endpoint=ENDPOINT)
                record(name, {"protected": protected, "exitcode": code, **evidence})
                if code or (protected and evidence["violations"]):
                    raise RuntimeError(f"{name} failed; see {client.work / (name + '.txt')}")
                return evidence

            canary = (
                "curl --noproxy '*' --interface "
                + ENDPOINT.replace(".1", ".20")
                + " --max-time 3 http://198.51.100.7:8000/"
            )
            # Force physical routing before/after protection for an honest leak control.
            route = "ip route replace 198.51.100.7/32 via 172.31.250.1\n"
            evidence = phase("clear_control", route + canary, protected=False)
            if not evidence["violations"].get("198.51.100.7/proto6/port8000"):
                raise RuntimeError("Capture did not detect the reachable direct canary")
            phase(
                "tor_start",
                f"ttp start --require-vpn {UUID} --watchdog --no-lan-bypass --no-ipv6 --bootstrap-timeout 300",
                timeout=400,
            )
            verified_request = (
                "runuser -u ttp -- curl --fail --max-time 60 https://check.torproject.org/api/ip | "
                "python3 -c 'import json,sys; r=json.load(sys.stdin); print(r); assert r[\"IsTor\"] is True'\n"
            )
            phase(
                "tor_dns",
                "set -o pipefail\n" + verified_request + "ttp check\nttp status --json",
                timeout=120,
            )
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
                "if command -v aa-status >/dev/null; then aa-status --json; fi\ntrue",
                timeout=15,
                check=False,
            )
            (client.work / "security-state.txt").write_text(security)
            report["security_state_file"] = "client/security-state.txt"
            phase(
                "dhcp_renewal",
                "set -o pipefail\nsleep 135\n" + verified_request + "ttp status --json",
                timeout=190,
            )
            if not report["checks"]["dhcp_renewal"]["counts"].get("dhcp_renewals_acknowledged"):
                raise RuntimeError("No matching DHCP renewal request/ACK observed")
            # The physical fallback exists; a re-created WG link is a new identity.
            emergency = (
                f"{guest_python} -c "
                "'from ttp.session_report import observe_session; r=observe_session(); print(r); "
                'assert r["health"] == "emergency_verified"; '
                'assert r["emergency"]["requested"] and r["emergency"]["verified"]\'\n'
            )
            denied_canary = f"if {canary}; then echo 'Direct canary unexpectedly reachable' >&2; exit 1; fi\n"
            phase("tunnel_loss", f"nmcli con down uuid {UUID}\n" + denied_canary + "sleep 35\n" + emergency, timeout=65)
            phase(
                "reconnect_latched",
                f"nmcli con up uuid {UUID}\nsleep 5\n" + denied_canary + emergency,
                timeout=45,
            )
            phase(
                "explicit_stop",
                "ttp stop\nif nft list table inet ttp_vpn; then exit 1; fi\ntest ! -e /run/ttp/vpn-intent.json\n"
                'test "$(systemctl show ttp-tor -p MainPID --value)" = 0\n'
                'test "$(systemctl show ttp-tor -p ControlPID --value)" = 0',
                # Explicit stop intentionally ends the guarantee. Restored
                # resolver services can immediately emit physical LLMNR, etc.
                protected=False,
            )
            evidence = phase("stop_control", route + canary, protected=False)
            if not evidence["violations"].get("198.51.100.7/proto6/port8000"):
                raise RuntimeError("No direct path after explicit stop: observer inconclusive")
            if args.require_apparmor:
                phase(
                    "apparmor_start",
                    f"ttp start --require-vpn {UUID} --watchdog --no-lan-bypass --no-ipv6 --bootstrap-timeout 300",
                    timeout=400,
                )
                phase(
                    "apparmor_loss",
                    "apparmor_parser --replace --skip-cache --Complain /run/ttp/ttp-tor.apparmor\n"
                    + (ROOT / "scripts/vm/vpn/apparmor-check.sh").read_text(),
                    timeout=65,
                )
                phase("apparmor_stop", "ttp stop", protected=False)
            report["finished"] = datetime.now(UTC).isoformat()
            record("result", "pass")
        except BaseException as exc:
            record("result", f"failed: {exc}")
            with contextlib.suppress(Exception):
                _, output = client.agent.run(
                    "cat /tmp/ttp*log 2>/dev/null || true\n"
                    "journalctl -u ttp-tor -u ttp-watchdog -n 100 --no-pager\n"
                    "nft list ruleset\nip route show table all\nip rule\ncat /etc/resolv.conf\n"
                    "wg show wgtest latest-handshakes\nwg show wgtest transfer\nttp status --json",
                    check=False,
                )
                (client.work / "failure.txt").write_text(output)
            with contextlib.suppress(Exception):
                _, output = peer.agent.run(
                    "ip addr\nip route\nnft list ruleset\nwg show wgpeer transfer\n"
                    "journalctl -u qualification-dhcp -n 40 --no-pager",
                    check=False,
                )
                (peer.work / "failure.txt").write_text(output)
            raise


if __name__ == "__main__":

    def terminate(signum, _frame):
        raise SystemExit(f"Controller received signal {signum}")

    signal.signal(signal.SIGTERM, terminate)
    main()
