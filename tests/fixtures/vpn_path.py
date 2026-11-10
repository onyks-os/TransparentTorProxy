# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Destructive only inside the disposable, network-disabled VPN container.

A real NM/WireGuard tunnel to a local peer, with capture on the peer's
underlay. Tor traffic is a controlled UID probe, not a public Tor circuit.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


def run(*args, **kwargs):
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr, file=sys.stderr)
        raise


def server(*, local=False):
    import socketserver

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(128))

    socketserver.TCPServer.allow_reuse_address = True
    dual = os.environ.get("TTP_VPN_DUALSTACK") == "1"
    if dual and not local:
        socketserver.TCPServer.address_family = socket.AF_INET6
    address = ("127.0.0.1", 9041) if local else ("::" if dual else "0.0.0.0", 8000)
    with socketserver.TCPServer(address, Echo) as listener:
        if local:
            Path("/tmp/vpn-proof/local-ready").touch()
        listener.serve_forever()


def probe():
    os.setgroups([])
    os.setgid(100)
    os.setuid(int(sys.argv[3]))
    try:
        with socket.create_connection((sys.argv[2], 8000), timeout=1) as stream:
            stream.sendall(b"TTP-VPN-PLAINTEXT-CANARY")
            assert stream.recv(128) == b"TTP-VPN-PLAINTEXT-CANARY"
    except OSError:
        sys.exit(1)


def main():
    assert os.environ.get("TTP_VPN_INTEGRATION") == "1", "Use scripts/check-vpn.sh"
    from ttp import firewall, vpn, vpn_guard

    work = Path("/tmp/vpn-proof")
    dual = os.environ.get("TTP_VPN_DUALSTACK") == "1"
    work.mkdir()
    run("ip", "netns", "add", "peer")
    run("ip", "link", "add", "wan", "type", "veth", "peer", "name", "remote")
    run("ip", "link", "set", "remote", "netns", "peer")
    run("nmcli", "device", "set", "wan", "managed", "no")
    run("ip", "addr", "add", "192.0.2.2/24", "dev", "wan")
    run("ip", "link", "set", "wan", "up")
    run("ip", "route", "add", "default", "via", "192.0.2.1")

    def peer(*args):
        return run("nsenter", "--net=/run/netns/peer", "--", *args)

    peer("ip", "link", "set", "lo", "up")
    peer("ip", "addr", "add", "192.0.2.1/24", "dev", "remote")
    peer("ip", "link", "set", "remote", "up")
    peer("ip", "addr", "add", "1.1.1.1/32", "dev", "lo")
    if dual:
        run("ip", "-6", "addr", "add", "2001:db8:1::2/64", "dev", "wan", "nodad")
        peer("ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "remote", "nodad")
        run("ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
        peer("ip", "-6", "addr", "add", "2606:4700:4700::1111/128", "dev", "lo", "nodad")
    private = run("wg", "genkey")
    public = run("wg", "pubkey", input=private)
    remote_private = run("wg", "genkey")
    remote_public = run("wg", "pubkey", input=remote_private)
    secret = work / "remote.key"
    secret.write_text(remote_private)
    secret.chmod(0o600)
    peer("ip", "link", "add", "wgpeer", "type", "wireguard")
    peer("ip", "addr", "add", "10.9.0.1/24", "dev", "wgpeer")
    if dual:
        peer("ip", "-6", "addr", "add", "fd00:9::1/64", "dev", "wgpeer", "nodad")
    peer(
        "wg",
        "set",
        "wgpeer",
        "private-key",
        str(secret),
        "listen-port",
        "51820",
        "peer",
        public,
        "allowed-ips",
        "10.9.0.2/32,fd00:9::2/128" if dual else "10.9.0.2/32",
    )
    peer("ip", "link", "set", "wgpeer", "up")
    echo = subprocess.Popen(["nsenter", "--net=/run/netns/peer", "--", sys.executable, __file__, "server"])
    capture = subprocess.Popen(
        [
            "nsenter",
            "--net=/run/netns/peer",
            "--",
            "tcpdump",
            "-Z",
            "root",
            "-U",
            "-n",
            "-i",
            "remote",
            "-w",
            str(work / "underlay.pcap"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=work.joinpath("capture.log").open("w"),
    )
    time.sleep(1)
    assert capture.poll() is None, work.joinpath("capture.log").read_text()

    def reaches(destination, uid):
        return subprocess.run([sys.executable, __file__, "probe", destination, str(uid)], check=False).returncode == 0

    assert reaches("192.0.2.1", 100), "Underlay positive control must work"
    profile_uuid = "12345678-1234-4234-8234-123456789012"
    config = Path("/etc/NetworkManager/system-connections/ttp-test.nmconnection")
    endpoint = "[2001:db8:1::1]:51820" if dual else "192.0.2.1:51820"
    ranges = "0.0.0.0/0;::/0;" if dual else "0.0.0.0/0;"
    ipv6 = "method=manual\naddress1=fd00:9::2/64\n" if dual else "method=disabled\n"
    config.write_text(f"""[connection]
id=ttp-local-vpn
uuid={profile_uuid}
type=wireguard
interface-name=wgtest
autoconnect=false
[wireguard]
private-key={private}
fwmark=51820
[wireguard-peer.{remote_public}]
endpoint={endpoint}
allowed-ips={ranges}
[ipv4]
method=manual
address1=10.9.0.2/24
never-default=false
[ipv6]
{ipv6}
""")
    config.chmod(0o600)
    run("nmcli", "connection", "load", str(config))
    run("nmcli", "connection", "up", "uuid", profile_uuid)
    policy = vpn.inspect_profile(profile_uuid, no_ipv6=not dual, tor_uid=100)
    assert reaches("1.1.1.1", 100), "Real VPN tunnel positive control must work"
    Path("/run/ttp").mkdir(exist_ok=True)
    vpn_guard.install(policy, 100)
    assert vpn.observe(policy, 100)["state"] == "constrained"
    # Exercise observations with the watchdog's actual privilege boundary,
    # including system D-Bus access and public WireGuard queries.
    run("useradd", "--system", "--no-create-home", "ttp-watchdog")
    observation_script = work / "observe.py"
    observation_script.write_text(
        "from ttp.vpn import VPNPolicy, observe\n"
        f"p=VPNPolicy.from_snapshot({policy.snapshot()!r})\n"
        "assert observe(p, 100)['state'] == 'constrained'\n"
    )
    run(
        "systemd-run",
        "--wait",
        "--pipe",
        "--uid=ttp-watchdog",
        "--property=AmbientCapabilities=CAP_NET_ADMIN",
        "--property=CapabilityBoundingSet=CAP_NET_ADMIN",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        sys.executable,
        str(observation_script),
    )
    assert reaches("1.1.1.1", 100), "Guard must permit Tor UID through the real tunnel"
    if dual:
        assert reaches("2606:4700:4700::1111", 100), "IPv6 payload must traverse the actual VPN"
    assert not reaches("1.1.1.1", 101), "Guard must reject direct application traffic before TTP NAT exists"
    firewall.apply_rules("100", lan_bypass=False, disable_ipv6=not dual, vpn=policy.snapshot())
    assert reaches("1.1.1.1", 100), "Normal TTP table must permit WireGuard outer transport"
    local = subprocess.Popen([sys.executable, __file__, "local"])
    deadline = time.monotonic() + 5
    while not work.joinpath("local-ready").exists():
        assert time.monotonic() < deadline, "Controlled transparent listener did not start"
        time.sleep(0.05)
    try:
        assert reaches("1.1.1.1", 101), "Non-exempt TCP must reach the redirected loopback listener"
        # Reproduce the old bug using real packets: OUTPUT still sees the WG
        # oif after DNAT; POSTROUTING must see the final loopback route.
        wrong_hook = vpn_guard.specification(policy, 100)
        wrong_hook[1]["chain"]["hook"] = "output"

        def replace_guard(objects):
            reply = vpn_guard._nft(
                "-j",
                "-f",
                "-",
                payload={
                    "nftables": [
                        {"delete": {"table": {"family": "inet", "name": "ttp_vpn"}}},
                        *({"add": obj} for obj in objects),
                    ]
                },
            )
            assert reply.returncode == 0, reply.stderr

        replace_guard(wrong_hook)
        assert not reaches("1.1.1.1", 101), "Old OUTPUT hook mutation must block the redirected connection"
        replace_guard(vpn_guard.specification(policy, 100))
        vpn_guard.verify(policy, 100)
        assert reaches("1.1.1.1", 101), "Restoring the actual egress hook must restore local redirection"
    finally:
        local.terminate()
        local.wait(timeout=5)
    assert not reaches("192.0.2.1", 100), "Tor UID must not use a direct underlay route"

    # The route fallback is installed deliberately: a functioning kill switch
    # must protect packets before a polling supervisor can observe this change.
    run("ip", "rule", "add", "priority", "1", "to", "1.1.1.1/32", "lookup", "main")
    assert not reaches("1.1.1.1", 100), "Tor must not fall back to physical routing"
    # Mutation proves the negative assertion is measuring a reachable leak path.
    run("nft", "delete", "table", "inet", "ttp_vpn")
    assert reaches("1.1.1.1", 100), "Removing the guard must expose the forbidden path"
    # Reinstall the specification without adopting any observed rules.
    reply = vpn_guard._nft(
        "-j", "-f", "-", payload={"nftables": [{"add": obj} for obj in vpn_guard.specification(policy, 100)]}
    )
    assert reply.returncode == 0, reply.stderr
    vpn_guard.verify(policy, 100)
    assert not reaches("1.1.1.1", 100)
    assert vpn.observe(policy, 100)["state"] == "unknown"
    run("ip", "rule", "del", "priority", "1")
    assert reaches("1.1.1.1", 100)

    from ttp import state
    from ttp.firewall.verification import inspect_emergency_rules
    from ttp.runtime_records import session_store
    from ttp.session_safety import emergency_latched
    from ttp.settings import Settings, WatchdogSettings
    from ttp.watchdog.service import start_watchdog, watchdog_observation

    state.ensure_runtime_dir()
    session_store().prepare()
    resolver = Path("/run/ttp/test-resolv.conf")
    resolver.write_text("nameserver 127.0.0.1\n")
    resolver.chmod(0o644)
    run("mount", "--bind", str(resolver), "/etc/resolv.conf")
    run("systemd-run", "--unit=ttp-tor", "--uid=100", "/usr/bin/sleep", "300")
    timing = WatchdogSettings(
        enabled=True,
        readiness_timeout=10,
        heartbeat_interval=1,
        service_timeout=10,
        check_interval=2,
        check_timeout=3,
        observation_max_age=6,
    )
    state.write_lock(
        vpn=policy.snapshot(),
        tor_uid=100,
        interface="wan",
        lan_bypass=False,
        no_ipv6=not dual,
        watchdog_requested=True,
        table_fingerprint=firewall.table_fingerprint(),
        settings=Settings(watchdog=timing).snapshot(),
    )
    start_watchdog()
    assert watchdog_observation()["value"] == "healthy"
    run("ip", "rule", "add", "priority", "1", "to", "1.1.1.1/32", "lookup", "main")
    deadline = time.monotonic() + 12
    while not inspect_emergency_rules().verified:
        assert time.monotonic() < deadline, "Required watchdog did not contain the VPN route failure"
        time.sleep(0.2)
    vpn_guard.verify(policy, 100)
    run("ip", "rule", "del", "priority", "1")
    assert inspect_emergency_rules().verified, "Restored VPN route must not release the emergency"
    # An unchanged name cannot cause an old index constraint to trust a new device.
    run("nmcli", "connection", "down", "uuid", profile_uuid)
    assert vpn.observe(policy, 100)["state"] == "unknown"
    assert not reaches("1.1.1.1", 100)
    run("nmcli", "connection", "up", "uuid", profile_uuid)
    assert vpn.observe(policy, 100)["state"] == "unknown"
    assert not reaches("1.1.1.1", 100)
    assert emergency_latched(state.read_lock(strict=True))
    assert inspect_emergency_rules().verified
    capture.terminate()
    capture.wait(timeout=5)
    echo.terminate()
    echo.wait(timeout=5)
    frames = []
    with (work / "underlay.pcap").open("rb") as capture_file:
        header = capture_file.read(24)
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        assert struct.unpack(endian + "I", header[20:24])[0] == 1, "Expected Ethernet capture"
        while record := capture_file.read(16):
            length = struct.unpack(endian + "IIII", record)[2]
            frames.append(capture_file.read(length))
    clear = [frame for frame in frames if b"TTP-VPN-PLAINTEXT-CANARY" in frame]
    # Only the two positive/mutation controls may expose the canary physically.
    assert len(clear) == 4, f"Expected request/reply for two controls, got {len(clear)} cleartext frames"
    assert any(
        len(frame) > 38
        and (
            (frame[12:14] == b"\x08\x00" and frame[23] == 17 and int.from_bytes(frame[36:38], "big") == 51820)
            or (
                len(frame) > 58
                and frame[12:14] == b"\x86\xdd"
                and frame[20] == 17
                and int.from_bytes(frame[56:58], "big") == 51820
            )
        )
        for frame in frames
    ), "Observer did not see VPN transport"
    # Recovery refuses while a real systemd process is still running.
    try:
        vpn_guard.release_after_stop()
    except vpn.VPNError:
        pass
    else:
        raise AssertionError("Live Tor service must retain the guard")
    from ttp.commands.lifecycle import do_stop

    do_stop()
    assert not vpn_guard.INTENT.exists()
    print(
        json.dumps(
            {
                "result": "pass",
                "observer": "peer underlay capture",
                "scope": "real NM/WireGuard and kernel path; controlled Tor UID, no public Tor circuit",
            }
        )
    )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        {"server": server, "local": lambda: server(local=True), "probe": probe}[sys.argv[1]]()
    else:
        main()
