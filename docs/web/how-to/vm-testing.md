# How-To: VM and Chaos Testing

This guide provides operational recipes for running multi-distribution integration tests, managing QEMU/KVM virtual machines, and executing Watchdog chaos monkey routines.

---

## 1. Multi-Distribution Docker Integration Testing

Execute automated integration test suites across containerized Linux environments:

```bash
# Run the Debian 13 integration test suite
make integration-debian

# Run the Fedora 44 integration test suite
make integration-fedora

# Run the Arch Linux integration test suite
make integration-arch

# Run all integration test suites sequentially
make integration-all
```

The runner resolves IPv4 and IPv6 STUN targets before enabling TTP and passes
the numeric addresses to the UDP containment probes. This avoids depending on
the selected Tor exit to resolve AAAA records during a firewall test. Missing
targets fail the setup; an inconclusive probe never counts as containment.

The same three run in CI on every push and pull request. A container shares the host's kernel and has no real boot, so these cannot show lifecycle behaviour; section 3 covers that.

---

## 2. QEMU/KVM Virtual Machine Orchestration

For full kernel-level, DNS mount, and `systemd` integration testing, use the provided QEMU/KVM VM management scripts:

### Spawning a Test VM

```bash
# Launch an Arch Linux VM instance
./scripts/vm/start.sh arch

# Launch a Debian VM instance
./scripts/vm/start.sh debian
```

### Syncing Codebase and Taking Snapshots

```bash
# Sync local TTP source code into the running VM
./scripts/vm/send.sh

# Save a named VM snapshot before executing intrusive tests
./scripts/vm/snapshot.sh arch save before-fsm-test

# Restore the VM snapshot after testing completes
./scripts/vm/snapshot.sh arch restore before-fsm-test
```

---

## 3. Lifecycle Transitions in a Disposable VM

`scripts/vm/lifecycle/run.sh` takes a TTP session through shutdown, reboot and
suspend/resume onto a new network, and judges each from a packet capture QEMU writes
outside the guest. It needs KVM, `qemu-system-x86_64`, `genisoimage` and `curl`, and
no root:

```bash
VM_WORK=~/.cache/ttp-lifecycle-vm scripts/vm/lifecycle/run.sh
# the same on a guest whose network is managed by NetworkManager
VM_DISTRO=fedora VM_WORK=~/.cache/ttp-lifecycle-vm-fedora scripts/vm/lifecycle/run.sh
```

`VM_DISTRO` is `debian` (default; Debian 13, systemd-networkd) or `fedora` (Fedora 44,
NetworkManager, SELinux enforcing). It downloads that cloud image once (verified against
the distribution's published checksum list; the list's signature is not checked),
installs TTP from the working tree, and writes `results.txt`, one capture per phase
and state snapshots into `$VM_WORK`. `scripts/vm/lifecycle/egress.py <file.pcap>`
summarises a capture by destination; it streams the file, so size is not a concern.
Captures are header-only and only cover scenario phases, never provisioning.

`scripts/vm/lifecycle/chaos.sh` runs the watchdog chaos sweep (`tests/chaos_monkey.py`,
options through `CHAOS_ARGS`, e.g. `CHAOS_ARGS="--reset-between --no-bypass"`)
in the same kind of guest, detached, because two of its faults cut the SSH session on
purpose; it collects the sweep's log and exit code when the guest answers again.

Both scripts run in CI from `.github/workflows/lifecycle.yml`. See
`docs/security-assessment.md` section 4.3 for what it asserts and what it found.

### Required VPN with real Tor

`scripts/vm/vpn/run.py` provisions two fresh Debian 13 cloud VMs. One runs a
WireGuard peer, DHCP and Internet forwarding; the other runs NetworkManager,
the required VPN and TTP. Nothing changes the host's firewall or resolver.
The client's provisioning NIC is disabled before measurements. QEMU Guest
Agent controls the protected guest over virtio-serial, so the test needs no
SSH exception in the VPN guard.

Requirements: Python 3.12+, KVM access, `qemu-system-x86_64`, `qemu-img`,
`genisoimage`, OpenSSH and Internet access from the guests. Supply the official
Debian 13 genericcloud AMD64 image and its matching published `SHA512SUMS`:

```bash
mkdir -p target/vpn-qualification
python3 scripts/vm/vpn/run.py \
  --base /path/to/debian-13-genericcloud-amd64.qcow2 \
  --checksums /path/to/SHA512SUMS \
  --work target/vpn-qualification/debian-unique-run
```

The work directory must not exist. The base image is read-only and its checksum
is checked before boot; this harness does not authenticate the checksum list's
signature. Obtain both from the [Debian cloud image service](https://cloud.debian.org/images/cloud/).
Source installation uses the repository's hashed dependency locks. Only tracked
files are copied into the guest. Public network or Tor failures fail the run;
there is no automatic fallback to an offline success.

The peer also exposes a controlled HTTP server directly on the physical path.
The external QEMU capture must detect that direct path before protection and
after explicit stop. During protection it accepts only ARP, DHCP and UDP to
the exact VPN endpoint. Unknown traffic, fragments, truncated evidence and
empty captures fail visibly. A real non-exempt HTTPS request must resolve its
hostname and return `IsTor=true`; encrypted tunnel packets must be observed.
The harness also checks DHCP renewal, tunnel loss, verified emergency containment,
reconnection without reopening and explicit stop with guard removal.
Each phase ends with a controlled ARP request so that even an isolated guest
must produce observable link-layer traffic. This adds no IP exception. DHCP
renewal requires a matching DHCPREQUEST/DHCPACK transaction, not just retries.

The same scenarios run on relevant pull requests, weekly and on demand in
`.github/workflows/vpn-vm.yml`; CI uploads reports and captures, excluding disks
and seed images.

Evidence is in `results.json`, guest version reports, phase logs and external
`client/*.pcap` files. The current topology is IPv4 underlay/IPv4 tunnel with
`--no-ipv6`. It does not qualify ParrotOS, Fedora, bridge transports, other
IPv6 combinations or every lifecycle transition. Keep those gates pending in
the [VPN validation table](vpn.md#validation-limits-and-release-gate).

Both QEMU processes are stopped on normal completion or an exception. The
private work directory (mode `0700`) retains disks and captures for investigation;
the guest disks contain throwaway WireGuard keys. Share the reports and captures,
not VM disks or cloud-init material. Captures retain the first 768 bytes of
each frame, sufficient to inspect the DHCP exchange; treat them as test data.

---

## 4. Executing Watchdog Chaos Monkey Testing

The Watchdog Chaos Monkey suite simulates live system faults, abrupt process terminations, table deletions, and `/etc/resolv.conf` target modifications while TTP is active:

```bash
# Execute full Watchdog fault injection suite
make chaos-monkey
```

The sweep runs every fault once against a live session - Tor stopped, Tor killed behind systemd's back, the table flushed, the table destroyed, the DNS overlay unmounted, the link flapped - and audits containment after each, TCP and UDP. Every audit is paired with a canary, a bypassed user audited the same way, which must be seen: a pass means the audit could have shown a leak at that moment. It requires root and cuts the network on purpose, so run it on a disposable host, or in a VM with `scripts/vm/lifecycle/chaos.sh` as above.
