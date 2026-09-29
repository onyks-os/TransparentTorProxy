# How-To: VM and Chaos Testing

This guide provides operational recipes for running multi-distribution integration tests, managing QEMU/KVM virtual machines, and executing Watchdog chaos monkey routines.

---

## 1. Multi-Distribution Docker Integration Testing

Execute automated integration test suites across containerized Linux environments:

```bash
# Run the Debian 13 integration test suite
make integration-debian

# Run the Fedora 41 integration test suite
make integration-fedora

# Run the Arch Linux integration test suite
make integration-arch

# Run all integration test suites sequentially
make integration-all
```

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

---

## 4. Executing Watchdog Chaos Monkey Testing

The Watchdog Chaos Monkey suite simulates live system faults, abrupt process terminations, table deletions, and `/etc/resolv.conf` target modifications while TTP is active:

```bash
# Execute full Watchdog fault injection suite
make chaos-monkey
```

The sweep runs every fault once against a live session - Tor stopped, Tor killed behind systemd's back, the table flushed, the table destroyed, the DNS overlay unmounted, the link flapped - and audits containment after each, TCP and UDP. Every audit is paired with a canary, a bypassed user audited the same way, which must be seen: a pass means the audit could have shown a leak at that moment. It requires root and cuts the network on purpose, so run it on a disposable host, or in a VM with `scripts/vm/lifecycle/chaos.sh` as above.
