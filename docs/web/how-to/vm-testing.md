# How-To: VM and Chaos Testing

This guide provides operational recipes for running multi-distribution integration tests, managing QEMU/KVM virtual machines, and executing Watchdog chaos monkey routines.

---

## 1. Multi-Distribution Docker Integration Testing

Execute automated integration test suites across containerized Linux environments:

```bash
# Run Debian 12 integration test suite
make integration-debian

# Run Fedora 40 integration test suite
make integration-fedora

# Run Arch Linux integration test suite
make integration-arch

# Run all integration test suites sequentially
make integration-all
```

Docker test environments validate package installation, systemd service detection, and `nftables` syntax checks.

---

## 2. QEMU/KVM Virtual Machine Orchestration

For full kernel-level, DNS mount, and `systemd` integration testing, use the provided QEMU/KVM VM management scripts:

### Spawning a Test VM

```bash
# Launch an Arch Linux VM instance
./scripts/vm/start.sh arch

# Launch a Debian 12 VM instance
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
```

It downloads the Debian 13 cloud image once (verified against Debian's `SHA512SUMS`),
installs TTP from the working tree, and writes `results.txt`, one capture per phase
and state snapshots into `$VM_WORK`. `scripts/vm/lifecycle/egress.py <file.pcap>`
summarises a capture by destination; it streams the file, so size is not a concern.
Captures are header-only and only cover scenario phases, never provisioning.

The same script runs in CI from `.github/workflows/lifecycle.yml`. See
`docs/security-assessment.md` section 4.3 for what it asserts and what it found.

---

## 4. Executing Watchdog Chaos Monkey Testing

The Watchdog Chaos Monkey suite simulates live system faults, abrupt process terminations, table deletions, and `/etc/resolv.conf` target modifications while TTP is active:

```bash
# Execute full Watchdog fault injection suite
make chaos-monkey
```

The chaos monkey suite verifies that the FSM Watchdog correctly detects integrity violations, restores damaged `nftables` chains, and engages the emergency killswitch when recovery fails.
