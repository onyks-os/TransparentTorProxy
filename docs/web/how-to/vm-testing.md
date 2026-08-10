# How-To: VM & Chaos Testing

For integration testing and leak verification, TTP provides QEMU/KVM virtual machine orchestration scripts and automated chaos monkey test routines.

---

## 1. Running Docker Multi-Distro Integration Tests

TTP provides pre-configured Docker test environments for Debian, Fedora, and Arch Linux:

```bash
# Run Debian integration tests
make integration-debian

# Run all distribution tests
make integration-all
```

---

## 2. QEMU/KVM VM Management

For full kernel and systemd integration testing:

```bash
# Launch an Arch Linux VM
./scripts/vm/start.sh arch

# Sync current local codebase to the VM
./scripts/vm/send.sh

# Take a VM snapshot before running risky tests
./scripts/vm/snapshot.sh arch save before-test
```

---

## 3. Watchdog Chaos Monkey Testing

Run the Watchdog Chaos Monkey suite to simulate network drops, nftables table deletions, and `/etc/resolv.conf` target swaps:

```bash
make chaos-monkey
```
