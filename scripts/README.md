# scripts/

Operational shell scripts. Everything here is linted by `make lint-shell` (ShellCheck) and must:

- start with `#!/usr/bin/env bash` and `set -euo pipefail`;
- resolve its own directory rather than assuming the caller's working directory;
- be idempotent, or refuse to run twice with a clear message;
- print what it is about to change to the system *before* changing it.

| Script | Purpose |
| :----- | :------ |
| `verify.sh` | Full local gate: `make lint`, `make test`, fuzzing, dependency audit, multi-distro integration, and the native package build. |
| `install.sh` | System-wide install. Detects SELinux in Enforcing mode on Red Hat systems and compiles the custom policy module that lets Tor bind TTP's non-standard ports (9041, 9054) - a step `pip` cannot perform. |
| `uninstall.sh` | Removes the installed files, the `ttp-watchdog` system user and group, and the Polkit rule. |
| `restore-network.sh` | Emergency recovery: tears down the `inet ttp` nftables table and restores DNS if TTP is not available to do it itself. |
| `vm/`, `vms/` | QEMU helpers for the manual multi-distro test matrix (not run by `make`). |

Both `install.sh` and `uninstall.sh` modify the host system and require root.
