# Resolving System & Service Conflicts

This tutorial guides you through diagnosing operational failures, resolving port conflicts, inspecting session logs, and resetting corrupted state using built-in TTP administration commands.

---

## 1. Running System Diagnostics (`sudo ttp diagnose`)

When a session fails to start or network redirection behaves unexpectedly, run `sudo ttp diagnose` to generate an integrated diagnostic report:

```bash
sudo ttp diagnose
```

The diagnostic command collects and formats 7 critical system layers:

1. **System & OS**: Distribution version, kernel release, and SELinux status.
2. **Tor Service State**: `ttp-tor.service` systemd unit status and active PIDs.
3. **Torrc Configuration**: Active volatile configuration in `/run/tor/ttp/torrc`.
4. **nftables Ruleset**: Active `inet ttp` redirection rules and chain counters.
5. **DNS Configuration**: `/etc/resolv.conf` mount overlay and `systemd-resolved` drop-ins.
6. **Tor Control Interface**: Connection status on the control socket `/run/tor/ttp/control.sock`.
7. **TTP Internal State**: Session lock content and volatile RAM file state in `/run/ttp`.

---

## 2. Inspecting Volatile Logs (`ttp logs`)

View recent session logs stored in `/run/ttp/ttp.log`:

```bash
# Display full volatile session log
ttp logs

# Combine with systemd journal for Tor daemon logs
sudo journalctl -u ttp-tor.service -n 50 --no-pager
```

Log entries capture preflight check events, `nftables` rule applications, DNS mount operations, and watchdog state transitions.

---

## 3. Resolving Port Conflicts

TTP's Tor needs two local ports: the TransPort (`9041` by default, `--transport-port`) and the DNSPort (`9054` by default, `--dns-port`). They are deliberately not Tor's usual `9040` and `5353`, so a system Tor can keep running; the control interface is a Unix socket, not a port.

If another process occupies these ports, preflight checks report a port conflict:

```bash
# Check if the TransPort (9041) is occupied by another process
sudo ss -tulpn | grep 9041

# Check the DNSPort (9054) listener
sudo ss -tulpn | grep 9054
```

If another process holds one of them, stop it or pick other ports with `--transport-port` / `--dns-port`.

---

## 4. Restoring the Network After a Crash

If a session crashed, or a lock file outlived its session, force a teardown:

```bash
# Remove TTP's table, restore DNS and delete the lock, even with no session running
sudo ttp stop --restore-only
```

If `ttp` itself cannot run, the repository ships a standalone script that does the
same with plain `nft` and `umount`:

```bash
sudo ./scripts/restore-network.sh
```

A `kill -9` or a power cut needs neither: the lock lives in `tmpfs`, and the next
`ttp start` detects an orphaned one and recovers before starting.

To remove TTP from the system entirely - stopping any session, unloading the
SELinux module and removing its markers - use `sudo ttp uninstall`, then remove the
package or run `scripts/uninstall.sh`.
