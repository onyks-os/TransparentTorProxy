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
6. **Tor Control Interface**: Connection status on control socket `/run/tor/ttp/control`.
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

TTP requires dedicated TCP and UDP ports for Tor TransPort (`9040`), DNSPort (`5353`), and ControlPort (`9051`).

If another process occupies these ports, preflight checks report a port conflict:

```bash
# Check if Tor TransPort (9040) is occupied by another process
sudo ss -tulpn | grep 9040

# Check DNS port (5353) listener
sudo ss -tulpn | grep 5353
```

If another Tor instance or local resolver occupies these ports, stop the conflicting daemon or allow TTP to manage its dedicated `ttp-tor.service` instance.

---

## 4. Emergency State Purge (`sudo ttp purge`)

If a session crashes abruptly or leaves stale lock files, SELinux policy modules, or invalid `/run/ttp` files, run `sudo ttp purge`:

```bash
# Clean up temporary state, locks, and SELinux modules
sudo ttp purge
```

`sudo ttp purge` stops active sessions, flushes stale `nftables` rules, unmounts temporary `/etc/resolv.conf` overlays, removes temporary files from `/run/ttp`, and unloads SELinux policy modules.
