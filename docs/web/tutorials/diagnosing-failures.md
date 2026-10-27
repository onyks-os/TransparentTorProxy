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

---

## 5. Diagnose a hardened host without weakening its policy

A failed TTP session is not evidence that the host configuration is wrong. Locate
which layer failed before changing Quad9, firewall rules or hardening settings.
The 0.5.0 work adds automatic restrictive-umask compatibility and a specific
[DNSSEC policy contract](../how-to/dnssec.md). An explicit per-interface requirement
refuses startup with code `4`; inherited global DNSSEC is temporarily disabled.
The following procedure is manual: it does not disable defenses, change DNS or
apply diagnostic firewall rules. Run locally, with a terminal available for
recovery; do not experiment over your only remote management connection.

### A. Record the baseline before starting a session

Run these while TTP is inactive. If it is already active, capture section C first:
otherwise teardown would discard useful evidence. Replace example ports below
if your command uses non-default values.

```bash
command -v ttp
ttp --help
cat /etc/os-release
uname -r
nft --version
systemctl is-active systemd-resolved NetworkManager firewalld nftables
readlink -f /etc/resolv.conf
findmnt -T /etc/resolv.conf
resolvectl status
ip -4 rule show
ip -4 route show table all
ip -6 rule show
ip -6 route show table all
sudo ss -lntup
sudo nft -a list ruleset
```

Record the installed package version using your installation method (for example
`rpm -q transparent-tor-proxy`, `dpkg-query -W transparent-tor-proxy`, or the
package metadata in the pip/pipx environment used to install TTP). Version 0.4.11
does not expose a `ttp --version` option.

An inactive service is useful information, not automatically an error. If
`resolvectl` is unavailable, record that and inspect `/etc/resolv.conf` locally.
If iptables-based tooling is installed, also inspect `sudo iptables-save` and
`sudo ip6tables-save`: the nftables listing alone does not establish that no other
filtering exists. Do not flush any rules.

Describe how Quad9 is configured: plain DNS (53), DNS-over-TLS (853), browser
DNS-over-HTTPS, a local proxy such as Stubby/Unbound, or a combination. Note whether
a VPN, container network, UID-based egress policy or application sandbox is active.
Record whether normal browsing and name resolution work before TTP starts.
Record nftables' version too: syntax support is distinct from firewall hardening.
For example, nftables 1.0.6 rejects the `destroy table` operation used by
TTP 0.4.11's teardown. The subsequent implementation uses `delete table` and
handles an absent table explicitly. If that exact error appears on an older
release, preserve it as a compatibility issue; do not loosen firewall policy.

### B. Reproduce once and preserve the exit status

Use the exact command and options that previously failed; record them locally,
including whether this is managed or `--external-daemon` mode. For example:

```bash
sudo ttp start --watchdog
start_rc=$?
printf 'ttp start exit code: %s\n' "$start_rc"
```

This starts a real TTP session and changes its firewall/DNS state; it is the
intentional reproduction step, not a read-only diagnostic. Do not add bypasses or
`--allow-root` merely to make the check pass.

For 0.4.11, code `1` indicates an unsuccessful start, `3` an established but
unverified session, and `0` successful verification. A failed external check is
not by itself proof of a leak or proof that no traffic reaches Tor. Also inspect
watchdog startup errors: a requested watchdog can fail independently of Tor.

### C. Capture the failing state before stopping

```bash
sudo ttp status
sudo ttp diagnose
sudo systemctl status ttp-tor.service ttp-watchdog.service --no-pager
sudo journalctl -b -u ttp-tor.service -u ttp-watchdog.service -n 150 --no-pager
sudo ss -lntup
sudo nft -a list table inet ttp
resolvectl status
findmnt -T /etc/resolv.conf
sudo journalctl -b -k -n 150 --no-pager
```

Inspect output locally. Reports can contain bridge addresses, public IPs, user
names, paths and internal DNS domains. Redact those before sharing; never send
bridge secrets or complete logs without review. In external-daemon mode inspect
the actual external Tor unit as well: `ttp-tor.service` may correctly be absent.
For SELinux/AppArmor hosts, look for relevant denial messages; if available,
`sudo ausearch -m AVC,USER_AVC -ts recent` supplies SELinux evidence. Absence of a
logged denial does not prove that filtering is absent.

### D. Separate the layers

If `cat /etc/resolv.conf` fails as the ordinary user but succeeds as root, inspect
the generated file's permissions before investigating DNS transport. A field
diagnosis found mode `0640` under a restrictive root umask: the DNSPort worked,
but applications could not read the overlay. Another independent problem was an
inaccessible `/opt/ttp/venv`, preventing the `nobody` verification child from
starting. The 0.5.0 fixes address both; reinstall to repair the installed venv.
DNSSEC rejection by resolved is a separate resolver-policy failure, covered by
the linked DNSSEC guide. A successful HTTPS request with curl's `--resolve` and
`IsTor: true` can establish Tor transport while ordinary name resolution fails.

| Observation | Next evidence to inspect |
| :--- | :--- |
| Tor unit fails before bootstrap | Journal: config parsing, port conflicts, permissions, SELinux/AppArmor or systemd sandbox errors |
| Tor runs but cannot finish bootstrap | Guard/bridge connectivity, routing and existing egress rules for Tor's actual UID; another firewall may drop traffic TTP accepts |
| Tor bootstraps but DNS fails | Local DNSPort, resolver overlay/drop-in, per-link DNS, DNSSEC/DoT requirements and local DNS proxies |
| System DNS works but one browser fails | Browser DoH mode, proxy settings, sandbox and the selected resolver hostname |
| Browsing works but `ttp check` fails | Verification endpoint availability, TLS trust/time, probe-child errors and the UID policy applied to the probe |
| Network becomes blocked after a short delay | Watchdog journal and reason for emergency containment; capture before clearing it |

If `dig` is already installed, compare the following as your ordinary,
non-bypassed user (not through `sudo`, not through `ttp bypass`):

```bash
dig +time=2 +tries=1 @127.0.0.1 -p 9054 example.com A
getent ahostsv4 example.com
curl --max-time 30 https://check.torproject.org/api/ip
```

The first tests the local UDP DNSPort, the second the application's system
resolver path, and the third adds HTTPS and external Tor verification. They make
real DNS/HTTPS requests. A successful direct DNSPort query with a failed `getent`
query points to a difference in resolver paths, not automatically to Quad9.
These checks do not test DNS-over-TCP support: a firewall redirect is not evidence
that a TCP DNS service is listening at the destination.

Quad9 as the ordinary system resolver is not inherently incompatible with TTP.
During a session, port-53 requests should be redirected to Tor, so even a query
addressed to Quad9 is not proof that Quad9 answered. A local proxy insisting on
DoT, or a browser insisting on DoH, follows a different path. Managed mode maps
`dns.quad9.net` to `0.0.0.0`; a browser configured to require that DoH hostname can
therefore fail while the system resolver works. See
[applications with their own DNS](../how-to/apps-with-own-dns.md).

For restrictive firewalls, inspect the complete output-hook chain order and Tor's
service identity. An `accept` in TTP does not override a `drop` in another base
chain. Do not disable firewalld, flush nftables, change global DNS or turn off
SELinux/AppArmor as a first diagnostic step. Any later experiment should change
one identified variable, with an explicit expected result and rollback plan.

### E. Restore deliberately, then report a minimal reproduction

After collecting evidence, `sudo ttp stop` ends protection and restores direct
network access. `sudo ttp stop --restore-only` is the recovery path if ordinary
teardown is unavailable. Reboot also ends a volatile TTP session; it does not
restore protection automatically.

For the next diagnostic round provide: version/install method, distribution,
exact start options with secrets removed, exit code, bootstrap result, whether the
watchdog stayed active, Quad9 configuration method, active firewall/VPN tooling,
and which of the three section-D probes failed. Include only the relevant redacted
journal excerpt. This is sufficient to choose a focused next check; a complete
host configuration dump is not required.
