# Tor confinement with AppArmor

**Since the development version for 0.5.0**, TTP requires its managed Tor
process to run under `ttp-tor (enforce)` whenever the running kernel selects
AppArmor. This is automatic; there is no option to ignore a confinement failure.
Kernels using other LSMs, including Fedora's usual SELinux configuration,
continue to use TTP's existing systemd sandbox and SELinux integration.

## Requirements and startup

On Debian, Ubuntu and Parrot, install `apparmor` for the parser and standard
policy abstractions. The native DEB declares this dependency. On Arch, install
`apparmor` when using an AppArmor kernel. Installing the package does not itself
enable AppArmor in a kernel that has not selected it.

At each managed startup, TTP:

1. Reads the running kernel's LSM selection. A module compiled with AppArmor
   support is not sufficient evidence that AppArmor is active. Ambiguous or
   unreadable kernel evidence causes startup to fail.
2. Refuses AppArmor policy loading from containers. Use a host or a disposable
   VM; policy namespace delegation for containers is not implemented.
3. Writes its shipped policy to a private, root-owned file under `/run/ttp/`
   and loads the dedicated named `ttp-tor` profile in enforce mode, without
   using the parser's cache. The distribution's `system_tor` profile is unchanged.
4. Writes `AppArmorProfile=ttp-tor` into the managed service. There is no `-`
   prefix to ignore errors. Existing systemd restrictions, including an empty
   capability bounding set and `NoNewPrivileges`, remain in effect.
5. Independently reads the active service's actual MainPID, account and
   AppArmor label before accepting startup. An unconfined process, complain
   mode, another profile, an unreadable label or a changing process fails
   verification. TTP stops its managed Tor if this final verification fails.

Missing tools, compilation errors and unverifiable required confinement fail
startup with a nonzero exit code. In required-VPN mode the independent startup
guard remains retained; follow the [VPN recovery procedure](vpn.md#stop-and-recover-deliberately).
No session is advertised as successfully confined on the strength of the unit
file alone.

## What the profile permits

The policy is shipped inside the Python package as `ttp/ttp-tor.apparmor`.
It uses the distribution's base, name service and OpenSSL abstractions, allows
Tor's network sockets and reads of its configuration and data files, and limits
its own writable state to `/var/lib/tor/ttp/` and `/run/tor/ttp/`. Those directories
remain private to the Tor account. When TTP creates a missing `/run/tor` parent,
it makes it searchable despite a restrictive root umask; it does not expose
the private child configuration or cookie.

The listed transport executables (`obfs4proxy`, `snowflake-client`, `lyrebird`)
inherit the same profile. TTP does not grant an unconfined execution fallback
or silently weaken policy for a transport. Listing an executable is not proof
that every transport, bridge, distribution or custom build has been qualified;
consult the [VM testing guide](vm-testing.md) and current release qualification.
Custom binary locations or additional helper requirements can produce a
visible denial. Report the denial with sensitive bridge details removed.

## Observations and loss of confinement

`sudo ttp status --json` includes a separate observation:

```json
{
  "apparmor": {
    "required": true,
    "profile": "ttp-tor",
    "state": "enforced",
    "reason": "apparmor.process_enforced",
    "pid": 1234,
    "label": "ttp-tor (enforce)"
  }
}
```

The PID is an example. `sudo ttp monitor` shows the same local evidence and
records changes. Both commands are passive: neither reloads policy nor makes
a network probe or requests containment. `unknown` means evidence cannot be
read or validated; `unverified` means the observed label differs from the
required enforce label.

The watchdog checks confinement before ordinary network integrity checks.
It needs no new capability and does not read the privileged kernel profile
store: the actual process label provides the current enforce-mode evidence.
Loss or unreadability triggers the existing emergency containment path,
without automatic healing of AppArmor policy. `ttp check` also checks this
requirement before attempting an Internet verification and requests containment
if it fails. A verified emergency returns `7`; containment that cannot be
confirmed returns `8`. Passive missing confinement evidence contributes code
`1`, subject to the [diagnostic precedence](session-observations.md).

Reinstating a profile does not clear a latched emergency. Close sensitive
applications, use explicit `ttp stop`, investigate, then start a new session.
Stop ends the network protection guarantee. Required-VPN recovery has its own
retained startup guard, described in the VPN guide.

## Diagnosis

Inspect these on the affected host or guest, with root privileges:

```bash
sudo journalctl -u ttp-tor.service -n 40 --no-pager
sudo journalctl -k --since '-5 minutes' --no-pager
sudo systemctl show ttp-tor.service -p ActiveState -p MainPID -p AppArmorProfile
sudo cat /sys/kernel/security/apparmor/profiles
```

Audit records may be routed to a separate audit log. An absence of printed
denials is not proof that policy permits an operation; check Unix ownership
and directory traversal permissions too. For the PID reported by systemd,
inspect `/proc/PID/attr/apparmor/current`; older kernels may expose only
`/proc/PID/attr/current`. Do not switch to complain mode to obtain a green
session. Missing or inaccessible securityfs inside a container is a deployment
limitation, not evidence of an AppArmor-free host.

## Scope and limits

- This requirement covers the Tor instance managed by TTP. With
  `--external-daemon`, the administrator owns the daemon and its confinement;
  TTP does not claim or verify an AppArmor policy for it. Older running sessions
  without a recorded requirement are not retroactively declared confined.
- Without the watchdog, `status` and monitor only observe; `check` acts when
  explicitly invoked. Use `--watchdog` for continuous bounded supervision.
  The required-VPN mode already mandates it.
- A process label proves the profile name and enforcement mode at observation
  time. It does not attest the full policy contents, prevent every compromise,
  or establish network anonymity. Root can replace a loaded policy under the
  same name or change distribution abstractions. Root compromise is outside
  this guarantee, as it is for TTP's firewall and session evidence.
- A loaded profile remains in kernel memory after stop; TTP does not unload
  policy from a possibly attached task. The runtime source file is volatile,
  there is no persistent AppArmor enablement entry, and reboot removes it.
  Package removal does not silently detach a live task from its profile.
- Confinement is an additional boundary, separate from the firewall, the VPN
  path, the watchdog's liveness and the historical external Tor check. None
  substitutes for the others.

See systemd's [AppArmorProfile documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#AppArmorProfile=)
for the mandatory transition and privileged pre-start command semantics, and
the [AppArmor policy reference](https://gitlab.com/apparmor/apparmor/-/wikis/manpage_apparmor.d.5)
for policy rules and execution modes.
