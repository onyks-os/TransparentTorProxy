<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# DNSSEC policy and TTP

TTP's DNS path ends at Tor's DNSPort. That port handles A, AAAA and PTR queries,
not the complete set of records needed for local DNSSEC validation. Tor transport
does not replace DNSSEC validation. See the [Tor manual](https://man.archlinux.org/man/tor.1#DNSPort).

## Automatic configuration

When systemd-resolved is active, TTP's temporary drop-in sets `DNSSEC=no` for
the session. An interface that inherits the global DNSSEC setting inherits this
temporary value. No additional TTP flag is required. `ttp stop` removes the
drop-in and restarts resolved, restoring the previous persistent configuration.
The same cleanup runs if DNS setup fails after creating the drop-in.

TTP does not edit the persistent DNSSEC configuration or call `SetLinkDNSSEC`.
The generated resolver file is readable by applications (`0644`), and the drop-in
is readable by resolved (`0644` in a `0755` directory), even when root uses
`umask 0027` or `0077`. This does not make TTP's lock, log or other runtime data
public. The source installer also makes its installed virtualenv accessible to
the unprivileged verification process, without granting write access to others.

## An interface explicitly requires DNSSEC

If any current non-loopback interface explicitly requires `DNSSEC=yes`, TTP
prints an error naming that interface and exits with **code 4**. The check runs
before Tor setup, orphan recovery, firewall changes or DNS changes. `ttp restart`
also checks before stopping the existing session; a refusal leaves that session
in place. This is a configuration refusal, not a session with degraded DNS.

The check covers all current interfaces because DNS redirection is system-wide,
including when `--interface` names just one interface. It is an initial preflight,
not continuous monitoring of interfaces or policies added after session startup.
Explicit `no` and `allow-downgrade` settings are left unchanged; neither requires
validation unconditionally.

`resolvectl status` and resolved's D-Bus `DNSSEC` property show the effective
value, not whether it was inherited. A displayed `yes` alone is not a conflict.

### Resolve the conflict deliberately

- **Keep mandatory local DNSSEC:** leave the interface policy in place. Use Tor
  Browser for its own browsing traffic, or a separately configured VM for TTP.
  TTP's current DNSPort design cannot satisfy mandatory host DNSSEC validation.
- **Allow TTP's temporary DNSSEC policy:** review the explicit setting in the
  network manager that owns the interface. Remove that override only if you
  intend the interface to inherit the global policy. TTP never does this for you.

For an override set manually with `resolvectl`, an administrator can clear just
that runtime override after recording its previous value:

```bash
# Example only: replace wlo1 with the interface reported by TTP.
sudo resolvectl dnssec wlo1 ''
sudo ttp start
```

If the previous explicit value was `yes`, restore it after stopping TTP:

```bash
sudo ttp stop
sudo resolvectl dnssec wlo1 yes
```

The empty string means inheritance, not `no`. A network manager may reapply its
own setting on reconnection. Do not use `resolvectl revert` for this: it resets
other per-link DNS settings too. Disabling the firewall or SELinux does not solve
the DNSSEC policy conflict.

## When the policy cannot be inspected

An unreadable, unrecognized or inconsistent DNSSEC policy produces a visible
preflight error with code **1**, rather than code 4: TTP has not established that
an explicit requirement exists. Missing `busctl`, service/D-Bus query failures
and a network changing during the check are also inspection errors. Resolve the
reported cause and retry; there is no flag to ignore the check.

The implementation reads the internal per-interface state written by
systemd-resolved (`/run/systemd/resolve/netif/`) or, for networkd-managed links,
systemd-networkd (`/run/systemd/netif/links/`), and compares it with the effective
D-Bus value. These are **internal systemd formats**, not a public API; the adapter
needs compatibility tests when systemd changes. TTP never edits these files.
See the [systemd link implementation](https://github.com/systemd/systemd/blob/main/src/resolve/resolved-link.c)
and [resolved's D-Bus interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html).

## Verify the session and restoration

During a session, run as the ordinary user:

```bash
cat /etc/resolv.conf
resolvectl status
getent ahostsv4 check.torproject.org
curl --max-time 30 https://check.torproject.org/api/ip
```

A response with `IsTor: true` verifies that request's Tor routing. A successful
direct DNSPort query alone does not verify the application's resolver path.

After `sudo ttp stop`, confirm the original DNSSEC setting in `resolvectl status`
and the absence of TTP's bind mount with `findmnt -T /etc/resolv.conf`. For staged
troubleshooting, see [Diagnosing failures](../tutorials/diagnosing-failures.md).

## Automated compatibility checks

CI runs the policy tests with real D-Bus, systemd-resolved and systemd-networkd
on Debian 13 and Fedora 44. They check inherited versus explicit requirements,
preservation on refusal, and restoration of the global setting after removal
of TTP's drop-in. They do not exercise a complete Tor session.

To reproduce in a disposable Podman container from the repository root:

```bash
podman build -f tests/containers/dnssec.Containerfile -t localhost/ttp-dnssec-check .
podman run --rm --network none --security-opt label=disable \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BROADCAST \
  --cap-add BPF --cap-add SYS_ADMIN \
  --env TTP_TEST_DNSSEC_CONTAINER=1 --volume "$PWD:/src:ro" \
  localhost/ttp-dnssec-check /opt/v/bin/python -m pytest \
  -q -p no:cacheprovider -m integration tests/test_dnssec_systemd.py
```

Building downloads dependencies; the test run has no external network. The
repository is mounted read-only. Do not run these opt-in service tests on the
host: they deliberately create a system bus, interface and resolver configuration
inside the disposable container. Unit tests separately cover restrictive umasks,
unreadable or inconsistent state and CLI refusal before network changes.
