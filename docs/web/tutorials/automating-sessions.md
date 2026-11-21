# Automating TTP via systemd and Scripts

This tutorial demonstrates how to integrate TTP into automated workflows, system startup units, and NetworkManager dispatcher scripts using structured logging and non-interactive flags.

---

## 1. Non-Interactive CLI Flags

When executing TTP inside automated scripts or background daemons, use non-interactive flags to format output and suppress interactive rich console displays:

* `--quiet` / `-q`: Suppress all progress banners, tables, and standard output. Only fatal errors are printed.
* `--log-format json`: Output structured JSON log entries suitable for log collectors (`journalctl`, Fluentd, Datadog).
* `--verbose` / `-v`: Include debug-level internal trace logs.

Example automated execution command:

```bash
sudo ttp --quiet --log-format json start --watchdog
```

---

## 2. NetworkManager Dispatcher Script

To automatically start TTP when a network interface connects and stop it upon disconnection:

1. Create a NetworkManager dispatcher script at `/etc/NetworkManager/dispatcher.d/99-ttp.sh`:

```bash
#!/bin/bash
# /etc/NetworkManager/dispatcher.d/99-ttp.sh

IFACE="$1"
ACTION="$2"

# Only trigger on primary network interface (e.g. eth0, wlan0)
if [ "$IFACE" = "wlan0" ] || [ "$IFACE" = "eth0" ]; then
    case "$ACTION" in
        up)
            /usr/local/bin/ttp --quiet start --watchdog
            ;;
        down)
            /usr/local/bin/ttp --quiet stop
            ;;
    esac
fi
```

Native packages install `ttp` as `/usr/bin/ttp`; the source installer uses
`/usr/local/bin/ttp`. Use the path `command -v ttp` prints.

1. Make the script executable and set root ownership:

```bash
sudo chmod +x /etc/NetworkManager/dispatcher.d/99-ttp.sh
sudo chown root:root /etc/NetworkManager/dispatcher.d/99-ttp.sh
```

---

## 3. Creating a Custom systemd Service Unit

To run TTP as a system service managed by `systemd`:

1. Create `/etc/systemd/system/transparent-tor-proxy.service`:

```ini
[Unit]
Description=Transparent Tor Proxy (TTP)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ttp --quiet start --watchdog
ExecStop=/usr/local/bin/ttp --quiet stop
# Tor bootstrap (180 s by default) plus verification (60 s) must fit.
TimeoutStartSec=300
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

1. Reload systemd daemon and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable transparent-tor-proxy.service
```

!!! warning "This is not protection from boot"
    TTP has no start-at-boot mode, and a unit like this one does not add one. It
    runs after `network-online.target`, so the host is already on the network, in
    cleartext, before the session exists; DNS and NTP were observed leaving in that
    window when a reboot was measured
    ([security assessment, section 4.3](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/security-assessment.md#43-lifecycle-transitions-what-is-measured-and-what-is-not)).
    If the session fails to start, the unit fails and the host stays in cleartext.
    `sudo ttp status` tells you which state you are in.

---

## 4. Script Return Codes and Status Inspection

When invoking TTP inside shell scripts, branch on the exit code instead of
testing only for success. The code says what state the host is in:

```bash
#!/bin/bash

sudo ttp --quiet start --watchdog && status=0 || status=$?

case "$status" in
    0)  echo "Session active and Tor confirmed." ;;
    3)  echo "Session active, but the Tor check was inconclusive." >&2 ;;
    7)  echo "Emergency: all traffic is blocked until 'sudo ttp stop'." >&2
        exit 7 ;;
    8)  echo "Containment unconfirmed: treat the host as leaking; run 'sudo ttp stop'." >&2
        exit 8 ;;
    2|4|10)
        echo "Refused before any change (usage, DNSSEC or VPN): see the error." >&2
        exit "$status" ;;
    *)  echo "No session (code $status): the host is in cleartext." >&2
        exit "$status" ;;
esac
```

- `0`: the session is active *and* traffic was confirmed to reach Tor.
- `3`: the session's rules are in place, but the external check could not answer.
  Nothing bypasses them, yet Tor may or may not be carrying traffic: run
  `sudo ttp check` again before relying on it.
- `7`: the emergency rules are verified in the kernel; the host is offline on
  purpose, and stays so until `sudo ttp stop`.
- `8`: containment was required and TTP cannot show it is in place.
- `2`, `4`, `10`: a refusal before any change. With `10`, a retained VPN guard
  may still block traffic: `sudo ttp stop --restore-only` releases it.
- `1`, `5`, `6`, `9` on their own after `start` mean the start failed and the
  network was restored: **cleartext**. (`5` and `6` with containment come back as
  `7` or `8`, which take precedence.)

The full table, with the precedence when several causes apply, is in the
[CLI reference](../reference/cli.md#4-cli-exit-codes). For the complete set of
causes, read `sudo ttp status --json`.

Testing only for `$? -eq 0` collapses "blocked" and "cleartext" into one, which
is how `ttp restart && next_command` ends up running against a blocked network,
or `ttp start || retry` against an open one.
