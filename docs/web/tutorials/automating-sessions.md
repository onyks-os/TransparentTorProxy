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
            /usr/local/bin/ttp --quiet start --watchdog --lan-bypass
            ;;
        down)
            /usr/local/bin/ttp --quiet stop
            ;;
    esac
fi
```

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
After=network-online.target ttp-tor.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ttp --quiet start --watchdog
ExecStop=/usr/local/bin/ttp --quiet stop
TimeoutStartSec=120
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

1. Reload systemd daemon and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable transparent-tor-proxy.service
```

---

## 4. Script Return Codes and Status Inspection

When invoking TTP inside shell scripts, inspect exit codes to verify success:

```bash
#!/bin/bash
set -e

sudo ttp --quiet start && status=0 || status=$?

case "$status" in
    0) echo "TTP session established and verified." ;;
    3) echo "Session is up but Tor is unverified: traffic is blocked, not leaking." >&2
       exit 3 ;;
    *) echo "Failed to start TTP session; the network is in cleartext." >&2
       exit "$status" ;;
esac
```

`0` means the session is active *and* traffic was confirmed to be reaching Tor.
`3` means the session is active and fail-closed but Tor could not be verified —
nothing is leaking, but nothing is getting through either. Anything else means
there is no session and the host is back on clearnet.

Testing only for `$? -eq 0` collapses those last two into one, which is how
`ttp restart && next_command` ends up running against a blocked network.
