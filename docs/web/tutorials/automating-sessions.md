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

if sudo ttp --quiet start; then
    echo "TTP session established."
else
    echo "Failed to start TTP session." >&2
    exit 1
fi
```

Exit code `0` indicates successful session establishment. Exit code `1` indicates preflight failure or missing root privileges.
