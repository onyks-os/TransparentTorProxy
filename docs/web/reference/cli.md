# Reference: CLI Command Line Interface

TTP provides a clean, Typer-powered command-line interface. Most network-modifying commands require root privileges (`sudo`).

---

## Commands Summary

| Command | Privileges | Description |
|---|---|---|
| `sudo ttp start` | Root | Start the transparent Tor proxy session. |
| `sudo ttp stop` | Root | Stop the transparent proxy session and restore networking. |
| `sudo ttp restart` | Root | Restart the transparent proxy session cleanly. |
| `ttp status` | User | View current session status and active settings. |
| `ttp check` | User | Verify Tor network connectivity, circuit state, and exit IP. |
| `sudo ttp refresh` | Root | Request a new Tor exit IP circuit (`NEWNYM` signal). |
| `sudo ttp diagnose` | Root | Execute diagnostic tests and generate a system report. |
| `sudo ttp purge` | Root | Remove temporary state, locks, and SELinux modules. |
| `ttp logs` | User | View recent TTP volatile session logs. |
| `sudo ttp run` | Root | Execute a command bypassing the Tor proxy as a specified user. |

---

## Common `ttp start` Options

```text
Options:
  --watchdog / --no-watchdog  Enable background FSM integrity watchdog [default: watchdog]
  --lan-bypass / --no-lan-bypass Exclude RFC 1918 local subnets [default: lan-bypass]
  --bypass-user TEXT          System user(s) to bypass proxying
  --bypass-group TEXT         System group(s) to bypass proxying
  --bridge TEXT               Tor bridge configuration line(s)
  --bridge-file PATH          File containing Tor bridge configuration lines
  --no-ipv6                   Force drop all outbound IPv6 traffic
```
