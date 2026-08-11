# Connecting in Censored Networks (Bridges)

This tutorial guides you through configuring Tor bridges in TTP to bypass network censorship, protocol filtering, and blocked Tor relays.

---

## 1. Acquiring Tor Bridges

Before configuring TTP, obtain valid bridge lines from official Tor Project channels:

* **Web**: Visit [Tor Project Bridges](https://bridges.torproject.org/)
* **Email**: Send an email from a Gmail or Riseup address to `bridges@torproject.org` with `get transport obfs4` or `get transport snowflake` in the body.
* **Telegram**: Contact `@GetBridgesBot` on Telegram.

---

## 2. Using Inline Bridge Lines (`--bridge`)

Pass bridge configuration lines directly to `sudo ttp start` using the `--bridge` option:

```bash
# Start TTP with an obfs4 bridge
sudo ttp start --bridge "obfs4 192.0.2.1:443 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=EXAMPLE fingerprint=EXAMPLE"
```

For multiple bridges, specify `--bridge` multiple times:

```bash
sudo ttp start \
  --bridge "obfs4 192.0.2.1:443 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=ABC..." \
  --bridge "obfs4 198.51.100.2:8443 A91DF57D70E69D037D770D6C31D89F0A311494 cert=XYZ..."
```

---

## 3. Using a Bridge File (`--bridge-file`)

Store multiple bridge lines in a plain text file:

```bash
# Save bridge lines to a file
cat << 'EOF' > /tmp/my_bridges.txt
obfs4 192.0.2.1:443 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=ABC...
obfs4 198.51.100.2:8443 A91DF57D70E69D037D770D6C31D89F0A311494 cert=XYZ...
EOF

# Start TTP pointing to the bridge file
sudo ttp start --bridge-file /tmp/my_bridges.txt
```

---

## 4. Monitoring Bootstrap and Troubleshooting

If bootstrapping stalls on restricted networks:

```bash
# View real-time TTP and Tor logs
ttp logs

# Run diagnostic check to verify Tor control socket connectivity
sudo ttp diagnose
```

If an obfs4 bridge is unreachable, replace it with fresh bridge lines or switch to Snowflake transports.
