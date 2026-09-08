# How-To Guides

Goal-oriented recipes for users who already know the basics. Each guide assumes a working
installation — if you do not have one, start with the [Quickstart](../tutorials/quickstart.md).

- [Exempt a user or application from Tor routing](user-bypass.md) — split tunneling by UID/GID
  and the cgroups v2 `ttp bypass` command.
- [Reach Tor from a censored network](bridges.md) — obtaining, configuring, and verifying
  obfs4 and snowflake bridges.
- [Coexist with UFW or firewalld](custom-nftables.md) — how the isolated `inet ttp` table
  relates to rules you already have.
- [Test a session safely in a VM](vm-testing.md) — the QEMU matrix and the chaos monkey
  used to exercise the watchdog and killswitch.
