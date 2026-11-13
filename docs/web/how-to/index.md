# How-To Guides

- [Onion addresses and LAN bypass](onion-addresses.md) — reserved virtual
  ranges, LAN compatibility and calibrated E01 evidence.

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
- [Check applications that resolve DNS on their own](apps-with-own-dns.md) — browser DoH,
  per-link resolvers and containers: what happens to each under TTP, and how to check.
- [Resolve a DNSSEC policy conflict](dnssec.md) — automatic session settings,
  explicit interface requirements, refusal code `4` and restoration.
- [Interpret DNS and UDP containment tests](leak-evidence.md) — external packet
  observations, positive controls, inconclusive socket results and scope.
- [Observe faults continuously](continuous-fault-evidence.md) — initial exposure,
  recovery, calibration and retained VM captures.
- [Verify Tor's AppArmor confinement](apparmor.md) — mandatory enforce mode on
  AppArmor kernels, passive observations, emergency handling and deployment limits.
