# Security Policy

## Reporting a Vulnerability

We take the security of TTP seriously. If you discover a security vulnerability within this project, please **do not open a public issue**.

### How to report (preferred method)

Use GitHub's **private vulnerability reporting**:

1. Go to [https://github.com/onyks-os/TransparentTorProxy/security/advisories](https://github.com/onyks-os/TransparentTorProxy/security/advisories)
2. Click **"Report a vulnerability"**
3. Fill out the form with as much detail as possible:
   - Description of the issue
   - Steps to reproduce
   - Affected versions
   - Potential impact (e.g., DNS leak, firewall bypass)

### Alternative contact

If you cannot use GitHub's private reporting, you may email the maintainers at:  
`ttp.nzkav@aleeas.com`

Please note that email may have lower response priority than GitHub advisories.

## What to expect

- You will receive an acknowledgment within **48 hours**.
- We will investigate and keep you informed.
- Once a fix is ready, we will credit you in the release notes (unless you prefer to remain anonymous).

## Public Disclosure

When a security vulnerability is confirmed and fixed, TTP will publish a public advisory containing:
- Affected versions
- Description of the issue
- Mitigation or upgrade instructions

The advisory will be published on:
- **GitHub Security Advisories** (public viewable at `https://github.com/onyks-os/TransparentTorProxy/security/advisories`)
- **Release notes** of the fixed version

We do not currently assign CVEs, but may do so in the future.

## Scope

This policy applies to the TTP core modules and the CLI. Priority concerns include privilege escalation and any mechanism that could deanonymize the user.

The following are considered **critical scope targets**:
1. **Firewall Bypass**: Successfully sending cleartext TCP/UDP traffic to the internet bypassing Tor (with LAN bypass disabled).
2. **DNS Leak**: Successfully resolving an external domain by bypassing Tor's `DNSPort` redirection.
3. **Watchdog Evasion**: Disabling firewall rules, stopping critical services, or unmounting the `/etc/resolv.conf` bind mount without the watchdog daemon detecting it or triggering the emergency network lockout (killswitch).

For the full STRIDE threat model, trust boundaries, risk severity ratings, and security controls inventory, see:

**[`docs/security-assessment.md`](docs/security-assessment.md)**

## Informal Bug Bounty & Hall of Fame

While there is no financial budget to offer monetary rewards, the project aims to recognize and honor security researchers who help make TTP safer.

For valid, in-scope security vulnerability reports that are confirmed and resolved, the project offers:
- **Permanent inclusion** in the [`HALL_OF_FAME.md`](HALL_OF_FAME.md) file at the root of the repository, including a link to the researcher's GitHub profile or personal website.
- **Honorable mention** in the official GitHub Release Notes for the fixed version.

## Release support policy

| Version | Support status | End of life |
| ------- | -------------- | ------------ |
| 0.4.x   | ✅ Security fixes | When 0.5.0 is released |
| 0.3.x   | ❌ No longer supported | 2026-01-01 |
| < 0.3   | ❌ Unsupported | |

- Security fixes are provided only for the latest minor version.
- If you need long-term support, please contact maintainers.

## Project Nature

> **⚠️ Disclaimer**  
> TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety also depends on your behavior (e.g., using a regular browser vs. Tor Browser, signing into accounts, etc.). Always use TTP as part of a multi-layered security strategy.

## Acknowledgments

We thank the community for responsibly disclosing security issues. Contributors who report valid vulnerabilities will be publicly acknowledged (unless they request otherwise).