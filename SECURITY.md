# Security Policy

## Reporting a Vulnerability

We take the security of TTP seriously. If you discover a security vulnerability within this project, please **do not open a public issue**. Instead, follow these steps:

1. **Email the maintainers**: Send a detailed report to `ttp.nzkav@aleeas.com` or open a private advisory on GitHub.
2. **Provide details**: Include a description of the vulnerability, steps to reproduce, and any potential impact.
3. **Wait for a response**: We will acknowledge your report within 48 hours and work on a fix.

## Scope

This policy applies to the TTP core modules and the CLI. We are particularly concerned about:

- DNS leaks.
- IPv6 leaks.
- Firewall bypasses.
- Privilege escalation via the lock file system.

## Project Nature

> [!CAUTION]
> TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety also depends on your behavior (e.g., using a regular browser vs. Tor Browser, signing into accounts, etc.). Always use TTP as part of a multi-layered security strategy.

## Supported Versions

We only provide security updates for the latest minor version.
