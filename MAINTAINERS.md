# Maintainers

This document lists the maintainers of the Transparent Tor Proxy (TTP) project and defines the processes governing maintainership responsibilities, access, and lifecycle.

---

## Project Lead

| Handle  | GitHub                                   | Role                     | Since |
| :------ | :--------------------------------------- | :----------------------- | :---- |
| `onyks` | [@onyks-os](https://github.com/onyks-os) | Creator & Lead Developer | 2026  |

## Core Contributors

*We are actively looking for contributors who want to take on a maintainer role. See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get involved.*

## Emeritus Maintainers

*Maintainers who have stepped down but made significant past contributions will be listed here with our gratitude.*

---

## Project Roles

The table below maps each operational role to its current holder. A single person may hold multiple roles (as is the case for a solo-maintained project).

| Role                 | Current Holder | Responsibilities                                                                                                                                        |
| :------------------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Project Lead**     | `onyks`        | Final decision-maker on architecture, roadmap, and breaking changes.                                                                                    |
| **Code Reviewer**    | `onyks`        | Reviews and approves Pull Requests; enforces coding standards and architectural principles.                                                             |
| **Release Manager**  | `onyks`        | Owns the full release pipeline: version bump, CHANGELOG update, package build (`.deb`, `.rpm`, wheel), PyPI publish, and artifact signing via Sigstore. |
| **Security Officer** | `onyks`        | Triages private vulnerability disclosures, coordinates fixes, publishes GitHub Security Advisories, and ensures the SECURITY.md policy is kept current. |
| **CI/CD Maintainer** | `onyks`        | Maintains GitHub Actions workflows, manages repository secrets, and ensures the test pipeline (unit + integration) remains healthy.                     |

> When the project gains additional contributors, roles will be distributed and this table updated accordingly.

---

## Access to Sensitive Resources

| Resource                   | Access Holder | Notes                                                   |
| :------------------------- | :------------ | :------------------------------------------------------ |
| GitHub Repository (Admin)  | `onyks`       | Full admin access                                       |
| PyPI (package publishing)  | `onyks`       | Owner of `transparent-tor-proxy`                        |
| GitHub Actions Secrets     | `onyks`       | Manages CI/CD credentials                               |
| Sigstore / Release Signing | `onyks`       | Signs release artifacts via Sigstore (keyless)          |
| Security Reporting Inbox   | `onyks`       | `ttp.nzkav@aleeas.com` — see [SECURITY.md](SECURITY.md) |

---

## Responsibilities

Maintainers are expected to:

- **Review and merge Pull Requests** in a timely manner (target: within 7 days).
- **Triage issues**: label, respond to, and close stale issues.
- **Enforce the security policies** defined in [SECURITY.md](SECURITY.md).
- **Ensure CI passes** (`make verify`) before merging any change.
- **Manage releases**: version bumping, changelog update, package build, and PyPI publishing.
- **Respond to security disclosures** within 48 hours (see [SECURITY.md](SECURITY.md)).

---

## Merge Policy

- All changes to `main` must go through a Pull Request. Direct pushes to `main` are reserved for critical hotfixes only.
- At least **one maintainer approval** is required before merging.
- All CI checks (`make verify`, linting, unit and integration tests) must pass.
- PRs touching security-critical paths (`firewall.py`, `dns.py`, `tor_control.py`, `watchdog.py`, `.github/workflows/`) require explicit sign-off from the Project Lead.

---

## Becoming a Maintainer

Maintainership is granted based on sustained, high-quality contributions. The path is:

1. Contribute multiple non-trivial Pull Requests that are reviewed and merged.
2. Demonstrate understanding of TTP's architecture, security model, and crash-safety principles.
3. Be nominated by the current Project Lead or an existing Core Contributor.
4. Accept the [Code of Conduct](CODE_OF_CONDUCT.md) and the responsibilities described in this document.

---

## Offboarding a Maintainer

When a maintainer becomes inactive or steps down:

1. They are moved to the **Emeritus** section of this file.
2. All access (GitHub admin, PyPI, secrets) is revoked promptly.
3. Any release signing keys or credentials they held are rotated.
4. A note is added to the CHANGELOG if they made significant contributions.
