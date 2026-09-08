# Governance

This document describes how decisions are made in TransparentTorProxy (TTP).

## Model

TTP follows a **BDFL-with-delegation** model: the Project Lead has final authority, and
delegates areas of responsibility to maintainers as the contributor base grows. The roles and their
current holders are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Decision-Making

| Decision type                                | Process                                                                    |
| :------------------------------------------- | :------------------------------------------------------------------------- |
| Bug fix, documentation, refactor             | One maintainer approval on the pull request.                               |
| New feature                                  | Issue discussion first; then one maintainer approval.                      |
| Architectural change or breaking change      | An [ADR](docs/decisions/) is required, plus Project Lead approval.         |
| Security-critical change                     | Project Lead sign-off is mandatory.                                        |
| License change, code of conduct change       | Project Lead decision, announced in an issue at least 14 days in advance.  |

Disagreements are resolved by discussion in the issue or pull request. If consensus is not reached
within a reasonable time, the Project Lead decides and records the rationale in the thread or, for
architectural matters, in an ADR.

## Proposing a Change

1. Open an issue describing the problem, not just the solution.
2. For anything architectural, submit an ADR using the template in
   [`docs/decisions/0000-adr-template.md`](docs/decisions/0000-adr-template.md).
3. Once the approach is agreed, submit the implementation as a pull request.

## Communication Channels

- **GitHub Issues** — bug reports, feature requests, and design discussions (primary channel).
- **GitHub Security Advisories** — private vulnerability reports.
- **Email** — `ttp.nzkav@aleeas.com` for anything that cannot be public.

All project decisions are made in public channels so that they remain auditable. Private discussion
is limited to security disclosures and code-of-conduct matters.

## Changing This Document

Amendments to this document follow the same process as a breaking change: a pull request, a 14-day
comment period, and Project Lead approval.
