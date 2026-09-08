<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0001: Record Architectural Decisions

## Status

Accepted (v0.4.7)

## Context

TTP makes design choices whose rationale is not recoverable from the code alone. Six
months later, a maintainer reading a module cannot tell whether an unusual construction is a
deliberate trade-off or an accident, which makes changes either reckless or paralyzed.

Commit messages are too granular and pull request discussions disappear from view. We need a durable,
reviewable record of the decisions that shape the architecture.

## Decision

We decided to record architectural decisions as ADRs in `docs/decisions/`, following
[Michael Nygard's format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).

An ADR is required for any change that alters a trust boundary, introduces or removes a dependency
with architectural weight, changes the module layering, or would be surprising to a contributor
reading the code without context. The requirement is codified in
[`docs/documentation-policy.md`](../documentation-policy.md).

### Alternatives Considered

| Alternative | Why it was rejected |
| :---------- | :------------------ |
| Wiki pages | Not versioned with the code; drifts silently. |
| Long-form design docs | Too heavy for incremental decisions; rarely updated. |
| Commit messages only | Not discoverable; granularity too fine. |

## Consequences

* **Pros**:
  * The rationale for each decision survives maintainer turnover.
  * Reviewers can challenge a decision in the pull request that introduces its ADR.
  * New contributors have a reading path into the architecture.
* **Cons**:
  * Slight overhead per architectural change.
* **Neutral**:
  * ADRs are immutable; superseding requires a new record.

## References

* [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
