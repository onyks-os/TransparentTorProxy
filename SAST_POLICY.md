# SAST Policy

TTP uses **CodeQL** (GitHub) and **Ruff** for static analysis (SAST) of the codebase.

## Severity Thresholds
- **Critical / High**: Must be resolved **before merging** the PR.
- **Medium**: Resolved within **7 days** of identification.
- **Low**: Acceptable for merging, but should be resolved in the next release.

## Remediation Process
1. The PR is blocked if CodeQL detects Critical/High vulnerabilities.
2. The developer fixes the code (or marks the alert as a false positive using the appropriate suppression comment, e.g., `# codeql[rule-id]`).
3. Once corrected, the status check passes and the PR can be merged.

## False Positives
If a finding is deemed non-exploitable or a false positive, it must be suppressed inline with a comment explaining the rationale.
