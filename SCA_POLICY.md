# Software Composition Analysis (SCA) Policy

TTP uses Dependabot to monitor vulnerabilities in Python dependencies.

## Severity Thresholds
- **Critical / High**: Must be resolved within **7 days** of notification.
- **Medium**: Resolved within **30 days**.
- **Low**: Resolved in the next release, or accepted with justification.

## Remediation Process
1. Dependabot automatically opens a PR with the update.
2. The PR is merged after CI tests pass.
3. If the update is not possible (e.g., breaking changes), we evaluate a patch or dependency isolation.

## License Compliance
Dependencies must have licenses compatible with the MIT license (TTP's license). Any conflicts must be resolved before merging.

## Before Each Release
- Run `pip-audit` or `safety check` to verify that there are no unresolved vulnerabilities.
- Manually check Dependabot reports.
- If there are unresolved critical or high vulnerabilities, **the release is blocked** until remediation.
