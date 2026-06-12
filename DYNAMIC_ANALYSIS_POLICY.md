# Dynamic Analysis Policy

TTP utilizes **Hypothesis**, a property-based testing framework, for dynamic fuzzing and code analysis.

## Scope

The fuzzer exercises the following attack surfaces:
- JSON lock file parsing (`state.py`)
- Tor version regex extraction (`tor_detect.py`)
- Torrc configuration validation regexes (`tor_detect.py`)
- OS family detection string matching (`tor_detect.py`)
- `/proc/mounts` line parsing (`dns.py`)
- SELinux module detection regex (`tor_detect.py`)

## Process for Vulnerabilities Found by the Fuzzer

1. **Triage**: When the fuzzer identifies a crash or a logic error, the issue is assigned a `P1` (Critical) priority in the issue tracker.
2. **Remediation**: A fix for the vulnerability **must** be committed and merged within **7 days** of confirmation.
3. **Verification**: After a fix is applied, the fuzzer **must** run successfully on the updated codebase (running the test suite with a high number of examples, e.g., `max_examples=10000`) to confirm the vulnerability is resolved.
4. **Documentation**: For every confirmed vulnerability, an entry must be added to `CHANGELOG.md` under a "Security" subsection, detailing the issue and the fix.

## Assertions

Python assertions (`assert`) are enabled during all test and fuzzing runs. The `-O` (optimize) flag is **never** used in CI/CD environments to ensure `__debug__` remains `True` and all assertions are active.

## Automation

The fuzzing workflow (`.github/workflows/fuzzing.yml`) runs automatically:
- On every pull request targeting `main`.
- Weekly (every Sunday at midnight UTC) via scheduled cron.

This policy applies to all findings from the `fuzzing.yml` GitHub Action.
