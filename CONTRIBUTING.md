# Contributing to TTP

First off, thank you for considering contributing to TTP! It's people like you who make TTP such a great tool for the privacy community.

## Table of Contents

- [Contributing to TTP](#contributing-to-ttp)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [How to Report Bugs](#how-to-report-bugs)
  - [How to Propose Features](#how-to-propose-features)
  - [Development Setup](#development-setup)
  - [Coding Standards](#coding-standards)
  - [Architectural Principles](#architectural-principles)
  - [Testing](#testing)
    - [When Tests Run](#when-tests-run)
    - [Interpreting Results](#interpreting-results)
    - [Test Policy for Major Changes](#test-policy-for-major-changes)
  - [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
  - [Pull Request Process](#pull-request-process)
  - [Security Best Practices for GitHub Actions](#security-best-practices-for-github-actions)
    - [1. Never interpolate untrusted data directly into shell commands](#1-never-interpolate-untrusted-data-directly-into-shell-commands)
    - [2. Avoid using `pull_request_target` unless strictly necessary](#2-avoid-using-pull_request_target-unless-strictly-necessary)
    - [3. Use official actions from trusted sources](#3-use-official-actions-from-trusted-sources)
    - [4. Limit `GITHUB_TOKEN` permissions](#4-limit-github_token-permissions)
    - [5. Sanitize inputs from `github.event.issue.body` or `github.event.comment.body`](#5-sanitize-inputs-from-githubeventissuebody-or-githubeventcommentbody)
    - [6. Run untrusted code in isolated containers](#6-run-untrusted-code-in-isolated-containers)
    - [Reference](#reference)

## Code of Conduct

By participating in this project, you agree to maintain a professional and respectful environment. Please be kind to others.

## How to Report Bugs

- **Check existing issues**: Someone might have already reported it.
- **Use the template**: Provide as much detail as possible.
- **Diagnostics**: Always include the output of `sudo ttp diagnose` if the bug is related to connectivity or system configuration.

## How to Propose Features

- Open an issue titled `[Feature Request] Your idea`.
- Explain why this feature is needed and how it fits the project's goal of simplicity and crash-safety.

## Development Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/onyks-os/TransparentTorProxy.git
   cd TransparentTorProxy
   ```

2. **Create a virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install in editable mode with dev dependencies**:

   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests**:

   ```bash
   pytest tests/ -v
   ```

## Coding Standards

All contributions must conform to the following standards before being submitted. These checks are enforced automatically by the CI pipeline.

- **Linting & Formatting**: Python code must pass `ruff check` and `ruff format` without errors or warnings.
- **Shell Scripts**: All bash/shell scripts in `scripts/` and elsewhere must pass `shellcheck` without errors.
- **Style Conventions**: Follow [PEP 8](https://peps.python.org/pep-0008/) naming and style conventions. `ruff` enforces this automatically.
- **Type Annotations**: New functions and methods must include type annotations for all parameters and return values, consistent with the existing codebase.
- **No dead code**: Remove unused imports, variables, and commented-out code blocks before submitting a PR.

> PRs that fail `ruff check` or `shellcheck` linting will not be merged.

## Architectural Principles

When writing code for TTP, please adhere to these core principles:

1. **Single Responsibility Principle (SRP)**: Each module should do one thing. Keep UI logic (`rich`/`typer`) in `cli.py` and system logic in dedicated modules.
2. **No UI Coupling**: Modules like `tor_control.py` or `firewall.py` should NOT import `rich` or `typer`. Use callbacks or return raw data.
3. **Atomic Operations**: System changes (like firewall rules) must be atomic. We use `nft -f` to ensure the firewall is never in a half-configured state.
4. **Crash-Safety**: Always consider what happens if the power goes out mid-operation. Use the lock file system in `state.py` to track changes that need rolling back.
5. **TDD (Test Driven Development)**: Every new feature or bug fix should include a corresponding unit test in `tests/`.

## Testing

- **Unit Tests**: Must pass on every PR. They are fully mocked and run without root.
- **Integration Tests**: Should be run in a VM (see `README.md`) to verify actual network behavior.

### When Tests Run

- **Pull Requests**: Every PR automatically triggers the CI pipeline (GitHub Actions). The following checks are executed:
  - Linting with `ruff check` and `ruff format`
  - Shell scripting linting with ShellCheck
  - Unit tests on Python versions 3.10, 3.11, 3.12, and 3.13
- **Push to Main**: The same suite of tests and checks is run on any push to the main branch.
- **Locally**: You can (and should) run `pytest tests/ -v` locally before submitting your pull request.

### Interpreting Results

- **All tests pass (green)**: The code is ready for review and potential merge.
- **Any test fails (red)**: Blocks the merge. Review the logs, correct the issue, and push the updates.

### Test Policy for Major Changes

A change is considered **major** if it:
- Adds a new significant feature (e.g., a new CLI command).
- Modifies the firewall rules (`nftables`) or DNS resolution management.
- Alters the crash-safety architecture.

In these cases, the contributor **must**:
- Add new unit tests to cover the functionality.
- Update existing tests if the expected behavior changes.
- Manually run integration tests in a virtual machine (VM).

Pull requests will be blocked from merging if tests do not sufficiently cover the changes.

## Developer Certificate of Origin (DCO)

By contributing to TTP, you certify that you have the right to submit the contribution under the project's MIT license, and you agree to the [Developer Certificate of Origin v1.1](https://developercertificate.org/).

**Every commit must include a `Signed-off-by` line** with your real name and email:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The easiest way to add it is with the `-s` flag:

```bash
git commit -s -m "your commit message"
```

For multiple commits in a branch, you can amend them all at once:

```bash
git rebase --signoff HEAD~<number-of-commits>
```

> PRs with unsigned commits will not be merged. The DCO check is enforced automatically by the CI pipeline.

<details>
<summary>Full DCO text</summary>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

</details>

## Pull Request Process

1. Create a branch from `main`.
2. Ensure your code passes all linting checks (`ruff check`, `shellcheck`) and unit tests.
3. Update the documentation (`README.md`, `architecture.md`) if needed.
4. Submit the PR and wait for review.

Thank you for your help!

---

## Security Best Practices for GitHub Actions

When contributing workflows or modifying existing CI pipelines, follow these guidelines to prevent injection attacks.

### 1. Never interpolate untrusted data directly into shell commands

**Bad** (vulnerable to script injection):

```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```

**Good** (use environment variables):

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $PR_TITLE"
```

### 2. Avoid using `pull_request_target` unless strictly necessary

This trigger runs in the context of the base repository and can expose secrets to malicious code from a fork. Prefer `pull_request` instead.

### 3. Use official actions from trusted sources

Prefer actions from `actions/`, `github/`, or verified publishers. Review third-party actions for security before adding.

### 4. Limit `GITHUB_TOKEN` permissions

Set minimal permissions at workflow level:

```yaml
permissions:
  contents: read
  pull-requests: write
```

### 5. Sanitize inputs from `github.event.issue.body` or `github.event.comment.body`

If you must use user-provided text, validate it against an allowlist or escape special characters before passing to scripts.

### 6. Run untrusted code in isolated containers

For actions that execute code from PRs (e.g., linters on forked repos), consider running them inside a Docker container with no access to secrets.

### Reference

- [GitHub Security Hardening for Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
