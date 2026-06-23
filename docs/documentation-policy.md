# Repository Modification & Documentation Policy

This document defines the requirements for maintaining consistency between the source code, the test suites, and the project documentation. It specifies exactly which files must be updated for every type of modification to the repository.

---

## Modification Matrix Summary

| Type of Modification           | Tests Required? | Update `CHANGELOG.md`? | Update `docs/interfaces.md`? | Update `docs/architecture.md`? | Update `README.md`? | Update `docs/security-assessment.md`? | Update `DEPENDENCIES.md`? |
| :----------------------------- | :-------------: | :--------------------: | :--------------------------: | :----------------------------: | :-----------------: | :-----------------------------------: | :-----------------------: |
| **1. CLI Options / Commands**  |      ✅ Yes      |         ✅ Yes          |        ✅ Yes (Sec. 1)        |            ⚠️ Maybe             |       ⚠️ Maybe       |            ✅ Yes (STRIDE)             |           ❌ No            |
| **2. Core Network / Logic**    |      ✅ Yes      |         ✅ Yes          |             ❌ No             |             ✅ Yes              |        ❌ No         |                 ✅ Yes                 |           ❌ No            |
| **3. Dependencies / Versions** |      ❌ No       |         ✅ Yes          |             ❌ No             |              ❌ No              |        ❌ No         |            ✅ Yes (Sec. 5)             |           ✅ Yes           |
| **4. Packaging / Installer**   |      ❌ No       |         ✅ Yes          |             ❌ No             |              ❌ No              |       ⚠️ Maybe       |                 ❌ No                  |     ✅ Yes (Sys. deps)     |
| **5. Test Suite / Fuzzing**    |      ❌ No       |         ✅ Yes          |             ❌ No             |              ❌ No              |        ❌ No         |                 ❌ No                  |           ❌ No            |
| **6. Security Policies**       |      ❌ No       |         ✅ Yes          |             ❌ No             |              ❌ No              |        ❌ No         |                 ❌ No                  |           ❌ No            |
| **7. Architectural Decisions** |      ❌ No       |         ✅ Yes          |           ⚠️ Maybe            |             ✅ Yes              |       ⚠️ Maybe       |                 ✅ Yes                 |           ❌ No            |
| **8. Pure Documentation**      |      ❌ No       |         ✅ Yes          |             ❌ No             |              ❌ No              |        ❌ No         |                 ❌ No                  |           ❌ No            |

---

## Detailed Requirements by Scenario

### 1. Modifying CLI Commands or Options
When adding, modifying, or deleting command-line commands, groups, options, flags, or default parameters:
* **Source Code**: Modify `ttp/cli.py` (and optionally `ttp/state.py` if the state lock structure changes).
* **Tests**: Add/update CLI validation and argument parsing unit tests in `tests/test_cli.py`.
* **CHANGELOG.md**: Add an entry under the `### Added`, `### Changed`, or `### Removed` subheadings of the current development version.
* **docs/interfaces.md**: Update the Command Line Interface (CLI) tables (including options lists, required privileges, and descriptions) and the Exit Codes section if applicable.
* **docs/security-assessment.md**: Re-verify and update the STRIDE analysis for the CLI boundary, ensuring any new user input is marked as sanitization boundaries.
* **README.md**: Update only if the change affects the core Quick Start commands or if it is a major user-facing feature.

### 2. Modifying Core Network or System Logic
When altering the firewall (`firewall.py`), DNS routing (`dns.py`), watchdog daemon (`watchdog.py`), state management (`state.py`), or Tor lifecycle logic (`tor_install.py` / `tor_control.py`):
* **Tests**: 
  * Add unit tests in the corresponding `tests/test_*.py` file (e.g. `tests/test_firewall.py`).
  * Run the isolated ruleset validation tests via `tests/test_nse_rules.py`.
  * If the logic interacts with watchdog or system crashes, verify via the Chaos Monkey test (`tests/chaos_monkey.py`).
* **CHANGELOG.md**: Add a description of the change under `### Added` or `### Fixed` for the active version.
* **docs/architecture.md**: If components interaction or system flow is altered, update the corresponding architecture text and diagrams.
* **docs/security-assessment.md**: Re-evaluate the STRIDE threat model. Document any new security boundaries, potential lockouts, or mitigation controls.

### 3. Adding or Updating Dependencies
When introducing a new Python library, updating package version constraints in `pyproject.toml`, or adding dynamic dependencies:
* **CHANGELOG.md**: Log the package addition/update and version bump.
* **DEPENDENCIES.md**: 
  * Update the python or system dependencies table.
  * Provide the package license and version constraints.
  * Document the security justification (why the package is needed and what security checks were performed).
* **docs/security-assessment.md**: Update the Supply Chain Security Controls section to reflect the new dependency.

### 4. Modifying Packaging or Installers
When editing the `.deb`/`.rpm` packaging scripts (`packaging/`), source release triggers (`release.sh`, `Makefile`), or system installers (`scripts/install.sh`):
* **CHANGELOG.md**: Detail the installer/packaging enhancements under `### Changed` or `### Added`.
* **DEPENDENCIES.md**: Update the "System-Level Dependencies" section if the required package manager items change.
* **README.md**: Update the "Installation" instructions if the system requirements, paths, or pip installation options change.

### 5. Modifying or Adding Tests
When updating the test suite, adding new integration test cases, or fixing flaky test scenarios:
* **CHANGELOG.md**: Document under `### Changed` or `### Fixed` if the changes affect test harness coverage, flakiness fixes, or CI execution.
* **Documentation**: No updates to architecture, interfaces, or security models are required unless the test framework itself introduces user-exposed validation tools (e.g. NSE).

### 6. Updating Security Policies
When editing policies like `SECURITY.md`, `SAST_POLICY.md`, `SCA_POLICY.md`, or `SECRETS_POLICY.md`:
* **CHANGELOG.md**: Add a brief entry (e.g., `Updated project Security Policy for reporting vulnerabilities`).
* **Other Docs**: No other changes needed.

### 7. Architectural Decisions (ADR)
When making significant architectural design choices (e.g. introducing cgroups bypass, split tunneling, or changing DNS overlay strategy):
* **ADR Document**: Create a new ADR file in `docs/decisions/` following the numbered format: `XXXX-brief-description.md`. Register the new ADR in the table of contents inside `docs/decisions/README.md`.
* **CHANGELOG.md**: Log the decision and the features stemming from it under the active version.
* **docs/architecture.md**: Document the component additions/changes and update the high-level diagrams to keep them aligned.
* **docs/interfaces.md**: If the decision changes CLI commands, exit codes, or config schemas, update interfaces accordingly.
* **docs/security-assessment.md**: Re-run the threat analysis to reflect the new component design and boundaries in the threat model.

### 8. Pure Documentation Changes
When correcting typos, clarifying paragraphs, or updating maintenance logs in existing documentation files (e.g. `MAINTAINERS.md`, `SUPPORT.md`, or `ROADMAP.md`):
* **CHANGELOG.md**: Document the documentation update (e.g., `Added maintainers governance roles` or `Updated project support channels`).
* **Other Files**: None.

---

## Commit & PR Checklist for Contributors

Before submitting any Pull Request, ensure you have followed this checklist:
1. [ ] **Code Changes**: The feature or bug fix is fully implemented in the `ttp/` package.
2. [ ] **Unit Tests**: Coverage is maintained or increased; tests pass locally with `pytest`.
3. [ ] **Formatting**: Code has been run through `ruff format` and passes `ruff check`.
4. [ ] **Documentation**:
   * [ ] **`CHANGELOG.md`** has been updated under the current version.
   * [ ] Component references in **`docs/`** are updated (Interfaces, Architecture, Security, or Dependencies).
5. [ ] **DCO Sign-off**: All commits are signed off (`git commit -s`).
