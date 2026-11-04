# Reviewed Python dependency locks

`runtime.txt` is the manual install environment, `ci.txt` adds development/NSE
and audit tools, `oldest.txt` preserves Ubuntu 24.04 compatibility, and `docs.txt`
is the website toolchain. `tools.txt` bootstraps build tools from wheels before
any source distribution is built. The universal locks include Python/platform
markers and distribution SHA-256 hashes; the package metadata keeps its ranges.

Run `scripts/update_dependency_locks.sh` with uv available to propose an update.
Review version/hash changes, run `pip-audit` and the supported Python/distro CI
matrix, and merge through a PR. Never edit hashes to accept an unexpected file.
The separate newest-dependency CI job deliberately resolves fresh packages to
find incompatibilities before the reviewed locks are changed. OS package updates
remain the responsibility of the distribution package manager.

To install in a fresh virtual environment:

```bash
bash scripts/install_locked.sh /path/to/venv/bin/python ci
```

Local TTP source is built without build isolation and installed from its local
wheel with `installer`; pip cannot fetch undeclared build or runtime requirements.
Python dependency hashes verify the reviewed downloads, not the trustworthiness
of PyPI, the selected upstream version or the local TTP checkout.

The audit tool runs on Python 3.11+; Python 3.10 tests do not install it.
`python scripts/audit_dependency_locks.py` checks all locked versions, including
marker variants for other interpreters. The oldest input mirrors the compatibility
pins locally so Dependabot can parse the directory without parent paths.
