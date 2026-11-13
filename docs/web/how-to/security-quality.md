# Security and quality findings

GitHub aggregates different tools in this view. A Scorecard finding measures a
repository practice; it is not automatically a confirmed vulnerability in TTP.
The November 2026 review found seven open Scorecard findings and no open CodeQL
or Dependabot vulnerability alerts.

## Dependency downloads

Findings 27–30 and 37 identified unverified Python downloads in the manual
installer and integration images. Those paths now use the reviewed version/hash
locks in `requirements/`. CI and documentation use the same installation helper; fuzzing uses the
same reviewed locks. Native packages retain distribution dependencies and `pyproject.toml`
retains compatibility ranges. Release builds keep their existing independent
hash-pinned backend.

The helper first installs hash-verified build wheels, then reviewed dependencies
without dependency resolution or isolated build downloads. It builds trusted
local TTP source without isolation and installs its wheel with `installer`.
A mismatched download is an error. Source and lock review are still necessary:
a valid hash does not prove an upstream package is benign.

Regenerate with `scripts/update_dependency_locks.sh` (requires uv), review the
diff and audit results, and let the supported Python/distribution CI matrix run
before merging. The oldest-dependency profile keeps its explicit compatibility
pins. A separate latest-dependency job deliberately resolves new packages to
expose upcoming incompatibilities; it is not the release/install environment.

Dependabot excludes `requirements/oldest.in` and `requirements/oldest.txt`
from automatic updates: these are compatibility fixtures whose runtime pins
must continue to match `packaging/oldest-supported.pins`. The lock audit still
checks every pinned version in those files. Review any security finding there
explicitly rather than silently raising the supported dependency floors.
Pydantic/core/settings and wcmatch/bracex updates are grouped so related
versions are resolved and validated together.

## Parser fuzzing

Finding 32 did not recognize the existing Hypothesis workflow. Scorecard only
recognizes selected integrations. The old harness also mostly reimplemented
small pieces of parsing instead of exercising TTP directly.

The replacement properties call production bridge validation, DNS output
parsing, external-result reduction, settings snapshot validation and diagnostic
deserialization. Hypothesis and ClusterFuzzLite/Atheris exercise the same
properties. Invalid input may be rejected with the documented exception;
unexpected exceptions and failed invariants must fail the job. These tests do
not execute privileged operations or contact external services.

Run the generated-input suite with:

```bash
HYPOTHESIS_PROFILE=ci pytest fuzzing/fuzz_target.py -v
```

ClusterFuzzLite uses the official Python builder pinned by digest and Actions
pinned by commit. It builds a standalone Atheris target and runs bounded PR and
scheduled fuzzing. Crash artifacts are available from the Actions run. Adding
this integration does not establish exhaustive parser coverage or absence of
vulnerabilities.

## Branch protection

Finding 22 reports a protection score below the maximum. The approved rules for
`main` require pull requests, passing status checks, resolved conversations and
linear history. Zero independent approvals are required for this single-maintainer
project. There is no administrator bypass. Changes must pass the required checks
through a pull request. Zero mandatory reviewers cannot satisfy Scorecard's
higher review tiers; this residual finding is an accepted governance tradeoff,
not a claim that maximum protection was achieved.

See the [Scorecard check definitions](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
and the repository's active GitHub ruleset for the exact checks and enforcement.
