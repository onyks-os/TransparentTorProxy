# ---------------------------------------------------------------------------
# python.mk — Python implementation of the lang-* target contract.
#
# Tools are resolved from .venv when present, otherwise from PATH, so the same
# commands work inside and outside an activated virtualenv.
# ---------------------------------------------------------------------------

VENV    ?= .venv
PYTHON  ?= $(shell if [ -x $(VENV)/bin/python ]; then echo $(VENV)/bin/python; else command -v python3 || echo python3; fi)
RUFF    ?= $(shell if [ -x $(VENV)/bin/ruff ]; then echo $(VENV)/bin/ruff; else command -v ruff || echo ruff; fi)
MYPY    ?= $(shell if [ -x $(VENV)/bin/mypy ]; then echo $(VENV)/bin/mypy; else command -v mypy || echo mypy; fi)

.PHONY: lang-setup lang-lint lang-format lang-test lang-test-integration lang-fuzz lang-audit lang-build lang-clean coverage publish-test publish

lang-setup:
	@echo "==> [$(PROJECT_SHORT)] Creating virtualenv in $(VENV)..."
	@test -d $(VENV) || python3 -m venv $(VENV)
	@$(VENV)/bin/pip install --upgrade pip
	@$(VENV)/bin/pip install -e ".[dev]"

lang-lint:
	@echo "==> [$(PROJECT_SHORT)] Ruff check..."
	@$(RUFF) check $(SRC_DIRS) $(TEST_DIRS)
	@echo "==> [$(PROJECT_SHORT)] Ruff format check..."
	@$(RUFF) format --check $(SRC_DIRS) $(TEST_DIRS)
	@echo "==> [$(PROJECT_SHORT)] mypy..."
	@$(MYPY) $(SRC_DIRS)

lang-format:
	@echo "==> [$(PROJECT_SHORT)] Auto-formatting..."
	@$(RUFF) format $(SRC_DIRS) $(TEST_DIRS)
	@$(RUFF) check --fix $(SRC_DIRS) $(TEST_DIRS)

lang-test:
	@echo "==> [$(PROJECT_SHORT)] Unit tests..."
	@$(PYTHON) -m pytest $(TEST_DIRS) -v

lang-test-integration:
	@echo "==> [$(PROJECT_SHORT)] Integration tests..."
	@$(PYTHON) -m pytest $(TEST_DIRS) -v -m integration

lang-fuzz:
	@echo "==> [$(PROJECT_SHORT)] Hypothesis fuzz tests..."
	@$(PYTHON) -m pytest fuzzing/ -v

lang-audit:
	@echo "==> [$(PROJECT_SHORT)] pip-audit..."
	@$(PYTHON) -m pip_audit .

lang-build:
	@echo "==> [$(PROJECT_SHORT)] Building sdist and wheel..."
	@$(PYTHON) -m build --outdir $(DIST_DIR)

lang-clean:
	@rm -rf .pytest_cache .ruff_cache .mypy_cache .hypothesis *.egg-info htmlcov .coverage
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true

##@ Python extras

# A ratchet, not a target. Raise it when you add tests; never lower it to make a
# build pass. The floor sits just under the measured number so an accidental
# regression is caught while a deliberate improvement is not punished.
COV_FAIL_UNDER ?= 85

coverage: ## Run the test suite with a coverage report and enforce the floor
	@$(PYTHON) -m pytest $(TEST_DIRS) --cov=$(PROJECT_PKG) --cov-report=term-missing \
		--cov-report=html --cov-report=xml --cov-fail-under=$(COV_FAIL_UNDER)

# Manual escape hatches only. Publication is normally performed by
# .github/workflows/release.yml on a tag push, which uploads the exact wheel and
# sdist that Sigstore signed. These targets rebuild from the working tree, so
# what they push does NOT correspond to any published signature - use them only
# to recover a failed release, and never for a routine one.
publish-test: build ## Upload a locally rebuilt distribution to TestPyPI (prefer the release workflow)
	@echo "==> [$(PROJECT_SHORT)] WARNING: uploading a local rebuild, not the signed release artifacts."
	@$(PYTHON) -m twine upload --repository testpypi $(DIST_DIR)/*

publish: build ## Upload a locally rebuilt distribution to PyPI (prefer the release workflow)
	@echo "==> [$(PROJECT_SHORT)] WARNING: uploading a local rebuild, not the signed release artifacts."
	@$(PYTHON) -m twine upload $(DIST_DIR)/*
