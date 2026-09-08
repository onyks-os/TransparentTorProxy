# ---------------------------------------------------------------------------
# quality.mk — linting, formatting, testing, and security gates.
#
# The language profile (make/<profile>.mk) implements the lang-* contract;
# everything here is language-agnostic orchestration.
# ---------------------------------------------------------------------------

.PHONY: lint lint-code lint-shell lint-docs lint-secrets format test integration-test fuzz audit

##@ Quality

lint: lint-code lint-shell lint-docs lint-secrets ## Run every linter and static check

lint-code: lang-lint ## Lint and type-check first-party source

lint-shell: ## Lint shell scripts with ShellCheck
	@if command -v shellcheck >/dev/null 2>&1; then \
		echo "==> [$(PROJECT_SHORT)] Running ShellCheck..."; \
		found=$$(find $(SCRIPT_DIRS) -name '*.sh' 2>/dev/null); \
		if [ -n "$$found" ]; then shellcheck $$found; else echo "==> No shell scripts found."; fi; \
	else \
		echo "==> ShellCheck not found, skipping. Install it: https://shellcheck.net"; \
	fi

lint-docs: ## Lint Markdown and check for broken relative links
	@if command -v markdownlint >/dev/null 2>&1; then \
		echo "==> [$(PROJECT_SHORT)] Running markdownlint..."; \
		markdownlint '**/*.md' --ignore node_modules --ignore .venv --ignore venv --ignore .internal; \
	else \
		echo "==> markdownlint not found, skipping. Install it: npm i -g markdownlint-cli"; \
	fi

lint-secrets: ## Fail if a tracked file looks like it contains a secret
	@# Scans tracked files only: the point is to catch a secret before it is pushed,
	@# and untracked scratch files are not going anywhere.
	@if ! git rev-parse --git-dir >/dev/null 2>&1; then \
		echo "==> Not a git repository, skipping the secret scan."; \
	elif git grep -nIE '(BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+)' \
		-- ':!*.md' ':!make/*' 2>/dev/null; then \
		echo "!!! Potential secret found in a tracked file. Revoke it and remove it from history."; \
		echo "!!! See SECRETS_POLICY.md for the incident response steps."; \
		exit 1; \
	else \
		echo "==> [$(PROJECT_SHORT)] No secret patterns detected in tracked files."; \
	fi

format: lang-format ## Auto-format the codebase and fix what can be fixed

##@ Testing

test: lang-test ## Run the unit test suite (fast, no privileges)

integration-test: lang-test-integration ## Run integration tests (may require privileges)

fuzz: lang-fuzz ## Run property-based fuzz tests

audit: lang-audit ## Scan dependencies for known vulnerabilities
