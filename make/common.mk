# ---------------------------------------------------------------------------
# common.mk — environment discovery, help, housekeeping, documentation debt.
# ---------------------------------------------------------------------------

.PHONY: help setup install-hooks todo clean verify pre-commit ci-local

##@ General

help: ## Show this help
	@printf "\n\033[1m%s\033[0m — make targets\n\n" "$(PROJECT_NAME)"
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
		' $(MAKEFILE_LIST)
	@printf "\n"

setup: lang-setup ## Bootstrap the development environment
	@echo "==> [$(PROJECT_SHORT)] Environment ready. Next: make install-hooks"

install-hooks: ## Install the Git pre-commit hook (lint + unit tests)
	@echo "==> [$(PROJECT_SHORT)] Installing Git pre-commit hook..."
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nexec make pre-commit\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "==> Hook installed at .git/hooks/pre-commit"

##@ Verification

verify: lint test audit ## Full local gate — run this before every push
	@echo "======================================================================"
	@echo "[$(PROJECT_SHORT)] Local verification PASSED."
	@echo "======================================================================"

pre-commit: lint test ## Fast pre-commit checks (lint + unit tests)

ci-local: verify docs-build build ## Reproduce the full CI pipeline locally
	@echo "======================================================================"
	@echo "[$(PROJECT_SHORT)] Local CI pipeline PASSED."
	@echo "======================================================================"

##@ Housekeeping

todo: ## List the documentation sections still to be filled in
	@echo "==> [$(PROJECT_SHORT)] Outstanding template placeholders:"
	@# Tracked files only: virtualenvs and build caches contain unrelated matches.
	@if git rev-parse --git-dir >/dev/null 2>&1; then \
		git grep -In "TODO(template)" -- . || echo "==> None. Every templated section has been filled in."; \
		count=$$(git grep -Io "TODO(template)" -- . 2>/dev/null | wc -l); \
	else \
		grep -rIn --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=target \
			--exclude-dir=.venv --exclude-dir=venv "TODO(template)" . \
			|| echo "==> None. Every templated section has been filled in."; \
		count=$$(grep -rIo --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=target \
			--exclude-dir=.venv --exclude-dir=venv "TODO(template)" . 2>/dev/null | wc -l); \
	fi; \
	if [ "$$count" -gt 0 ]; then echo ""; echo "==> $$count item(s) remaining."; fi

clean: lang-clean ## Remove build artifacts, caches, and temporary files
	@echo "==> [$(PROJECT_SHORT)] Cleaning build artifacts..."
	@rm -rf dist/ build/ site/ .cache/
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "==> Clean."
