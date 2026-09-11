# ---------------------------------------------------------------------------
# docs.mk — MkDocs site build/serve and ADR scaffolding.
# ---------------------------------------------------------------------------

.PHONY: docs docs-build docs-serve docs-sync adr

MKDOCS ?= $(shell command -v mkdocs 2>/dev/null || echo mkdocs)
ADR_DIR := docs/decisions

##@ Documentation

docs: docs-build ## Alias for docs-build

docs-build: docs-sync ## Build the MkDocs documentation site
	@echo "==> [$(PROJECT_SHORT)] Building MkDocs site..."
	@if command -v mkdocs >/dev/null 2>&1; then \
		$(MKDOCS) build --strict; \
	else \
		echo "==> mkdocs not found. Install: pip install mkdocs-material mkdocstrings[python]"; \
		exit 1; \
	fi

docs-serve: ## Serve the documentation with live reload on :8000
	@echo "==> [$(PROJECT_SHORT)] Starting MkDocs dev server (http://127.0.0.1:8000)..."
	@if command -v mkdocs >/dev/null 2>&1; then \
		$(MKDOCS) serve; \
	else \
		echo "==> mkdocs not found. Install: pip install mkdocs-material mkdocstrings[python]"; \
		exit 1; \
	fi

docs-sync: ## Mirror the root CHANGELOG into the documentation site
	@echo "==> [$(PROJECT_SHORT)] Syncing CHANGELOG into the docs site..."
	@# `sed -e '1,/^# Changelog$$/d'` leaves the blank line that followed the
	@# heading, which lands next to the one echoed here and trips markdownlint's
	@# MD012. `cat -s` squeezes runs of blank lines to one.
	@{ \
		echo "# Release Notes & Changelog"; \
		echo ""; \
		sed -e '1,/^# Changelog$$/d' CHANGELOG.md; \
	} | cat -s > docs/web/release-notes/changelog.md

adr: ## Scaffold a new ADR — make adr TITLE="Short decision title"
	@if [ -z "$(TITLE)" ]; then \
		echo "Usage: make adr TITLE=\"Short decision title\""; exit 2; \
	fi
	@next=$$(printf '%04d' $$(( $$(ls $(ADR_DIR) | grep -cE '^[0-9]{4}-') ))); \
	slug=$$(echo "$(TITLE)" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9]\+/-/g' -e 's/^-//' -e 's/-$$//'); \
	target="$(ADR_DIR)/$$next-$$slug.md"; \
	if [ -e "$$target" ]; then echo "!!! $$target already exists."; exit 1; fi; \
	sed -e "s/^# ADR NNNN: .*/# ADR $$next: $(TITLE)/" \
	    -e "s/^Proposed | Accepted.*/Proposed/" \
	    $(ADR_DIR)/0000-adr-template.md > "$$target"; \
	echo "==> Created $$target"; \
	echo "==> Remember to register it in $(ADR_DIR)/README.md"
