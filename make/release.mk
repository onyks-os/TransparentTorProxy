# ---------------------------------------------------------------------------
# release.mk — version handling, artifact build, SBOM, checksums, signing.
#
# The release itself is performed by .github/workflows/release.yml when a
# v* tag is pushed; these targets exist to rehearse and verify it locally.
# ---------------------------------------------------------------------------

.PHONY: build sbom checksums sign release-check release-dry

DIST_DIR ?= dist

##@ Release

build: lang-build ## Build the distributable artifacts into dist/

sbom: ## Generate a CycloneDX SBOM for the built artifacts
	@echo "==> [$(PROJECT_SHORT)] Generating SBOM..."
	@if command -v cdxgen >/dev/null 2>&1; then \
		cdxgen -o $(DIST_DIR)/sbom.json; \
	else \
		echo "==> cdxgen not found. Install: npm install -g @cyclonedx/cdxgen"; \
		exit 1; \
	fi

checksums: ## Generate SHA256SUMS for everything in dist/
	@echo "==> [$(PROJECT_SHORT)] Generating checksums..."
	@cd $(DIST_DIR) && sha256sum -- * > SHA256SUMS && cat SHA256SUMS

sign: checksums ## Clearsign SHA256SUMS with GPG (CI uses Sigstore instead)
	@echo "==> [$(PROJECT_SHORT)] Signing SHA256SUMS (key: $(or $(GPG_KEY_ID),default))..."
	@gpg --clearsign $(if $(GPG_KEY_ID),--local-user $(GPG_KEY_ID),) \
		--output $(DIST_DIR)/SHA256SUMS.asc $(DIST_DIR)/SHA256SUMS

release-check: ## Verify the repository is ready to be tagged
	@echo "==> [$(PROJECT_SHORT)] Pre-release checks..."
	@test -z "$$(git status --porcelain)" \
		|| { echo "!!! Working tree is dirty."; exit 1; }
	@grep -q "## \[$(VERSION)\]" CHANGELOG.md \
		|| { echo "!!! CHANGELOG.md has no section for $(VERSION)."; exit 1; }
	@! grep -rIq "TODO(template)" README.md SECURITY.md \
		|| { echo "!!! README.md or SECURITY.md still contains template placeholders."; exit 1; }
	@echo "==> Ready to tag: git tag -s v$(VERSION) -m \"$(PROJECT_SHORT) v$(VERSION)\""

release-dry: release-check verify build sbom checksums ## Full local release rehearsal
	@echo "======================================================================"
	@echo "[$(PROJECT_SHORT)] Release rehearsal complete. Artifacts in $(DIST_DIR)/:"
	@ls -la $(DIST_DIR)/
	@echo "======================================================================"
