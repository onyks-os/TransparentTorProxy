# ---------------------------------------------------------------------------
# release.mk — version handling, artifact build, SBOM, checksums, signing.
#
# The release itself is performed by .github/workflows/release.yml when a
# v* tag is pushed; these targets exist to rehearse and verify it locally.
# ---------------------------------------------------------------------------

.PHONY: build sbom checksums sign release-check release-dry release-notes

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

# The release body is the CHANGELOG section for the version being released,
# header included, matching how the notes for v0.4.5 and earlier were written.
# GitHub's auto-generated notes list merged pull requests instead, which on a
# repository whose work lands as direct commits produces a near-empty changelog
# plus a "New Contributors" line crediting the maintainer as a first-timer.
#
# The section is copied verbatim, blank lines included; only trailing blank lines
# and the horizontal rule that separates versions are trimmed.
release-notes: ## Print the CHANGELOG section for VERSION as GitHub release notes
	@awk -v ver="$(VERSION)" ' \
		index($$0, "## [" ver "]") == 1 { found = 1; print; next } \
		found && index($$0, "## [") == 1 { exit } \
		found { print } \
	' CHANGELOG.md \
	| awk '{ lines[NR] = $$0 } END { \
		last = NR; \
		while (last > 0 && (lines[last] ~ /^[[:space:]]*$$/ || lines[last] ~ /^---+$$/)) last--; \
		for (i = 1; i <= last; i++) print lines[i]; \
	}'

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
