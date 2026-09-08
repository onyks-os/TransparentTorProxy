# ---------------------------------------------------------------------------
# project.mk — targets that exist only in TTP.
#
# Everything here is either privileged, container-based, or specific to the
# native packaging pipeline, so it has no equivalent in the shared contract.
# Targets that extend a contract target do so by adding a prerequisite rather
# than redefining a recipe, which keeps `make` from overriding the fragment.
# ---------------------------------------------------------------------------

.PHONY: integration-debian integration-fedora integration-arch integration-all \
        chaos-monkey test-leak-ip test-leak-dns test-leak-webrtc check-leak \
        test-nse packages clean-packages verify-full tarball testpypi pypi

##@ Integration (Docker, privileged)

# Tor bootstrap is occasionally flaky in a cold container, so each suite is
# retried once before it is reported as a failure.
integration-debian: ## Run the integration suite on Debian
	@echo "==> [$(PROJECT_SHORT)] Integration tests on Debian..."
	@./scripts/vm/run_integration_tests.sh debian || (sleep 5 && ./scripts/vm/run_integration_tests.sh debian)

integration-fedora: ## Run the integration suite on Fedora
	@echo "==> [$(PROJECT_SHORT)] Integration tests on Fedora..."
	@./scripts/vm/run_integration_tests.sh fedora || (sleep 5 && ./scripts/vm/run_integration_tests.sh fedora)

integration-arch: ## Run the integration suite on Arch Linux
	@echo "==> [$(PROJECT_SHORT)] Integration tests on Arch Linux..."
	@./scripts/vm/run_integration_tests.sh arch || (sleep 5 && ./scripts/vm/run_integration_tests.sh arch)

integration-all: integration-debian integration-fedora integration-arch ## All three distributions in sequence

chaos-monkey: ## Watchdog chaos-monkey stress test (60s, requires root)
	@echo "==> [$(PROJECT_SHORT)] Watchdog chaos monkey..."
	sudo -E $(VENV)/bin/python3 tests/chaos_monkey.py --duration 60

##@ Leak verification (run from an unproxied host, REAL_PUBLIC_IP set)

test-leak-ip: ## Offensive IP leak test
	@$(PYTHON) -m pytest tests/leak/test_ip_leak.py -v -s

test-leak-dns: ## Offensive DNS leak test
	@$(PYTHON) -m pytest tests/leak/test_dns_leak.py -v -s

test-leak-webrtc: ## Offensive WebRTC STUN leak test
	@$(PYTHON) -m pytest tests/leak/test_webrtc_leak.py -v -s

check-leak: test-leak-ip test-leak-dns test-leak-webrtc ## The full leak suite

##@ Zero-leak ruleset verification (NSE)

# The suite behind the README's strongest claim. It was written months ago and
# then run by nothing: no make target, no CI job, no step in verify.sh, and the
# `nse` marker is excluded from the default pytest run. This target is what
# turns that assertion into a measurement.
#
# TTP_REQUIRE_NSE=1 makes a missing, shadowed, or too-old NSE a hard error
# instead of a skip. A gate that skips itself is not a gate - and `nse` is a
# short import name that an unrelated PyPI package can shadow, which would look
# exactly like "NSE is not installed".
test-nse: ## Zero-leak nftables verification in a netns (requires root + the nse extra)
	@echo "==> [$(PROJECT_SHORT)] Zero-leak ruleset verification (NSE)..."
	@echo "    kernel:   $$(uname -r)"
	@echo "    nftables: $$(nft --version 2>/dev/null || echo 'MISSING')"
	@# Scapy compiles the sniffer's BPF filter through libpcap. Without it every
	@# test in the suite fails at sniffer construction - correctly, but with a
	@# message about Scapy rather than about the missing library.
	@if ! ldconfig -p 2>/dev/null | grep -q libpcap; then \
		echo "    !!! libpcap not found. Install libpcap-dev (Debian) or"; \
		echo "        libpcap-devel (Fedora) - Scapy needs the unversioned .so - or the"; \
		echo "        sniffer cannot compile its BPF filter and every test fails."; \
	fi
	@sudo -E TTP_REQUIRE_NSE=1 $(VENV)/bin/python -m pytest tests/test_nse_rules.py -m nse -v

##@ Native packaging

packages: ## Build .deb and .rpm into packaging/ (was `make build` before the template migration)
	@echo "==> [$(PROJECT_SHORT)] Building Debian, RPM, and Python release artifacts..."
	@./packaging/release.sh

tarball: ## Build the source tarball only
	@echo "==> [$(PROJECT_SHORT)] Building sdist..."
	@$(PYTHON) -m build --sdist --outdir $(DIST_DIR)

# `make clean` must also remove the native packages, which the shared fragment
# knows nothing about.
clean: clean-packages

clean-packages:
	@rm -rf .build_tmp/ packaging/*.deb packaging/*.rpm packaging/*.tar.gz \
		packaging/*.whl packaging/SHA256SUMS.txt packaging/SHA256SUMS.txt.asc

##@ Release rehearsal

verify-full: ## The 8-minute pre-release suite (lint + unit + integration + packages)
	@chmod +x scripts/verify.sh
	@./scripts/verify.sh $(ARGS)

# Names kept from the pre-template Makefile so muscle memory still works.
testpypi: publish-test ## Alias for publish-test
pypi: publish ## Alias for publish
