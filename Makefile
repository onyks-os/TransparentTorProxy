# ==============================================================================
# TTP (Transparent Tor Proxy) - Local CI/CD Pipeline
# ==============================================================================
# This Makefile automates the testing process for TTP. 
# It allows developers to quickly run unit tests and isolated integration tests
# in Docker containers before committing code.
#
# Usage:
#   make test             - Runs only the fast unit tests locally.
#   make integration-all  - Runs full system tests inside Docker (Debian, Fedora, Arch).
#   make verify           - Runs EVERYTHING (Unit tests + All integration tests).
# ==============================================================================

# .PHONY tells Make that these are command names, not actual files or directories.
.PHONY: test integration-debian integration-fedora integration-arch integration-all verify build clean testpypi pypi

# ------------------------------------------------------------------------------
# 1. LOCAL UNIT TESTS
# ------------------------------------------------------------------------------
# Runs standard Python tests using pytest. This checks the basic logic
# of the code without needing a real Tor connection or root privileges.
test:
	@echo "==> Running local Unit Tests..."
	pytest tests/ -v

# ------------------------------------------------------------------------------
# 2. INTEGRATION TESTS (DOCKER)
# ------------------------------------------------------------------------------
# These tests run the actual TTP software inside a privileged Docker container.
# They verify that TTP correctly interacts with systemd, nftables, and Tor.
#
# NOTE: Integration tests sometimes fail due to temporary network timeouts 
# (e.g., Tor bootstrap delays). To prevent false negatives, if a test fails, 
# it will automatically wait 5 seconds and retry exactly once.

integration-debian:
	@echo "==> Starting integration tests on Debian..."
	./scripts/vm/run_integration_tests.sh debian || (sleep 5 && ./scripts/vm/run_integration_tests.sh debian)

integration-fedora:
	@echo "==> Starting integration tests on Fedora..."
	./scripts/vm/run_integration_tests.sh fedora || (sleep 5 && ./scripts/vm/run_integration_tests.sh fedora)

integration-arch:
	@echo "==> Starting integration tests on Arch Linux..."
	./scripts/vm/run_integration_tests.sh arch || (sleep 5 && ./scripts/vm/run_integration_tests.sh arch)

# A convenience command to run all three integration tests in sequence.
integration-all: integration-debian integration-fedora integration-arch

# ------------------------------------------------------------------------------
# 3. FULL VERIFICATION PIPELINE
# ------------------------------------------------------------------------------
# The ultimate command to run before a git commit. 
# It runs local unit tests first. If they pass, it moves on to Docker tests.
verify:
	@chmod +x scripts/verify.sh
	@./scripts/verify.sh $(ARGS)

# ------------------------------------------------------------------------------
# 4. PACKAGE BUILDING & PUBLISHING
# ------------------------------------------------------------------------------
# Builds the final .deb and .rpm packages using the packaging scripts.
build:
	@echo "==> Building Debian and RPM packages..."
	@./packaging/release.sh

# Builds the Python wheel/sdist and uploads to TestPyPI
testpypi: clean
	@echo "==> Building and publishing to TestPyPI..."
	python3 -m build
	python3 -m twine upload --repository testpypi dist/*

# Builds the Python wheel/sdist and uploads to official PyPI
pypi: clean
	@echo "==> Building and publishing to PyPI..."
	python3 -m build
	python3 -m twine upload dist/*

# ------------------------------------------------------------------------------
# 5. CLEANUP
# ------------------------------------------------------------------------------
# Removes all generated artifacts, caches, and built packages.
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf dist/ build/ ttp.egg-info/ packaging/*.deb packaging/*.rpm packaging/SHA256SUMS.txt
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true