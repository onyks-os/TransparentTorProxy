# TTP local CI/CD: unit tests, Docker integration, native packages.
#
# Usage:
#   make test             - unit tests only
#   make fuzz             - property-based fuzz tests (Hypothesis)
#   make audit            - dependency vulnerability scan
#   make integration-all  - Docker tests (Debian, Fedora, Arch)
#   make verify           - lint + unit + fuzz + audit + integration + package build

# .PHONY tells Make that these are command names, not actual files or directories.
.PHONY: test fuzz audit integration-debian integration-fedora integration-arch integration-all verify build clean testpypi pypi test-leak-ip test-leak-dns test-leak-webrtc check-leak tarball

# 1. Local unit tests (pytest, no root).
test:
	@echo "==> Running local Unit Tests..."
	pytest tests/ -v

# 1b. Property-based fuzz testing (Hypothesis, no root).
fuzz:
	@echo "==> Running Hypothesis Fuzz Tests..."
	pytest fuzzing/fuzz_target.py -v

# 1c. Dependency vulnerability scan (pip-audit).
audit:
	@echo "==> Running Dependency Audit (pip-audit)..."
	pip-audit .

# 2. Integration tests (privileged Docker; retries once on failure for flaky Tor bootstrap).

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

# 3. Full verify: scripts/verify.sh (lint, unit, integration, package build).
verify:
	@chmod +x scripts/verify.sh
	@./scripts/verify.sh $(ARGS)

# 4. Native packages (.deb / .rpm) and Python release artifacts (Source Tarball & Wheel) via packaging/release.sh
build:
	@echo "==> Building Debian, RPM packages, and Python release artifacts..."
	@./packaging/release.sh

tarball:
	@echo "==> Generating Source Tarball (sdist)..."
	python3 -m build --sdist

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

# 5. Clean build artifacts and release outputs.
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf dist/ build/ .build_tmp/ ttp.egg-info/ packaging/*.deb packaging/*.rpm packaging/*.tar.gz packaging/*.whl packaging/SHA256SUMS.txt packaging/SHA256SUMS.txt.asc
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# 6. Offensive Leak Testing Suite (must run inside unproxied target environment, with REAL_PUBLIC_IP set)
test-leak-ip:
	@echo "==> Running Offensive IP Leak Test..."
	pytest tests/leak/test_ip_leak.py -v -s

test-leak-dns:
	@echo "==> Running Offensive DNS Leak Test..."
	pytest tests/leak/test_dns_leak.py -v -s

test-leak-webrtc:
	@echo "==> Running Offensive WebRTC STUN Leak Test..."
	pytest tests/leak/test_webrtc_leak.py -v -s

check-leak: test-leak-ip test-leak-dns test-leak-webrtc