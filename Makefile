# TransparentTorProxy (TTP) — developer entrypoint.
#
# Every target is documented inline; run `make help` for the full list.
# Logic lives in the modular fragments under make/ so that this file stays readable:
#
#   make/common.mk   — environment, help, housekeeping, TODO tracking
#   make/quality.mk  — lint, format, audit, security gates
#   make/docs.mk     — MkDocs site and ADR scaffolding
#   make/release.mk  — versioning, build, SBOM, checksums, signing
#   make/python.mk   — language-specific implementation of the target contract
#   make/project.mk  — TTP-specific targets (Docker integration, leak suite, packages)
#   make/local.mk    — optional, git-ignored, machine-local overrides

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Project identity — the single source of truth for scripts and workflows.
# ---------------------------------------------------------------------------
PROJECT_NAME  := TransparentTorProxy
PROJECT_SHORT := TTP
PROJECT_SLUG  := TransparentTorProxy
PROJECT_PKG   := ttp
PROJECT_DIST  := transparent-tor-proxy
GITHUB_OWNER  := onyks-os
VERSION       := 0.4.8

# Directories that hold first-party source, tests, and shell scripts.
SRC_DIRS     := ttp
TEST_DIRS    := tests
SCRIPT_DIRS  := scripts packaging

# This repository predates the template's .venv convention.
VENV         := venv

include make/common.mk
include make/quality.mk
include make/docs.mk
include make/release.mk
include make/python.mk
include make/project.mk
-include make/local.mk
