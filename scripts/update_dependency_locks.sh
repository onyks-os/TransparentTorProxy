#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Maintainer-only regeneration; review the diff and run CI before merging.
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile requirements/tools.in --python-version 3.10 --universal --generate-hashes --upgrade -o requirements/tools.txt
uv pip compile pyproject.toml requirements/tools.in --python-version 3.10 --universal --generate-hashes --upgrade -o requirements/runtime.txt
uv pip compile pyproject.toml requirements/tools.in requirements/ci-tools.in --extra dev --extra nse --python-version 3.10 --universal --generate-hashes --upgrade -o requirements/ci.txt
uv pip compile requirements/oldest.in requirements/tools.in --python-version 3.10 --universal --generate-hashes --upgrade -o requirements/oldest.txt
uv pip compile requirements/docs.in --python-version 3.10 --universal --generate-hashes --upgrade -o requirements/docs.txt
