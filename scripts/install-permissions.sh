#!/bin/bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

# Public installed Python code must be readable by users and by nobody, which
# runs TTP's verification probe. Never apply this to runtime state or logs.
ttp_install_permissions() {
    local install_dir="$1"
    chmod 0755 "$install_dir" || return
    # GNU chmod does not follow symlinks encountered during recursive traversal:
    # the venv's Python symlink must not change the system interpreter's mode.
    chmod -R u+rwX,go+rX,go-w "$install_dir/venv"
}
