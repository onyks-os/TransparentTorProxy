# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Package - Isolation via dedicated nftables tables."""

import pwd as pwd
import subprocess as subprocess
from ttp.state import LOCK_DIR as LOCK_DIR

from ttp.firewall.builder import (
    _build_ruleset as _build_ruleset,
    _has_cgroup_bypass_support as _has_cgroup_bypass_support,
)
from ttp.firewall.runner import (
    RULES_TEMP_PATH as RULES_TEMP_PATH,
    _run_nft as _run_nft,
    _run_nft_string as _run_nft_string,
    apply_rules as apply_rules,
    destroy_rules as destroy_rules,
)
from ttp.firewall.emergency import (
    apply_active_socket_slaughter as apply_active_socket_slaughter,
    apply_emergency_killswitch as apply_emergency_killswitch,
    apply_teardown_lockdown as apply_teardown_lockdown,
)

__all__ = [
    "apply_rules",
    "destroy_rules",
    "apply_teardown_lockdown",
    "apply_active_socket_slaughter",
    "apply_emergency_killswitch",
    "RULES_TEMP_PATH",
    "LOCK_DIR",
    "_build_ruleset",
    "_has_cgroup_bypass_support",
    "_run_nft",
    "_run_nft_string",
    "subprocess",
    "pwd",
]
