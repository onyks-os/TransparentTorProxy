# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Package - Isolation via dedicated nftables tables."""

import pwd as pwd
import subprocess as subprocess

from ttp.firewall.builder import (
    _build_ruleset as _build_ruleset,
)
from ttp.firewall.builder import (
    _has_cgroup_bypass_support as _has_cgroup_bypass_support,
)
from ttp.firewall.emergency import (
    apply_active_socket_slaughter as apply_active_socket_slaughter,
)
from ttp.firewall.emergency import (
    apply_emergency_killswitch as apply_emergency_killswitch,
)
from ttp.firewall.emergency import (
    apply_teardown_lockdown as apply_teardown_lockdown,
)
from ttp.firewall.runner import (
    RULES_TEMP_PATH as RULES_TEMP_PATH,
)
from ttp.firewall.runner import (
    _run_nft as _run_nft,
)
from ttp.firewall.runner import (
    _run_nft_string as _run_nft_string,
)
from ttp.firewall.runner import (
    apply_rules as apply_rules,
)
from ttp.firewall.runner import (
    destroy_rules as destroy_rules,
)
from ttp.state import LOCK_DIR as LOCK_DIR

__all__ = [
    "LOCK_DIR",
    "RULES_TEMP_PATH",
    "_build_ruleset",
    "_has_cgroup_bypass_support",
    "_run_nft",
    "_run_nft_string",
    "apply_active_socket_slaughter",
    "apply_emergency_killswitch",
    "apply_rules",
    "apply_teardown_lockdown",
    "destroy_rules",
    "pwd",
    "subprocess",
]
