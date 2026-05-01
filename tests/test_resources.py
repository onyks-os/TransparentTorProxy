"""Tests for internal resource management.

These tests verify that embedded files (like SELinux policies) are
correctly accessible via importlib.resources.
"""

import importlib.resources
from pathlib import Path

def test_selinux_policy_resource_exists():
    """Verify that the SELinux policy .te file is accessible."""
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath(
        "ttp_tor_policy.te"
    )
    assert traversable.exists()
    assert traversable.is_file()
    
    # Verify we can read content
    content = traversable.read_text(encoding="utf-8")
    assert "module ttp_tor_policy" in content
    assert "require {" in content

def test_selinux_resource_as_file():
    """Verify that as_file context manager works (needed for subprocesses)."""
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath(
        "ttp_tor_policy.te"
    )
    with importlib.resources.as_file(traversable) as te_path:
        assert isinstance(te_path, Path)
        assert te_path.exists()
        assert te_path.suffix == ".te"
