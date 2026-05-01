"""Tests for SELinux "Install Once, Run Fast" strategy.

These tests verify OS family detection, SELinux state detection, and
the installation/removal logic for the custom policy module.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from ttp.tor_detect import (
    is_fedora_family,
    is_selinux_enforcing,
    is_selinux_module_installed,
)
from ttp.tor_install import (
    setup_selinux_if_needed,
    remove_selinux_module,
)


# ── OS Family Detection ──────────────────────────────────────────────


def test_is_fedora_family_true_fedora():
    """Returns True if /etc/os-release contains 'fedora'."""
    content = 'ID=fedora\nNAME="Fedora Linux"'
    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "read_text", return_value=content):
            assert is_fedora_family() is True


def test_is_fedora_family_true_rhel():
    """Returns True if /etc/os-release contains 'rhel'."""
    content = 'ID="rhel"\nID_LIKE="fedora"'
    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "read_text", return_value=content):
            assert is_fedora_family() is True


def test_is_fedora_family_false_debian():
    """Returns False if /etc/os-release contains 'debian'."""
    content = 'ID=debian\nNAME="Debian GNU/Linux"'
    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "read_text", return_value=content):
            assert is_fedora_family() is False


def test_is_fedora_family_fallback_to_redhat_release():
    """Returns True if /etc/os-release is missing but /etc/redhat-release exists."""
    with patch.object(Path, "exists") as mock_exists:
        # First call for /etc/os-release (False), second for /etc/redhat-release (True)
        mock_exists.side_effect = [False, True]
        assert is_fedora_family() is True


# ── SELinux State Detection ──────────────────────────────────────────


def test_is_selinux_enforcing_true():
    """Returns True if getenforce output is 'Enforcing'."""
    with patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/getenforce"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Enforcing\n", returncode=0)
            assert is_selinux_enforcing() is True


def test_is_selinux_enforcing_false():
    """Returns False if getenforce output is 'Permissive'."""
    with patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/getenforce"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Permissive\n", returncode=0)
            assert is_selinux_enforcing() is False


def test_is_selinux_enforcing_no_command():
    """Returns False if getenforce is not installed."""
    with patch("ttp.tor_detect.shutil.which", return_value=None):
        assert is_selinux_enforcing() is False


# ── SELinux Module Management ────────────────────────────────────────


def test_is_selinux_module_installed_true():
    """Returns True if semodule -l lists the policy."""
    with patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/semodule"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="ttp_tor_policy\nother_mod\n", returncode=0
            )
            assert is_selinux_module_installed() is True


def test_is_selinux_module_installed_false():
    """Returns False if semodule -l does not list the policy."""
    with patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/semodule"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="other_mod\n", returncode=0)
            assert is_selinux_module_installed() is False


def test_setup_selinux_if_needed_skips_on_debian():
    """Does nothing if not on Fedora family."""
    with patch("ttp.tor_detect.is_fedora_family", return_value=False):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            setup_selinux_if_needed()
            mock_run.assert_not_called()


def test_setup_selinux_if_needed_installs_when_missing():
    """Calls checkmodule, semodule_package, and semodule -i if on Fedora/Enforcing and module is missing."""
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=False),
        patch.object(Path, "exists", return_value=True),
        patch("ttp.tor_install._install_selinux_tools"),
        patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/cmd"),
        patch("ttp.tor_install.tempfile.TemporaryDirectory") as mock_tempdir,
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        mock_tempdir.return_value.__enter__.return_value = "/tmp/fake"
        setup_selinux_if_needed()

        # Verify 3 subprocess calls were made: checkmodule, semodule_package, semodule -i
        assert mock_run.call_count == 3
        args1, _ = mock_run.call_args_list[0]
        assert args1[0][0] == "checkmodule"
        args2, _ = mock_run.call_args_list[1]
        assert args2[0][0] == "semodule_package"
        args3, _ = mock_run.call_args_list[2]
        assert args3[0][0] == "semodule"
        assert args3[0][1] == "-i"


def test_setup_selinux_if_needed_skips_when_present():
    """Does nothing if module is already installed."""
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        setup_selinux_if_needed()
        mock_run.assert_not_called()


def test_remove_selinux_module_calls_semodule_r():
    """Calls semodule -r if the module is installed."""
    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch.object(Path, "exists", return_value=True),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        remove_selinux_module()
        mock_run.assert_any_call(
            ["semodule", "-r", "ttp_tor_policy"], check=True
        )
