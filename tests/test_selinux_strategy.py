# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for SELinux "Install Once, Run Fast" strategy.

These tests verify OS family detection, SELinux state detection, and
the installation/removal logic for the custom policy module.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.conftest import stub_path
from ttp.paths import resolve
from ttp.tor_detect import (
    is_fedora_family,
    is_selinux_enforcing,
    is_selinux_module_installed,
)
from ttp.tor_install import (
    label_ports_selinux,
    remove_selinux_module,
    setup_selinux_if_needed,
    unlabel_ports_selinux,
)


def _stub_lookup(value):
    """
    Patch the trusted binary lookup in every module that performs one.

    These tests used to patch ``shutil.which`` on the shared ``shutil`` module,
    which happened to affect all callers at once. Each module now binds
    ``resolve_optional`` locally, so the equivalent is an explicit set.
    """
    from contextlib import ExitStack

    stack = ExitStack()
    for module in (
        "ttp.system_info",
        "ttp.selinux",
        "ttp.tor_detect",
        "ttp.tor_install",
        "ttp.tor_config",
    ):
        try:
            stack.enter_context(
                patch(
                    f"{module}.resolve_optional",
                    side_effect=((lambda binary: None) if value is None else (lambda binary: stub_path(binary))),
                )
            )
        except AttributeError:
            pass
    return stack


# -- OS Family Detection ----------------------------------------------


def test_is_fedora_family_true_fedora():
    """Returns True if /etc/os-release contains 'fedora'."""
    content = 'ID=fedora\nNAME="Fedora Linux"'
    with patch.object(Path, "exists", return_value=True), patch.object(Path, "read_text", return_value=content):
        assert is_fedora_family() is True


def test_is_fedora_family_true_rhel():
    """Returns True if /etc/os-release contains 'rhel'."""
    content = 'ID="rhel"\nID_LIKE="fedora"'
    with patch.object(Path, "exists", return_value=True), patch.object(Path, "read_text", return_value=content):
        assert is_fedora_family() is True


def test_is_fedora_family_false_debian():
    """Returns False if /etc/os-release contains 'debian'."""
    content = 'ID=debian\nNAME="Debian GNU/Linux"'
    with patch.object(Path, "exists", return_value=True), patch.object(Path, "read_text", return_value=content):
        assert is_fedora_family() is False


def test_is_fedora_family_fallback_to_redhat_release():
    """Returns True if /etc/os-release is missing but /etc/redhat-release exists."""
    with patch.object(Path, "exists") as mock_exists:
        # First call for /etc/os-release (False), second for /etc/redhat-release (True)
        mock_exists.side_effect = [False, True]
        assert is_fedora_family() is True


# -- SELinux State Detection ------------------------------------------


def test_is_selinux_enforcing_true():
    """Returns True if getenforce output is 'Enforcing'."""
    with _stub_lookup("/usr/bin/getenforce"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Enforcing\n", returncode=0)
            assert is_selinux_enforcing() is True


def test_is_selinux_enforcing_false():
    """Returns False if getenforce output is 'Permissive'."""
    with _stub_lookup("/usr/bin/getenforce"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Permissive\n", returncode=0)
            assert is_selinux_enforcing() is False


def test_is_selinux_enforcing_no_command():
    """Returns False if getenforce is not installed."""
    with _stub_lookup(None):
        assert is_selinux_enforcing() is False


# -- SELinux Module Management ----------------------------------------


def test_is_selinux_module_installed_true():
    """Returns True if semodule -l lists the policy."""
    with _stub_lookup("/usr/bin/semodule"):
        with patch("ttp.tor_detect.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="ttp_tor_policy  1.1\nother_mod\n", returncode=0)
            assert is_selinux_module_installed() is True


def test_is_selinux_module_installed_false():
    """Returns False if semodule -l does not list the policy."""
    with _stub_lookup("/usr/bin/semodule"):
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
        _stub_lookup("/usr/bin/cmd"),
        patch("ttp.selinux.tempfile.TemporaryDirectory") as mock_tempdir,
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        mock_tempdir.return_value.__enter__.return_value = "/tmp/fake"
        setup_selinux_if_needed()

        # Verify 3 subprocess calls were made: checkmodule, semodule_package, semodule -i
        assert mock_run.call_count == 3
        args1, _ = mock_run.call_args_list[0]
        assert args1[0][0] == resolve("checkmodule")
        args2, _ = mock_run.call_args_list[1]
        assert args2[0][0] == resolve("semodule_package")
        args3, _ = mock_run.call_args_list[2]
        assert args3[0][0] == resolve("semodule")
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
    """Calls semodule -r if the module is installed.

    Both the binary lookup and subprocess must be patched on ttp.selinux, the
    module that actually calls them. Patching Path.exists here used to work only
    because the production code hardcoded /usr/sbin/semodule.
    """
    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        _stub_lookup("/usr/sbin/semodule"),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        remove_selinux_module()
        mock_run.assert_any_call([resolve("semodule"), "-r", "ttp_tor_policy"], check=True)


# ---------------------------------------------------------------------------
# Dynamic port labelling
# ---------------------------------------------------------------------------
#
# `label_ports_selinux` had no test at all, and it is not cosmetic: on an
# enforcing host, Tor cannot bind a TransPort or DNSPort that is not labelled
# `tor_port_t`. If this function silently does nothing, `ttp start` applies the
# full ruleset - redirecting all traffic at a port Tor could never open - and
# then fails verification. That is the fail-closed-but-broken state exit code 3
# exists to report, reached from a policy detail rather than a network fault.
#
# Everything here therefore has to degrade rather than raise: `start` calls it
# through `start_tor_service`, where an exception would abort the session before
# any rule is applied, leaving the host in cleartext.


def test_label_ports_is_a_no_op_without_semanage():
    """No semanage means no SELinux port management, and no crash either.

    Debian has no `semanage` and does not need one. The function has to be a
    silent no-op there, not an error, because the same code path runs on every
    distribution.
    """
    with (
        patch("ttp.selinux.resolve_optional", return_value=None),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        label_ports_selinux(9041, 9054)

    assert mock_run.call_count == 0


def test_label_ports_labels_both_the_transport_and_dns_ports():
    """The TCP TransPort and the UDP DNSPort are two separate labels.

    Getting the protocol wrong is the interesting failure: `-p tcp` on the
    DNSPort would leave UDP/9054 unlabelled, so DNS redirection would land on a
    port Tor cannot bind while TCP traffic worked - a DNS-only leak path that
    looks like a working session.
    """
    with (
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semanage"),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        label_ports_selinux(9041, 9054)

    assert mock_run.call_count == 2
    assert mock_run.call_args_list[0].args[0] == [
        "/usr/sbin/semanage",
        "port",
        "-a",
        "-t",
        "tor_port_t",
        "-p",
        "tcp",
        "9041",
    ]
    assert mock_run.call_args_list[1].args[0] == [
        "/usr/sbin/semanage",
        "port",
        "-a",
        "-t",
        "tor_port_t",
        "-p",
        "udp",
        "9054",
    ]


def test_label_ports_modifies_a_label_that_already_exists():
    """`semanage port -a` fails when the mapping is already there; `-m` is the fix.

    This is the common case, not an edge one: the label survives a reboot, so
    the second `ttp start` on the same ports always takes this path. Without the
    fallback, every session after the first would run with the `-a` failure
    swallowed and the label left owned by whatever set it last.
    """
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "-a" in args:
            raise subprocess.CalledProcessError(1, "semanage", stderr=b"port already defined")
        return MagicMock(returncode=0)

    with (
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semanage"),
        patch("ttp.selinux.subprocess.run", side_effect=run),
    ):
        label_ports_selinux(9041, 9054)

    # Four calls: -a then -m, for each of the two ports.
    assert len(calls) == 4
    assert calls[1] == ["/usr/sbin/semanage", "port", "-m", "-t", "tor_port_t", "-p", "tcp", "9041"]
    assert calls[3] == ["/usr/sbin/semanage", "port", "-m", "-t", "tor_port_t", "-p", "udp", "9054"]


def test_label_ports_still_attempts_the_second_port_after_the_first_fails(caplog):
    """One unlabellable port must not cost the other its label.

    The `try` is inside the loop, which is what makes this true. If it wrapped
    the loop instead, a TransPort that could not be labelled would silently
    skip the DNSPort - and DNS is the leak path that matters most, since a
    failed TCP redirect is visible immediately while a failed DNS one is not.
    """
    with (
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semanage"),
        patch(
            "ttp.selinux.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "semanage", stderr=b"permission denied"),
        ) as mock_run,
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        label_ports_selinux(9041, 9054)

    # -a and -m attempted for both ports, and both failures reported.
    assert mock_run.call_count == 4
    assert "Failed to label port 9041/tcp" in caplog.text
    assert "Failed to label port 9054/udp" in caplog.text


def test_unlabel_ports_is_a_no_op_without_semanage():
    """Teardown on a host with no semanage must not raise.

    `do_stop` calls this between stopping Tor and destroying the rules. An
    exception here would abort the teardown with the ruleset still loaded.
    """
    with (
        patch("ttp.selinux.resolve_optional", return_value=None),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        unlabel_ports_selinux(9041, 9054)

    assert mock_run.call_count == 0


def test_unlabel_ports_removes_both_labels():
    with (
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semanage"),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        unlabel_ports_selinux(9041, 9054)

    assert mock_run.call_count == 2
    assert mock_run.call_args_list[0].args[0] == ["/usr/sbin/semanage", "port", "-d", "-p", "tcp", "9041"]
    assert mock_run.call_args_list[1].args[0] == ["/usr/sbin/semanage", "port", "-d", "-p", "udp", "9054"]


def test_unlabel_ports_swallows_a_failed_removal_and_continues():
    """A label that was never added is the expected case, not an error.

    `do_stop` runs this unconditionally, including after a `start` that failed
    before `label_ports_selinux` ran. `semanage port -d` on a mapping that does
    not exist exits non-zero, and that has to stay silent - but the second port
    must still be attempted, which is why the `try` is inside the loop here too.
    """
    with (
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semanage"),
        patch(
            "ttp.selinux.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "semanage", stderr=b"not defined"),
        ) as mock_run,
    ):
        unlabel_ports_selinux(9041, 9054)  # must not raise

    assert mock_run.call_count == 2


# ---------------------------------------------------------------------------
# Policy module install and removal: every failure degrades
# ---------------------------------------------------------------------------


def test_setup_selinux_skips_when_the_policy_source_is_missing(caplog):
    """A packaging fault must be reported, not crash `ttp start`.

    The `.te` file ships inside the wheel, so its absence means a broken
    install. Tor will then fail to bind its ports on an enforcing host, and the
    warning here is the only thing connecting that to the real cause.
    """
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=False),
        patch.object(Path, "exists", return_value=False),
        patch("ttp.selinux.subprocess.run") as mock_run,
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        setup_selinux_if_needed()

    assert mock_run.call_count == 0
    assert "SELinux policy source missing" in caplog.text


def test_setup_selinux_skips_when_the_policy_toolchain_is_absent(caplog):
    """checkpolicy/policycoreutils missing is a supported configuration.

    An enforcing host without the compiler is not TTP's problem to solve, but
    it is TTP's job to say so and carry on rather than abort the session.
    """
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=False),
        patch.object(Path, "exists", return_value=True),
        patch("ttp.selinux.resolve_optional", return_value=None),
        patch("ttp.selinux.subprocess.run") as mock_run,
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        setup_selinux_if_needed()

    assert mock_run.call_count == 0
    assert "Cannot compile SELinux policy" in caplog.text


def test_setup_selinux_warns_but_does_not_raise_when_compilation_fails(caplog):
    """A failed compile leaves Tor unable to bind, and must say so without raising.

    This runs inside `setup_managed_tor`, before any firewall rule exists.
    Raising would abort `start` on the one path that leaves the host in plain
    cleartext - trading a session that might still work for a definite
    non-session, over a policy module.
    """
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=False),
        patch.object(Path, "exists", return_value=True),
        _stub_lookup("/usr/bin/cmd"),
        patch(
            "ttp.selinux.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "checkmodule", stderr=b"syntax error"),
        ),
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        setup_selinux_if_needed()  # must not raise

    assert "SELinux policy installation failed" in caplog.text


def test_remove_selinux_module_is_a_no_op_without_semodule():
    """Uninstall on a non-SELinux host must not look for a module to remove."""
    with (
        patch("ttp.selinux.resolve_optional", return_value=None),
        patch("ttp.tor_detect.is_selinux_module_installed") as mock_installed,
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        remove_selinux_module()

    assert mock_run.call_count == 0
    # The cheap check comes first: no semodule, so never ask whether it is loaded.
    assert mock_installed.call_count == 0


def test_remove_selinux_module_warns_but_does_not_raise_on_failure(caplog):
    """`ttp uninstall` must finish removing everything else.

    A leftover policy module is inert - it labels ports Tor is no longer using.
    An exception here would stop the uninstall partway through, which leaves
    things that are not inert.
    """
    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.selinux.resolve_optional", return_value="/usr/sbin/semodule"),
        patch(
            "ttp.selinux.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "semodule", stderr=b"module not found"),
        ),
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        remove_selinux_module()  # must not raise

    assert "Failed to remove SELinux policy module" in caplog.text
