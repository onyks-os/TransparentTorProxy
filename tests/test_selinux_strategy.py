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
            mock_run.return_value = MagicMock(stdout="ttp_tor_policy  1.2\nother_mod\n", returncode=0)
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


def test_setup_selinux_if_needed_skips_when_the_policy_is_current():
    """Nothing to do when the loaded policy is the revision this build ships."""
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.selinux.is_policy_module_current", return_value=True),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        setup_selinux_if_needed()
        mock_run.assert_not_called()


def test_setup_selinux_if_needed_reinstalls_when_the_loaded_policy_is_stale():
    """Presence alone is not enough: an older module must be upgraded.

    This is the case issue #50 left unreachable. The gate asked `semodule -l`
    for a version it no longer prints, so it answered "not installed" for every
    host - right outcome, wrong reason, and it meant a recompile on every
    single start rather than only on an upgrade.
    """
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.selinux.recorded_policy_version", return_value="1.1"),
        patch.object(Path, "exists", return_value=True),
        _stub_lookup("/usr/bin/cmd"),
        patch("ttp.selinux.tempfile.TemporaryDirectory") as mock_tempdir,
        patch("ttp.selinux.record_policy_version"),
        patch("ttp.selinux.subprocess.run") as mock_run,
    ):
        mock_tempdir.return_value.__enter__.return_value = "/tmp/fake"
        setup_selinux_if_needed()

    assert mock_run.call_count == 3


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


# ---------------------------------------------------------------------------
# Which policy is installed, and is it the one we ship
# ---------------------------------------------------------------------------
#
# See issue #50. The module's identity used to be checked with
# `re.search(r"ttp_tor_policy\s+1\.2\b", semodule_l_output)`, but modern
# policycoreutils dropped the version column from `semodule -l` years ago: on
# Fedora 44 the command prints the bare name. The regex therefore never
# matched, and three consequences followed from the same line:
#
#   * `setup_selinux_if_needed` recompiled and reinstalled the module on every
#     single `ttp start`;
#   * `remove_selinux_module` returned early every time, so `ttp uninstall`
#     never removed the policy it had installed;
#   * `ttp diagnose` reported `selinux_module: false` on hosts carrying it.
#
# Presence and currency are two different questions, and `semodule` can only
# answer the first. TTP records the version it installed in its own persistent
# state and compares that against the version declared in the shipped policy
# source.

#: Captured from `semodule -l` on Fedora 44 (policycoreutils-3.11-2.fc44),
#: abridged. No version column - that is the whole point of this fixture.
REAL_SEMODULE_L = "sudo\nsystemd\nthumb\ntor\nttp_tor_policy\nudev\nunconfined\n"


def test_module_presence_is_detected_in_output_that_carries_no_version():
    """The bare name is what `semodule -l` prints on a current system."""
    with _stub_lookup("/usr/sbin/semodule"):
        with patch("ttp.system_info.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=REAL_SEMODULE_L, returncode=0)
            assert is_selinux_module_installed() is True


def test_module_presence_is_detected_in_list_modules_full_output():
    """`semodule --list-modules=full` prints `priority name language`."""
    with _stub_lookup("/usr/sbin/semodule"):
        with patch("ttp.system_info.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="400 tor pp\n400 ttp_tor_policy pp\n", returncode=0)
            assert is_selinux_module_installed() is True


def test_a_module_whose_name_merely_contains_ours_is_not_ours():
    """Substring matching would make an unrelated module read as TTP's."""
    with _stub_lookup("/usr/sbin/semodule"):
        with patch("ttp.system_info.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="ttp_tor_policy_local\nunconfined\n", returncode=0)
            assert is_selinux_module_installed() is False


def test_the_shipped_version_is_read_from_the_policy_source():
    """The `.te` file is the single place the policy revision is declared."""
    from ttp.selinux import shipped_policy_version

    assert shipped_policy_version() == "1.2"


def test_a_host_carrying_the_version_we_ship_is_current():
    from ttp import selinux

    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.selinux.recorded_policy_version", return_value="1.2"),
        patch("ttp.selinux.shipped_policy_version", return_value="1.2"),
    ):
        assert selinux.is_policy_module_current() is True


def test_a_host_carrying_an_older_version_is_not_current():
    """The case the dead regex was meant to catch and never did."""
    from ttp import selinux

    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.selinux.recorded_policy_version", return_value="1.1"),
        patch("ttp.selinux.shipped_policy_version", return_value="1.2"),
    ):
        assert selinux.is_policy_module_current() is False


def test_a_module_removed_behind_our_back_is_not_current():
    """The stamp records what TTP installed, not what the kernel still holds.

    An administrator running `semodule -r ttp_tor_policy` leaves the stamp
    behind. Trusting it alone would skip the reinstall and leave Tor unable to
    bind its DNSPort.
    """
    from ttp import selinux

    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=False),
        patch("ttp.selinux.recorded_policy_version", return_value="1.2"),
        patch("ttp.selinux.shipped_policy_version", return_value="1.2"),
    ):
        assert selinux.is_policy_module_current() is False


def test_an_unstamped_host_is_not_current():
    """No record means TTP cannot claim the loaded module is the one it ships."""
    from ttp import selinux

    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        patch("ttp.selinux.recorded_policy_version", return_value=None),
        patch("ttp.selinux.shipped_policy_version", return_value="1.2"),
    ):
        assert selinux.is_policy_module_current() is False


def test_the_recorded_version_round_trips_through_the_stamp(tmp_path):
    from ttp import selinux

    stamp = tmp_path / "selinux-policy-version"
    with patch.object(selinux, "POLICY_VERSION_STAMP", stamp):
        assert selinux.recorded_policy_version() is None
        selinux.record_policy_version("1.2")
        assert selinux.recorded_policy_version() == "1.2"
        selinux.forget_policy_version()
        assert selinux.recorded_policy_version() is None


def test_an_unreadable_stamp_reads_as_no_record(tmp_path):
    """Failing towards a reinstall is the safe direction: worst case is a
    recompile, where the other direction is a host whose Tor cannot bind."""
    from ttp import selinux

    stamp = tmp_path / "selinux-policy-version"
    stamp.write_text("1.2\n", encoding="utf-8")
    with (
        patch.object(selinux, "POLICY_VERSION_STAMP", stamp),
        patch.object(Path, "read_text", side_effect=OSError("EACCES")),
    ):
        assert selinux.recorded_policy_version() is None


def test_installing_the_module_records_the_version_it_installed(tmp_path):
    from ttp import selinux

    stamp = tmp_path / "selinux-policy-version"
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.selinux.is_policy_module_current", return_value=False),
        patch.object(Path, "exists", return_value=True),
        _stub_lookup("/usr/bin/cmd"),
        patch("ttp.selinux.tempfile.TemporaryDirectory") as mock_tempdir,
        patch("ttp.selinux.subprocess.run"),
        patch.object(selinux, "POLICY_VERSION_STAMP", stamp),
    ):
        mock_tempdir.return_value.__enter__.return_value = str(tmp_path / "build")
        selinux.setup_selinux_if_needed()

    assert stamp.read_text(encoding="utf-8").strip() == "1.2"


def test_a_failed_install_records_nothing(tmp_path):
    """A stamp written after a failed `semodule -i` would suppress the retry."""
    from ttp import selinux

    stamp = tmp_path / "selinux-policy-version"
    with (
        patch("ttp.tor_detect.is_fedora_family", return_value=True),
        patch("ttp.tor_detect.is_selinux_enforcing", return_value=True),
        patch("ttp.selinux.is_policy_module_current", return_value=False),
        patch.object(Path, "exists", return_value=True),
        _stub_lookup("/usr/bin/cmd"),
        patch("ttp.selinux.tempfile.TemporaryDirectory") as mock_tempdir,
        patch("ttp.selinux.subprocess.run", side_effect=subprocess.CalledProcessError(1, "semodule")),
        patch.object(selinux, "POLICY_VERSION_STAMP", stamp),
    ):
        mock_tempdir.return_value.__enter__.return_value = str(tmp_path / "build")
        selinux.setup_selinux_if_needed()

    assert not stamp.exists()


def test_removing_the_module_clears_the_stamp(tmp_path):
    """A stamp surviving the removal would claim a policy that is gone."""
    from ttp import selinux

    stamp = tmp_path / "selinux-policy-version"
    stamp.write_text("1.2\n", encoding="utf-8")
    with (
        patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
        _stub_lookup("/usr/sbin/semodule"),
        patch("ttp.selinux.subprocess.run"),
        patch.object(selinux, "POLICY_VERSION_STAMP", stamp),
    ):
        selinux.remove_selinux_module()

    assert not stamp.exists()


def test_a_build_whose_policy_source_is_unreadable_is_never_current():
    """Without the `.te` there is nothing to compare a stamp against.

    A package that ships the code but not the policy data - a `pip install`
    without package data, a truncated build - must not let a leftover stamp
    assert that the loaded policy is the right one.
    """
    from ttp import selinux

    with patch("ttp.selinux._policy_source", return_value=None):
        assert selinux.shipped_policy_version() is None
        with (
            patch("ttp.tor_detect.is_selinux_module_installed", return_value=True),
            patch("ttp.selinux.recorded_policy_version", return_value="1.2"),
        ):
            assert selinux.is_policy_module_current() is False


def test_an_unreadable_policy_file_reads_as_no_source():
    from ttp import selinux

    traversable = MagicMock()
    traversable.read_text.side_effect = OSError("EACCES")
    with patch("ttp.selinux.importlib.resources.files") as files:
        files.return_value.joinpath.return_value = traversable
        assert selinux._policy_source() is None


def test_writing_the_stamp_never_reaches_for_the_default_directory(tmp_path):
    """The writer must create the parent of the path it is about to write.

    It used to create the module-level `/var/lib/ttp` instead. Every test here
    patches `POLICY_VERSION_STAMP` to a tmp path, so the mkdir was aimed
    somewhere the test never looked: on a developer machine where
    `/var/lib/ttp` already exists it succeeded and the write landed, and the
    suite was green. On a CI runner without that directory the mkdir raised
    `EACCES`, the best-effort `except OSError` swallowed it, and no stamp was
    ever written - which is exactly the failure the tests were meant to catch.

    `PERSISTENT_DIR` is patched here to a path that cannot be created, so any
    code reaching for it again fails loudly instead of depending on the host.
    """
    from ttp import selinux

    stamp = tmp_path / "state" / "selinux-policy-version"
    with (
        patch.object(selinux, "POLICY_VERSION_STAMP", stamp),
        patch.object(selinux, "PERSISTENT_DIR", Path("/proc/ttp-must-not-be-touched")),
    ):
        selinux.record_policy_version("1.2")

    assert stamp.read_text(encoding="utf-8").strip() == "1.2"
