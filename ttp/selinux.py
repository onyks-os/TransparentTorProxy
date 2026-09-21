# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""SELinux policy management for Tor dynamic port bindings."""

import importlib.resources
import logging
import re
import subprocess
import tempfile
from pathlib import Path

from ttp.paths import resolve_optional
from ttp.system_info import SELINUX_POLICY_MODULE
from ttp.ux import PERSISTENT_DIR

logger = logging.getLogger("ttp")

#: Where TTP records the policy revision it last installed successfully.
#:
#: ``semodule`` cannot be asked this. Its ``-l`` output carries no version on
#: current policycoreutils, and ``--list-modules=full`` adds a priority and a
#: language but still no version. So the question "is the loaded policy the one
#: this build ships?" is answerable only against a record TTP keeps itself.
#:
#: The file lives in the persistent directory because the answer must survive a
#: reboot - the policy does. It is root-owned along with its directory; a
#: missing, unreadable or malformed stamp reads as "no record", which forces a
#: reinstall. That is the safe direction: the cost is one ``checkmodule`` cycle,
#: where trusting a wrong stamp costs a host whose Tor cannot bind its DNSPort.
POLICY_VERSION_STAMP = PERSISTENT_DIR / "selinux-policy-version"

#: ``module ttp_tor_policy 1.2;`` - the first non-comment statement of a .te.
_MODULE_DECLARATION = re.compile(rf"^\s*module\s+{re.escape(SELINUX_POLICY_MODULE)}\s+([0-9.]+)\s*;", re.MULTILINE)


def _policy_source() -> str | None:
    """Return the text of the shipped ``.te``, or ``None`` if it is missing."""
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath(f"{SELINUX_POLICY_MODULE}.te")
    try:
        return traversable.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError):
        return None


def shipped_policy_version() -> str | None:
    """Return the version this build's policy source declares, e.g. ``"1.2"``.

    ``None`` when the source is missing, unreadable, or declares no version -
    three cases with one answer, because all three mean the same thing: this
    build cannot say which revision it ships, so nothing may be called current.
    """
    match = _MODULE_DECLARATION.search(_policy_source() or "")
    return match.group(1) if match else None


def recorded_policy_version() -> str | None:
    """Return the version TTP last installed, or ``None`` if there is no record."""
    try:
        recorded = POLICY_VERSION_STAMP.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    return recorded or None


def record_policy_version(version: str) -> None:
    """Record *version* as the policy revision now loaded."""
    try:
        PERSISTENT_DIR.mkdir(parents=True, exist_ok=True)
        POLICY_VERSION_STAMP.write_text(f"{version}\n", encoding="utf-8")
    except OSError as e:
        # Best effort. An unwritten stamp costs a recompile on the next start,
        # which is the same cost the bug in #50 imposed on every start.
        logger.debug("Could not record the SELinux policy version: %s", e)


def forget_policy_version() -> None:
    """Drop the record, so the next run treats the policy as absent."""
    try:
        POLICY_VERSION_STAMP.unlink(missing_ok=True)
    except OSError as e:
        logger.debug("Could not clear the SELinux policy version stamp: %s", e)


def is_policy_module_current() -> bool:
    """Return ``True`` when the loaded policy is the revision this build ships.

    Both halves are required. The kernel is asked whether *a* module by that
    name is loaded, because an administrator may have run ``semodule -r`` and
    left the stamp behind; the stamp is consulted for *which* revision, because
    the kernel will not say. Either one alone gives a wrong answer in a case
    that ends with Tor unable to bind its DNSPort.
    """
    from ttp.tor_detect import is_selinux_module_installed

    if not is_selinux_module_installed():
        return False
    shipped = shipped_policy_version()
    return shipped is not None and recorded_policy_version() == shipped


def setup_selinux_if_needed() -> None:
    """Compile and install the custom SELinux policy for Tor on Fedora/RHEL if needed."""
    from ttp.tor_detect import (
        is_fedora_family,
        is_selinux_enforcing,
    )

    if not is_fedora_family() or not is_selinux_enforcing():
        return

    if is_policy_module_current():
        return

    logger.info("SELinux detected. Compiling and installing TTP Tor policy module...")

    # Use importlib.resources to access the policy file inside the package
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath("ttp_tor_policy.te")

    with importlib.resources.as_file(traversable) as te_path:
        if not te_path.exists():
            logger.warning(f"SELinux policy source missing at {te_path}. Skipping.")
            return

        checkmodule = resolve_optional("checkmodule")
        semodule_package = resolve_optional("semodule_package")
        semodule = resolve_optional("semodule")
        if not checkmodule or not semodule_package or not semodule:
            logger.warning(
                "checkmodule or semodule_package not found. Cannot compile SELinux policy. "
                "Please install checkpolicy and policycoreutils manually."
            )
            return

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                mod_path = tmp / "ttp_tor_policy.mod"
                pp_path = tmp / "ttp_tor_policy.pp"

                logger.debug(f"Compiling {te_path.name}...")
                subprocess.run(
                    [checkmodule, "-M", "-m", "-o", str(mod_path), str(te_path)],
                    check=True,
                )
                subprocess.run(
                    [semodule_package, "-o", str(pp_path), "-m", str(mod_path)],
                    check=True,
                )

                logger.debug(f"Installing {pp_path.name}...")
                subprocess.run([semodule, "-i", str(pp_path)], check=True)

            version = shipped_policy_version()
            if version:
                record_policy_version(version)
            logger.info("SELinux policy module installed successfully.")
        except (subprocess.CalledProcessError, OSError) as e:
            logger.warning(f"SELinux policy installation failed: {e}. Tor might have permission issues.")


def label_ports_selinux(transport_port: int, dns_port: int) -> None:
    """Label our specific TransPort and DNSPort as tor_port_t in SELinux if semanage is available."""
    semanage = resolve_optional("semanage")
    if not semanage:
        logger.debug("semanage not available, skipping dynamic SELinux port labeling.")
        return

    for port, proto in [(transport_port, "tcp"), (dns_port, "udp")]:
        try:
            logger.debug("Adding SELinux port label tor_port_t for %s/%s", port, proto)
            subprocess.run(
                [
                    semanage,
                    "port",
                    "-a",
                    "-t",
                    "tor_port_t",
                    "-p",
                    proto,
                    str(port),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except subprocess.CalledProcessError:
            # If the port mapping already exists, modify it instead
            try:
                subprocess.run(
                    [
                        semanage,
                        "port",
                        "-m",
                        "-t",
                        "tor_port_t",
                        "-p",
                        proto,
                        str(port),
                    ],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            except subprocess.CalledProcessError as e_mod:
                logger.warning(
                    "Failed to label port %d/%s as tor_port_t: %s",
                    port,
                    proto,
                    e_mod.stderr.decode().strip(),
                )


def unlabel_ports_selinux(transport_port: int, dns_port: int) -> None:
    """Remove our specific TransPort and DNSPort labels from SELinux if semanage is available."""
    semanage = resolve_optional("semanage")
    if not semanage:
        return

    for port, proto in [(transport_port, "tcp"), (dns_port, "udp")]:
        try:
            logger.debug("Removing SELinux port label for %s/%s", port, proto)
            subprocess.run(
                [semanage, "port", "-d", "-p", proto, str(port)],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except subprocess.CalledProcessError:
            # Non-fatal if removal fails (e.g. was never added or already removed)
            pass


def remove_selinux_module() -> None:
    """Remove the custom TTP SELinux policy module."""
    # PATH lookup, not a hardcoded /usr/sbin: semodule sits in different places
    # across distributions, and this matches how the module probes checkmodule
    # and semodule_package above.
    semodule = resolve_optional("semodule")
    if not semodule:
        return

    from ttp.tor_detect import is_selinux_module_installed

    if not is_selinux_module_installed():
        return

    logger.info("Removing TTP Tor policy module...")
    try:
        subprocess.run([semodule, "-r", SELINUX_POLICY_MODULE], check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        logger.warning(f"Failed to remove SELinux policy module: {e}")
        return

    # Only once the module is actually gone: a stamp outliving a failed removal
    # would be a record of a policy that is still loaded.
    forget_policy_version()
    logger.info("SELinux policy module removed.")
