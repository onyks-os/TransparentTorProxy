# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tor readiness checking and orchestration module.

This module enforces a strict NO AUTO-INSTALL policy. TTP will never attempt
to install system packages automatically. If Tor or required pluggable transport
helpers are missing, TTP displays distro-specific package guidance and official
documentation links, then exits gracefully with status code 0.
"""

from __future__ import annotations

import logging
import shutil
from typing import Any, Optional

import typer
from rich.panel import Panel

from ttp.tor_config import (
    PT_MAP as PT_MAP,
    TOR_CACHE_DIR as TOR_CACHE_DIR,
    TOR_RUNTIME_DIR as TOR_RUNTIME_DIR,
    _build_torrc_content as _build_torrc_content,
    generate_torrc as generate_torrc,
)
from ttp.tor_detect import detect_tor
from ttp.tor_service import (
    TTP_SERVICE_NAME as TTP_SERVICE_NAME,
    TTP_SERVICE_PATH as TTP_SERVICE_PATH,
    _build_service_unit_content as _build_service_unit_content,
    _write_service_unit as _write_service_unit,
    start_tor_service as start_tor_service,
    stop_tor_service as stop_tor_service,
)
from ttp.selinux import (
    setup_selinux_if_needed as setup_selinux_if_needed,
    label_ports_selinux as label_ports_selinux,
    unlabel_ports_selinux as unlabel_ports_selinux,
    remove_selinux_module as remove_selinux_module,
)

logger = logging.getLogger("ttp")


def _get_distro_install_command(
    pkg_debian: str,
    pkg_fedora: str,
    pkg_arch: str = "",
    pkg_suse: str = "",
) -> str:
    """Return the recommended package installation command for the current system."""
    if shutil.which("apt-get") or shutil.which("apt"):
        return f"sudo apt install {pkg_debian}"
    elif shutil.which("dnf"):
        return f"sudo dnf install {pkg_fedora}"
    elif shutil.which("pacman"):
        arch_pkg = pkg_arch or pkg_debian
        return f"sudo pacman -S {arch_pkg}"
    elif shutil.which("zypper"):
        suse_pkg = pkg_suse or pkg_debian
        return f"sudo zypper install {suse_pkg}"
    return f"sudo apt install {pkg_debian}   # or: sudo dnf install {pkg_fedora}"


def ensure_pluggable_transports(required_transports: list[str]) -> None:
    """Verify that required pluggable transport helper binaries are installed.

    If any binary is missing, display distro package guidance and official
    documentation links, then exit gracefully with status code 0.
    """
    for pt in required_transports:
        pt = pt.lower()
        if pt not in PT_MAP:
            logger.error("Unsupported pluggable transport: '%s'", pt)
            from ttp.commands._common import console, _PREFIX

            console.print(
                f"{_PREFIX} [bold red]Unsupported pluggable transport: '{pt}'[/bold red]"
            )
            raise typer.Exit(code=0)

        pt_info = PT_MAP[pt]
        binary = pt_info["binary"]

        if not shutil.which(binary):
            cmd = _get_distro_install_command(
                pkg_debian=pt_info["apt-get"],
                pkg_fedora=pt_info["dnf"],
                pkg_arch=pt_info["pacman"],
                pkg_suse=pt_info["zypper"],
            )
            doc_url = "https://tb-manual.torproject.org/bridges/"

            msg = (
                f"[bold red]Pluggable transport helper binary '{binary}' (required for '{pt}') is missing.[/bold red]\n\n"
                f"[bold cyan]Recommended installation command:[/bold cyan]\n"
                f"  [bold yellow]{cmd}[/bold yellow]\n\n"
                f"[bold cyan]Official Tor Bridges Documentation:[/bold cyan]\n"
                f"  {doc_url}"
            )
            from ttp.commands._common import console

            console.print(
                Panel(
                    msg, title="[bold red]Missing Dependency[/bold red]", expand=False
                )
            )
            raise typer.Exit(code=0)


def ensure_tor_ready(
    transport_port: int = 9041,
    dns_port: int = 9054,
    block_doh: bool = True,
    use_bridges: bool = False,
    bridges: Optional[list[str]] = None,
    disable_ipv6: bool = False,
) -> dict[str, Any]:
    """Ensure Tor is installed and start it via the OS native service.

    Enforces strict NO AUTO-INSTALL policy. If Tor or required helpers are missing,
    displays installation guidance and exits gracefully with status code 0.
    """
    info = detect_tor(transport_port=transport_port, dns_port=dns_port)

    if not info["is_installed"]:
        cmd = _get_distro_install_command(pkg_debian="tor", pkg_fedora="tor")
        doc_url = "https://community.torproject.org/onion-services/setup/install/"

        msg = (
            "[bold red]Tor daemon ('tor') is not installed on this system.[/bold red]\n\n"
            "[bold cyan]Recommended installation command:[/bold cyan]\n"
            f"  [bold yellow]{cmd}[/bold yellow]\n\n"
            "[bold cyan]Official Tor Project Installation Guide:[/bold cyan]\n"
            f"  {doc_url}"
        )
        from ttp.commands._common import console

        console.print(
            Panel(
                msg, title="[bold red]Missing Tor Dependency[/bold red]", expand=False
            )
        )
        raise typer.Exit(code=0)

    tor_user = info.get("tor_user", "debian-tor")

    # If bridges are requested, ensure the corresponding pluggable transports are installed
    if use_bridges and bridges:
        required_transports = []
        for b in bridges:
            parts = b.split()
            if parts:
                first_word = parts[0].lower()
                if first_word in PT_MAP:
                    if first_word not in required_transports:
                        required_transports.append(first_word)
        if required_transports:
            ensure_pluggable_transports(required_transports)

    # Start Tor via the dedicated ttp-tor service
    start_tor_service(
        tor_user,
        transport_port=transport_port,
        dns_port=dns_port,
        block_doh=block_doh,
        use_bridges=use_bridges,
        bridges=bridges,
        disable_ipv6=disable_ipv6,
    )

    return info
