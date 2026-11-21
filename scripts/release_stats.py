#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Estimate how many people downloaded TTP's releases, without telemetry.

GitHub counts every download of a release asset: the project's own
verify-release workflow, mirrors and crawlers included. Those fetch *every*
asset of a release. A person fetches one package, perhaps with its checksums.
Nobody downloads the SBOMs (``*.cdx.json``) by hand, so the lowest SBOM count
of a release is its floor of automated downloads, and a package's count above
that floor estimates the people who downloaded it.

It is an estimate, not a count: one person downloading twice counts twice, and
a crawler that fetches only the ``.deb`` counts as a person.

    scripts/release_stats.py                    # a table, for a terminal
    scripts/release_stats.py --json             # the full snapshot
    scripts/release_stats.py --snapshot DIR     # record it, as the workflow does

Release counts are public. Traffic (views, clones, referrers, paths) needs a
token with write access to the repository, read from ``STATS_TOKEN``,
``GH_TOKEN`` or ``GITHUB_TOKEN``; without one, traffic is recorded as
unavailable. Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
DEFAULT_REPO = "onyks-os/TransparentTorProxy"
PACKAGE_SUFFIXES = (".deb", ".rpm", ".whl", ".tar.gz")
SBOM_SUFFIXES = (".cdx.json", "sbom.json")
TRAFFIC_ENDPOINTS = ("views", "clones", "popular/referrers", "popular/paths")
#: What a recorded snapshot keeps of the traffic. Referrers and visited paths
#: are shown by GitHub to maintainers only; the stats branch is public, so they
#: stay out of it (``--json`` still prints them).
PUBLIC_TRAFFIC = ("views", "clones")
TRAFFIC_COLUMNS = ("date", "views", "unique_views", "clones", "unique_clones")
HISTORY_COLUMNS = ("date", "estimated", "raw_packages", "stars")


def kind(name: str) -> str:
    """``sbom``, ``package`` or ``other`` (signatures, checksums, keys)."""
    if name.endswith(SBOM_SUFFIXES):
        return "sbom"
    if name.endswith(PACKAGE_SUFFIXES):
        return "package"
    return "other"


def estimate(release: dict[str, Any]) -> dict[str, Any]:
    """The floor of automated downloads, and each package's count above it."""
    assets = release.get("assets", [])
    sboms = [a["download_count"] for a in assets if kind(a["name"]) == "sbom"]
    floor = min(sboms) if sboms else 0
    raw = {a["name"]: a["download_count"] for a in assets if kind(a["name"]) == "package"}
    packages = {name: max(0, count - floor) for name, count in raw.items()}
    return {
        "tag": release["tag_name"],
        "published_at": release.get("published_at"),
        # Without SBOMs there is no floor to subtract: the estimate is then the
        # raw count, an overestimate, and says so.
        "has_floor": bool(sboms),
        "floor": floor,
        "raw_packages": sum(raw.values()),
        "estimated": sum(packages.values()),
        "packages": packages,
    }


def _get(url: str, token: str | None) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def releases(repo: str, token: str | None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = _get(f"{API}/repos/{repo}/releases?per_page=100&page={page}", token)
        found.extend(r for r in batch if not r.get("draft"))
        if len(batch) < 100:
            return found
        page += 1


def traffic(repo: str, token: str | None) -> dict[str, Any] | None:
    """Traffic, or None when the token may not read it (or there is none)."""
    if not token:
        return None
    result = {}
    try:
        for endpoint in TRAFFIC_ENDPOINTS:
            result[endpoint] = _get(f"{API}/repos/{repo}/traffic/{endpoint}", token)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403, 404):
            return None
        raise
    return result


def snapshot(repo: str, token: str | None, traffic_token: str | None, now: datetime.datetime) -> dict[str, Any]:
    estimates = [estimate(r) for r in releases(repo, token)]
    return {
        "taken_at": now.isoformat(timespec="seconds"),
        "repo": repo,
        "stars": _get(f"{API}/repos/{repo}", token).get("stargazers_count"),
        "estimated": sum(e["estimated"] for e in estimates),
        "raw_packages": sum(e["raw_packages"] for e in estimates),
        "releases": estimates,
        "traffic": traffic(repo, traffic_token),
    }


def traffic_rows(data: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Daily views and clones keyed by date, from one 14-day traffic window."""
    rows: dict[str, dict[str, Any]] = {}
    if not data:
        return rows
    for endpoint, prefix in (("views", "views"), ("clones", "clones")):
        for day in data.get(endpoint, {}).get(endpoint, []):
            date = day["timestamp"][:10]
            row = rows.setdefault(date, {"date": date})
            row[prefix] = day["count"]
            row[f"unique_{prefix}"] = day["uniques"]
    return rows


def _read_csv(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open(newline="") as handle:
        return {row["date"]: row for row in csv.DictReader(handle)}


def _write_csv(path: Path, columns: tuple[str, ...], rows: dict[str, dict[str, Any]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, restval="")
        writer.writeheader()
        for date in sorted(rows):
            writer.writerow({column: rows[date].get(column, "") for column in columns})


def badge(data: dict[str, Any]) -> dict[str, Any]:
    """A shields.io endpoint badge for the estimate."""
    return {
        "schemaVersion": 1,
        "label": "downloads (est.)",
        "message": str(data["estimated"]),
        "color": "blue",
    }


def record(data: dict[str, Any], directory: Path) -> None:
    """Write the snapshot, merge the histories and refresh the badge.

    GitHub keeps only 14 days of traffic and only cumulative download counts,
    so the history exists only if it is recorded. A day seen in two windows
    keeps the later reading: the last day of a window may still be partial.
    Only views and clones are recorded; see ``PUBLIC_TRAFFIC``.
    """
    date = data["taken_at"][:10]
    if data["traffic"] is not None:
        data = {**data, "traffic": {key: data["traffic"][key] for key in PUBLIC_TRAFFIC if key in data["traffic"]}}
    (directory / "snapshots").mkdir(parents=True, exist_ok=True)
    (directory / "snapshots" / f"{date}.json").write_text(json.dumps(data, indent=2) + "\n")

    days = _read_csv(directory / "traffic.csv")
    for day, row in traffic_rows(data["traffic"]).items():
        days[day] = {**days.get(day, {}), **row}
    _write_csv(directory / "traffic.csv", TRAFFIC_COLUMNS, days)

    history = _read_csv(directory / "downloads.csv")
    history[date] = {"date": date, **{key: data[key] for key in HISTORY_COLUMNS[1:]}}
    _write_csv(directory / "downloads.csv", HISTORY_COLUMNS, history)

    (directory / "downloads.json").write_text(json.dumps(badge(data)) + "\n")


def table(data: dict[str, Any]) -> str:
    lines = [f"{'release':<10} {'floor':>5} {'raw':>5} {'est.':>5}  packages above the floor"]
    for release in data["releases"]:
        floor = str(release["floor"]) if release["has_floor"] else "-"
        detail = ", ".join(f"{name} {count}" for name, count in release["packages"].items())
        lines.append(
            f"{release['tag']:<10} {floor:>5} {release['raw_packages']:>5} {release['estimated']:>5}  {detail}"
        )
    lines.append(f"{'total':<10} {'':>5} {data['raw_packages']:>5} {data['estimated']:>5}")
    if any(not r["has_floor"] for r in data["releases"]):
        lines.append("floor '-': the release has no SBOM, so its estimate is the raw count.")
    traffic = data["traffic"]
    if traffic is None:
        lines.append("traffic: unavailable (needs a token with write access to the repository).")
        return "\n".join(lines)
    views, clones = traffic.get("views", {}), traffic.get("clones", {})
    lines.append(
        f"last 14 days: {views.get('count', 0)} views ({views.get('uniques', 0)} unique), "
        f"{clones.get('count', 0)} clones ({clones.get('uniques', 0)} unique)"
    )
    for label, key, field in (("referrers", "popular/referrers", "referrer"), ("pages", "popular/paths", "path")):
        top = ", ".join(f"{item[field]} {item['uniques']}" for item in traffic.get(key, [])[:5])
        if top:
            lines.append(f"top {label} (unique visitors): {top}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=DEFAULT_REPO)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print the full snapshot")
    output.add_argument("--snapshot", type=Path, metavar="DIR", help="record the snapshot in DIR")
    args = parser.parse_args(argv)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or None
    traffic_token = os.environ.get("STATS_TOKEN") or token
    data = snapshot(args.repo, token, traffic_token, datetime.datetime.now(datetime.UTC))

    if args.snapshot:
        record(data, args.snapshot)
        print(f"recorded {data['taken_at']}: {data['estimated']} estimated, {data['raw_packages']} raw")
    elif args.json:
        print(json.dumps(data, indent=2))
    else:
        print(table(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
