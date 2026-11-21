# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""The download estimate behind the README's statistics, without the network."""

import csv
import io
import json
import runpy
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
stats = runpy.run_path(str(ROOT / "scripts/release_stats.py"))


def release(tag, **counts):
    return {
        "tag_name": tag,
        "published_at": "2026-10-06T00:00:00Z",
        "assets": [{"name": name, "download_count": count} for name, count in counts.items()],
    }


V0411 = release(
    "v0.4.11",
    **{
        "transparent-tor-proxy_0.4.11_all.deb": 101,
        "transparent-tor-proxy_0.4.11_all.deb.cdx.json": 8,
        "transparent-tor-proxy_0.4.11_all.deb.sigstore.json": 12,
        "transparent-tor-proxy-0.4.11-1.fc44.noarch.rpm": 38,
        "transparent-tor-proxy-0.4.11-1.fc44.noarch.rpm.cdx.json": 9,
        "transparent_tor_proxy-0.4.11.tar.gz": 14,
        "transparent_tor_proxy-0.4.11.tar.gz.cdx.json.sigstore.json": 8,
        "SHA256SUMS.txt": 13,
    },
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("transparent-tor-proxy_0.4.11_all.deb", "package"),
        ("transparent-tor-proxy-0.5.0-1.fc45.noarch.rpm", "package"),
        ("transparent_tor_proxy-0.5.0-py3-none-any.whl", "package"),
        ("transparent_tor_proxy-0.5.0.tar.gz", "package"),
        ("transparent-tor-proxy_0.4.11_all.deb.cdx.json", "sbom"),
        ("sbom.json", "sbom"),
        # A signature of an SBOM is not an SBOM: a verifier fetches it with
        # whatever it checks, so it says nothing about the automated floor.
        ("transparent-tor-proxy_0.4.11_all.deb.cdx.json.sigstore.json", "other"),
        ("transparent-tor-proxy_0.4.11_all.deb.sigstore.json", "other"),
        ("transparent-tor-proxy-0.5.0-fc45-rpm-key.asc", "other"),
        ("SHA256SUMS.txt", "other"),
    ],
)
def test_assets_are_told_apart_by_name(name, expected):
    assert stats["kind"](name) == expected


def test_the_lowest_sbom_count_is_subtracted_from_every_package():
    result = stats["estimate"](V0411)

    assert result["has_floor"] is True
    assert result["floor"] == 8
    assert result["packages"] == {
        "transparent-tor-proxy_0.4.11_all.deb": 93,
        "transparent-tor-proxy-0.4.11-1.fc44.noarch.rpm": 30,
        "transparent_tor_proxy-0.4.11.tar.gz": 6,
    }
    assert result["raw_packages"] == 153
    assert result["estimated"] == 129


def test_a_package_below_the_floor_counts_as_nobody_not_as_a_negative():
    result = stats["estimate"](release("v1", **{"a.deb": 2, "a.deb.cdx.json": 5}))

    assert result["packages"] == {"a.deb": 0}
    assert result["estimated"] == 0


def test_a_release_without_sboms_reports_its_raw_count_and_says_so():
    result = stats["estimate"](release("v0.1.0", **{"ttp_0.1.0_all.deb": 3, "SHA256SUMS.txt": 9}))

    assert result["has_floor"] is False
    assert result["estimated"] == result["raw_packages"] == 3
    assert "floor '-'" in stats["table"]({"releases": [result], "raw_packages": 3, "estimated": 3, "traffic": {}})


def test_traffic_days_merge_views_and_clones():
    data = {
        "views": {"views": [{"timestamp": "2026-11-20T00:00:00Z", "count": 12, "uniques": 9}]},
        "clones": {
            "clones": [
                {"timestamp": "2026-11-20T00:00:00Z", "count": 40, "uniques": 15},
                {"timestamp": "2026-11-21T00:00:00Z", "count": 3, "uniques": 2},
            ]
        },
    }

    rows = stats["traffic_rows"](data)

    assert rows["2026-11-20"] == {
        "date": "2026-11-20",
        "views": 12,
        "unique_views": 9,
        "clones": 40,
        "unique_clones": 15,
    }
    assert rows["2026-11-21"] == {"date": "2026-11-21", "clones": 3, "unique_clones": 2}
    assert stats["traffic_rows"](None) == {}


def snapshot(date, estimated, views=None):
    traffic = None
    if views is not None:
        traffic = {
            "views": {"views": [{"timestamp": f"{day}T00:00:00Z", "count": c, "uniques": c} for day, c in views]},
            "clones": {"clones": []},
        }
    return {
        "taken_at": f"{date}T06:17:00+00:00",
        "stars": 42,
        "estimated": estimated,
        "raw_packages": estimated + 50,
        "releases": [],
        "traffic": traffic,
    }


def read_csv(path):
    return list(csv.DictReader(io.StringIO(path.read_text())))


def test_recording_keeps_history_beyond_githubs_fourteen_days(tmp_path):
    record = stats["record"]

    record(snapshot("2026-11-16", 300, views=[("2026-11-14", 5), ("2026-11-15", 4)]), tmp_path)
    # A week later: the 15th is seen again with a complete count; the 14th has
    # left GitHub's window and must survive from the earlier snapshot.
    record(snapshot("2026-11-23", 320, views=[("2026-11-15", 7), ("2026-11-22", 10)]), tmp_path)

    traffic = {row["date"]: row["views"] for row in read_csv(tmp_path / "traffic.csv")}
    assert traffic == {"2026-11-14": "5", "2026-11-15": "7", "2026-11-22": "10"}

    history = read_csv(tmp_path / "downloads.csv")
    assert [(row["date"], row["estimated"]) for row in history] == [("2026-11-16", "300"), ("2026-11-23", "320")]

    assert sorted(p.name for p in (tmp_path / "snapshots").iterdir()) == ["2026-11-16.json", "2026-11-23.json"]
    assert json.loads((tmp_path / "downloads.json").read_text()) == {
        "schemaVersion": 1,
        "label": "downloads (est.)",
        "message": "320",
        "color": "blue",
    }


def test_a_snapshot_without_traffic_keeps_the_traffic_already_recorded(tmp_path):
    stats["record"](snapshot("2026-11-16", 300, views=[("2026-11-15", 4)]), tmp_path)
    stats["record"](snapshot("2026-11-23", 320), tmp_path)

    assert [row["date"] for row in read_csv(tmp_path / "traffic.csv")] == ["2026-11-15"]


@pytest.mark.parametrize("code", [401, 403, 404])
def test_traffic_the_token_may_not_read_is_unavailable_not_an_error(monkeypatch, code):
    def refuse(url, token):
        raise urllib.error.HTTPError(url, code, "refused", {}, None)

    traffic = stats["traffic"]
    monkeypatch.setitem(traffic.__globals__, "_get", refuse)

    assert traffic("o/r", "token") is None


def test_no_token_means_no_traffic_request():
    assert stats["traffic"]("o/r", None) is None


def test_a_server_error_is_not_mistaken_for_missing_permission(monkeypatch):
    def fail(url, token):
        raise urllib.error.HTTPError(url, 502, "bad gateway", {}, None)

    traffic = stats["traffic"]
    monkeypatch.setitem(traffic.__globals__, "_get", fail)

    with pytest.raises(urllib.error.HTTPError):
        traffic("o/r", "token")


def test_referrers_and_paths_never_reach_the_public_snapshot(tmp_path):
    data = snapshot("2026-11-23", 320, views=[("2026-11-22", 10)])
    data["traffic"]["popular/referrers"] = [{"referrer": "intranet.example", "count": 3, "uniques": 1}]
    data["traffic"]["popular/paths"] = [{"path": "/onyks-os/TransparentTorProxy/releases", "count": 4}]

    stats["record"](data, tmp_path)

    written = (tmp_path / "snapshots" / "2026-11-23.json").read_text()
    assert "intranet.example" not in written
    assert "/releases" not in written
    assert set(json.loads(written)["traffic"]) == {"views", "clones"}
    # The caller's snapshot is not changed under it.
    assert "popular/referrers" in data["traffic"]


def test_the_table_summarises_traffic_when_it_is_readable():
    traffic = {
        "views": {"count": 140, "uniques": 60},
        "clones": {"count": 300, "uniques": 90},
        "popular/referrers": [{"referrer": "github.com", "count": 50, "uniques": 20}],
        "popular/paths": [],
    }

    text = stats["table"]({"releases": [], "raw_packages": 0, "estimated": 0, "traffic": traffic})

    assert "140 views (60 unique), 300 clones (90 unique)" in text
    assert "top referrers (unique visitors): github.com 20" in text
    assert "top pages" not in text
