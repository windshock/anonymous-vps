"""DB-driven KR location-context generator contract.

The core intersection logic is unit-tested with tiny synthetic intervals (offline,
no 22MB DB). A fixture-DB test exercises build_rows end-to-end against the real
data/asns.yml + tiny CSV snapshots.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate_location_context.py"
ASN_DB = ROOT / "data" / "asn-ipv4.csv"
COUNTRY_DB = ROOT / "data" / "country-ipv4.csv"

EXPECTED_FIELDS = ["cidr", "provider_id", "vendor", "asn", "geo_country", "source"]


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def test_fieldnames_and_outfile():
    import generate_location_context as gen

    assert gen.FIELDNAMES == EXPECTED_FIELDS
    assert gen.OUT_FILE == ROOT / "generated" / "context" / "kr-localized-cidrs.csv"


def test_tracked_asn_map_excludes_candidate_and_unknown():
    import generate_location_context as gen

    asns = [
        {"asn": "AS9009", "provider_id": "m247", "relationship": "owned_by_provider"},
        {"asn": "AS100", "provider_id": "x", "relationship": "used_by_provider"},
        {"asn": "AS200", "provider_id": "y", "relationship": "candidate_link"},
        {"asn": "AS300", "provider_id": None, "relationship": "unknown"},
    ]
    provider_index = {"m247": {"name": "M247"}, "x": {"name": "X"}, "y": {"name": "Y"}}
    tracked = gen.tracked_asn_map(asns, provider_index)
    assert set(tracked) == {"9009", "100"}
    assert tracked["9009"] == ("AS9009", "m247", "M247")


def test_core_intersects_and_clips_partial_overlap():
    import generate_location_context as gen

    tracked = {
        "212238": ("AS212238", "datacamp-limited", "Datacamp Limited"),
        "9009": ("AS9009", "m247", "M247"),
    }
    asn_intervals = [
        (_ip("1.2.3.0"), _ip("1.2.3.255"), "212238"),  # fully KR
        (_ip("5.0.0.0"), _ip("5.0.0.255"), "9009"),      # only lower half KR
    ]
    country = sorted([(_ip("1.2.3.0"), _ip("1.2.3.255")), (_ip("5.0.0.0"), _ip("5.0.0.127"))])
    rows = gen.kr_localized_rows(tracked, asn_intervals, country, "KR")
    cidrs = [r["cidr"] for r in rows]
    assert "1.2.3.0/24" in cidrs
    assert "5.0.0.0/25" in cidrs        # clipped to the KR portion only
    assert "5.0.0.0/24" not in cidrs
    assert all(r["geo_country"] == "KR" for r in rows)
    # numerically sorted by network then prefix
    keys = [(_ip(r["cidr"].split("/")[0]), int(r["cidr"].split("/")[1])) for r in rows]
    assert keys == sorted(keys)


def test_core_excludes_non_kr_ranges():
    import generate_location_context as gen

    tracked = {"9009": ("AS9009", "m247", "M247")}
    asn_intervals = [(_ip("8.8.8.0"), _ip("8.8.8.255"), "9009")]
    country = [(_ip("1.2.3.0"), _ip("1.2.3.255"))]  # no overlap with 8.8.8.x
    assert gen.kr_localized_rows(tracked, asn_intervals, country, "KR") == []


def test_core_merges_adjacent_kr_intervals():
    import generate_location_context as gen

    tracked = {"9009": ("AS9009", "m247", "M247")}
    asn_intervals = [(_ip("10.0.0.0"), _ip("10.0.1.255"), "9009")]
    country = sorted([(_ip("10.0.0.0"), _ip("10.0.0.255")), (_ip("10.0.1.0"), _ip("10.0.1.255"))])
    rows = gen.kr_localized_rows(tracked, asn_intervals, country, "KR")
    assert [r["cidr"] for r in rows] == ["10.0.0.0/23"]  # merged, not two /24s


def test_build_rows_with_fixture_dbs(tmp_path):
    """End-to-end over real data/asns.yml (AS212238 -> datacamp-limited) + tiny DB snapshots."""
    import generate_location_context as gen

    asn = tmp_path / "asn.csv"
    asn.write_text('1.2.3.0,1.2.3.255,212238,"Datacamp Limited"\n8.8.8.0,8.8.8.255,15169,"Google"\n', encoding="utf-8")
    country = tmp_path / "country.csv"
    country.write_text("1.2.3.0,1.2.3.255,KR\n8.8.8.0,8.8.8.255,US\n", encoding="utf-8")

    rows = gen.build_rows(asn_db=asn, country_db=country, country="KR")
    assert len(rows) == 1
    row = rows[0]
    assert row["cidr"] == "1.2.3.0/24"
    assert row["provider_id"] == "datacamp-limited"
    assert row["asn"] == "AS212238"
    assert row["geo_country"] == "KR"


@pytest.mark.skipif(not (ASN_DB.exists() and COUNTRY_DB.exists()), reason="requires fetched ASN + country DBs")
def test_dry_run_is_deterministic_and_writes_nothing():
    def run():
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--dry-run"], cwd=ROOT, capture_output=True, text=True
        )

    out_file = ROOT / "generated" / "context" / "kr-localized-cidrs.csv"
    before = out_file.read_bytes() if out_file.exists() else None

    first, second = run(), run()
    assert first.returncode == 0, first.stderr
    assert first.stdout == second.stdout
    header = next(csv.reader(io.StringIO(first.stdout)))
    assert header == EXPECTED_FIELDS
    assert (out_file.read_bytes() if out_file.exists() else None) == before  # unchanged
