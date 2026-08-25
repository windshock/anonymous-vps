"""Todo 4 contract: exactly three evidence-backed location_context CIDRs.

Reads the real ``data/cidrs.yml``. RED until the three rows are added.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CIDRS = ROOT / "data" / "cidrs.yml"

APPROVED = {
    "79.110.55.0/24": {"asn": "AS9009", "provider_id": "m247", "geo_mismatch": True},
    "84.233.167.0/24": {"asn": "AS212238", "provider_id": "datacamp-limited", "geo_mismatch": False},
    "141.98.213.0/24": {"asn": "AS206804", "provider_id": "estnoc", "geo_mismatch": False},
}
FORBIDDEN_PREFIXES = {"188.214.106.0/24", "154.219.226.0/24", "188.21.106.0/24"}


def _load():
    return json.loads(CIDRS.read_text(encoding="utf-8"))


def _location_rows():
    return [c for c in _load() if c.get("scope") == "location_context"]


def test_exactly_three_location_context_rows():
    rows = _location_rows()
    assert {r["cidr"] for r in rows} == set(APPROVED)


def test_all_location_rows_are_candidate():
    for row in _location_rows():
        assert row["status"] == "candidate"


def test_approved_prefixes_have_exact_shape():
    rows = {r["cidr"]: r for r in _location_rows()}
    for cidr, spec in APPROVED.items():
        row = rows[cidr]
        assert row["asn"] == spec["asn"]
        assert row["provider_id"] == spec["provider_id"]
        assert "kr-localized" in row["tags"]
        assert row["registry_country"] == "KR"
        assert row["advertised_location"]
        assert row.get("evidence"), f"{cidr} needs CIDR-specific evidence"
        if spec["geo_mismatch"]:
            assert "geo-mismatch-candidate" in row["tags"]
            assert row["observed_location"] and row["observed_location"] != "KR"
            assert row["observed_at"]
        else:
            assert "geo-mismatch-candidate" not in row["tags"]
            assert "observed_location" not in row
            assert "observed_at" not in row


def test_only_m247_row_is_geo_mismatch():
    rows = {r["cidr"]: r for r in _location_rows()}
    mismatch = [c for c, r in rows.items() if "geo-mismatch-candidate" in r.get("tags", [])]
    assert mismatch == ["79.110.55.0/24"]


def test_no_forbidden_prefix_present():
    all_cidrs = {c["cidr"] for c in _load()}
    assert all_cidrs.isdisjoint(FORBIDDEN_PREFIXES)


def test_location_rows_never_reach_high_risk_output():
    from generate_high_risk_cidrs import build_rows

    high_risk_cidrs = {row["cidr"] for row in build_rows()}
    assert high_risk_cidrs.isdisjoint(set(APPROVED))
