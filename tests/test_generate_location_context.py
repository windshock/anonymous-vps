"""Todo 5 contract: the isolated KR location-context CSV generator.

Imports the not-yet-existing generator inside each test so collection succeeds.
"""

from __future__ import annotations

import csv
import io
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate_location_context.py"

EXPECTED_FIELDS = [
    "cidr",
    "provider_id",
    "vendor",
    "asn",
    "status",
    "tags",
    "registry_country",
    "advertised_location",
    "observed_location",
    "observed_at",
    "summary",
    "evidence_types",
    "source_urls",
]


def test_csv_contract_fieldnames_and_order():
    import generate_location_context as gen

    assert gen.FIELDNAMES == EXPECTED_FIELDS
    assert gen.OUT_FILE == ROOT / "generated" / "context" / "kr-localized-cidrs.csv"


def test_csv_contract_rows_sorted_and_serialized():
    import generate_location_context as gen

    rows = gen.build_rows()
    cidrs = [row["cidr"] for row in rows]
    assert cidrs == sorted(cidrs)
    assert set(cidrs) == {"79.110.55.0/24", "84.233.167.0/24", "141.98.213.0/24"}

    by_cidr = {row["cidr"]: row for row in rows}
    mismatch = by_cidr["79.110.55.0/24"]
    assert mismatch["tags"] == "kr-localized | geo-mismatch-candidate"
    assert mismatch["observed_location"] == "JP"
    assert mismatch["observed_at"]

    plain = by_cidr["84.233.167.0/24"]
    assert plain["tags"] == "kr-localized"
    assert plain["observed_location"] == ""
    assert plain["observed_at"] == ""
    assert " | " in plain["source_urls"] or plain["source_urls"]


def test_dry_run_is_deterministic_and_writes_nothing(tmp_path):
    def run():
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--dry-run"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    out_file = ROOT / "generated" / "context" / "kr-localized-cidrs.csv"
    existed_before = out_file.exists()
    before = out_file.read_bytes() if existed_before else None

    first = run()
    second = run()
    assert first.returncode == 0, first.stderr
    assert first.stdout == second.stdout

    header = next(csv.reader(io.StringIO(first.stdout)))
    assert header == EXPECTED_FIELDS

    # dry-run must not create or modify the real artifact
    assert out_file.exists() == existed_before
    if existed_before:
        assert out_file.read_bytes() == before
