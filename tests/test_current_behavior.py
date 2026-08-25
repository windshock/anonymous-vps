"""Lock the current public behavior so the validator refactor cannot regress it.

These tests exercise the real CLI and the real generated CSV headers. They must
pass BEFORE and AFTER the Todo 2 refactor. They intentionally assert stable
structure (exit codes, headers, the six known ASN name-mismatch warnings) rather
than volatile row counts, which grow as data is added in later todos.
"""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_validate_data_cli_passes():
    result = _run("validate_data.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Data validation passed" in result.stdout


def test_validate_data_reports_exactly_six_known_warnings():
    """The six brand-vs-legal-name ASN warnings are the accepted baseline."""
    result = _run("validate_data.py")
    assert result.returncode == 0
    assert "6 warning(s)" in result.stdout
    # No new warning topic should appear beyond the known name-mismatch class.
    for line in result.stdout.splitlines():
        if "이름 불일치" in line or "warning" in line.lower():
            continue
        assert "sapics" not in line or "이름 불일치" in line


def test_validate_data_quiet_suppresses_success_banner():
    result = _run("validate_data.py", "--quiet")
    assert result.returncode == 0
    assert "Data validation passed" not in result.stdout


@pytest.mark.parametrize(
    "relative, expected_header",
    [
        (
            "generated/detection/provider-ranges.csv",
            ["provider_id", "vendor", "asn", "cidr", "start_ip", "end_ip", "org", "scope", "status"],
        ),
        (
            "generated/detection/high-risk-cidrs.csv",
            ["cidr", "provider_id", "vendor", "asn", "status", "scope", "summary", "evidence_types", "source_urls"],
        ),
        (
            "generated/detection/incident-iocs.csv",
            ["ioc", "type", "incident_id", "incident_name", "provider_id", "vendor", "asn", "status", "notes"],
        ),
        (
            "generated/legacy/providers-bridge.csv",
            ["vendor", "domain", "asn", "asn_link", "shodan_template", "abuse_template", "note", "source"],
        ),
    ],
)
def test_generated_csv_headers_are_locked(relative, expected_header):
    path = ROOT / relative
    assert path.exists(), f"missing generated file: {relative}"
    with open(path, newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))
    assert header == expected_header


def test_high_risk_csv_is_header_only():
    """No CIDR has cleared the conservative bar; the file stays header-only."""
    path = ROOT / "generated/detection/high-risk-cidrs.csv"
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []
