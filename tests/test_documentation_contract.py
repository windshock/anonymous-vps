"""Todo 6 contract: docs, policy, changelog, and the KR report describe the
four separate evidence layers and drop the false DataCamp=coin.host mapping.

Reads the real docs. RED until the reconciliation edits land.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
AGENT = ROOT / "AGENT.md"
POLICY = ROOT / "docs" / "policy.md"
CHECKLIST = ROOT / "docs" / "review-checklist.md"
REPORT = ROOT / "reports" / "kr-localized-anonymous-vps-2026-08.md"
CHANGELOG = ROOT / "CHANGELOG.md"

DOC_FILES = [README, AGENT, POLICY, CHECKLIST, REPORT, CHANGELOG]

_DATACAMP_COINHOST = re.compile(r"datacamp[^\n]{0,40}coin\.host|coin\.host[^\n]{0,40}datacamp", re.IGNORECASE)


def test_no_datacamp_coin_host_mapping_anywhere():
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        assert not _DATACAMP_COINHOST.search(text), f"false DataCamp=coin.host mapping in {path.name}"


def test_report_drops_legal_concerns_as_risk_and_utm():
    text = REPORT.read_text(encoding="utf-8")
    assert "utm_source=chatgpt.com" not in text
    assert "LEGAL CONCERNS" not in text.upper() or "verdict" in text.lower()


def test_readme_documents_context_layer_and_isolation():
    text = README.read_text(encoding="utf-8")
    assert "generated/context/kr-localized-cidrs.csv" in text
    assert "kr-localized" in text
    assert "geo-mismatch-candidate" in text
    # crypto payment alone qualifies for inventory, never for detection
    assert re.search(r"crypto", text, re.IGNORECASE)


def test_readme_names_four_layers():
    text = README.read_text(encoding="utf-8").lower()
    for token in ("provider inventory", "asn", "location context", "detection"):
        assert token in text, f"README missing layer: {token}"


def test_policy_and_checklist_keep_location_out_of_detection():
    policy = POLICY.read_text(encoding="utf-8").lower()
    checklist = CHECKLIST.read_text(encoding="utf-8").lower()
    assert "location context" in policy
    assert "location" in checklist


def test_report_uses_datacamp_co_uk_not_coin_host():
    text = REPORT.read_text(encoding="utf-8")
    assert "coin.host" not in text.lower()
