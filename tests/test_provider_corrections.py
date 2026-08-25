"""Todo 3 contract: provider identity correction and evidence enrichment.

Reads the real data files. RED until DataCamp is separated from COIN.HOST and
the verified COIN.HOST / Evoxt records are added.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROVIDERS = ROOT / "data" / "providers.yml"
ASNS = ROOT / "data" / "asns.yml"

DEFERRED_IDS = {"onionvps", "ironserver", "0xcloud", "likevps", "navicosoft", "xservercloud"}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _by_id(records):
    return {r["provider_id"]: r for r in records}


def test_datacamp_is_not_coin_host():
    providers = _by_id(_load(PROVIDERS))
    datacamp = providers["datacamp-limited"]
    blob = json.dumps(datacamp, ensure_ascii=False).lower()
    assert "coin.host" not in blob
    assert datacamp["domains"] == ["datacamp.co.uk"]
    assert datacamp["service_types"] == ["hosting"]
    assert datacamp["payment_methods"] == []


def test_as212238_owned_by_datacamp_without_coin_host():
    asns = {a["asn"]: a for a in _load(ASNS)}
    rec = asns["AS212238"]
    assert rec["provider_id"] == "datacamp-limited"
    assert rec["relationship"] == "owned_by_provider"
    assert "coin.host" not in json.dumps(rec, ensure_ascii=False).lower()


def test_coin_host_added_as_verified_without_asn():
    providers = _load(PROVIDERS)
    matches = [p for p in providers if p["provider_id"] == "coin-host"]
    assert len(matches) == 1
    coin = matches[0]
    assert coin["status"] == "provider_verified"
    assert "solar" in json.dumps(coin, ensure_ascii=False).lower()
    asns = _load(ASNS)
    assert not any(a.get("provider_id") == "coin-host" for a in asns)


def test_evoxt_added_as_verified_without_asn():
    providers = _load(PROVIDERS)
    matches = [p for p in providers if p["provider_id"] == "evoxt"]
    assert len(matches) == 1
    assert matches[0]["status"] == "provider_verified"
    asns = _load(ASNS)
    assert not any(a.get("provider_id") == "evoxt" for a in asns)


def test_named_currency_enrichment_has_payment_evidence():
    from validation_common import evidence_supports_payment

    providers = _by_id(_load(PROVIDERS))
    for pid in ("njalla", "shinjiru", "black-host"):
        rec = providers[pid]
        assert rec["payment_methods"], f"{pid} should declare named currencies"
        assert set(rec["payment_methods"]) - {"crypto"}, f"{pid} should have named currencies"
        assert evidence_supports_payment(rec["evidence"]), f"{pid} missing payment evidence"


def test_no_deferred_providers_added():
    providers = _load(PROVIDERS)
    ids = {p["provider_id"] for p in providers}
    assert ids.isdisjoint(DEFERRED_IDS)
    blob = json.dumps(providers, ensure_ascii=False).lower()
    assert "154.219.226.0" not in blob


def test_validate_passes_after_corrections():
    """The full real dataset must still validate cleanly with corrections applied."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_data.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "6 warning(s)" in result.stdout
