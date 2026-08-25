"""Shared offline fixtures for the anonymous-vps test-suite.

No fixture here touches the network or the real 22 MB ASN database. Record
fixtures are small JSON-compatible dicts and the ASN snapshot is a handful of
synthetic rows written into ``tmp_path``.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def repo_root() -> Path:
    return ROOT


# --------------------------------------------------------------------------- #
# Record builders (return fresh dicts so tests can mutate freely)
# --------------------------------------------------------------------------- #
@pytest.fixture
def make_provider():
    def _make(**overrides):
        record = {
            "provider_id": "example",
            "name": "Example",
            "domains": ["example.com"],
            "service_types": ["vps"],
            "payment_methods": [],
            "status": "candidate",
            "summary": "Example provider held for context.",
            "bridge": {
                "domain": "example.com",
                "asn_link": "https://bgp.tools/asn/1",
                "shodan_template": "https://shodan.io/search?query=example.com",
                "abuse_template": "https://www.abuseipdb.com/check/<IP>",
                "note": "context only",
                "source": "aggregator lists",
            },
            "evidence": [
                {
                    "type": "provider_site",
                    "source": "Example official site",
                    "url": "https://example.com",
                    "claim": "service_domain",
                }
            ],
        }
        record.update(overrides)
        return record

    return _make


@pytest.fixture
def make_asn():
    def _make(**overrides):
        record = {
            "asn": "AS64500",
            "name": "Example Networks",
            "provider_id": "example",
            "relationship": "owned_by_provider",
            "status": "candidate",
            "summary": "context",
            "evidence": [
                {
                    "type": "provider_site",
                    "source": "Example official site",
                    "url": "https://example.com",
                    "claim": "service_domain",
                }
            ],
        }
        record.update(overrides)
        return record

    return _make


@pytest.fixture
def make_cidr():
    def _make(**overrides):
        record = {
            "cidr": "192.0.2.0/24",
            "asn": "AS64500",
            "provider_id": "example",
            "status": "candidate",
            "scope": "provider_allocated",
            "summary": "context only",
            "evidence": [
                {
                    "type": "registry_record",
                    "source": "RDAP",
                    "url": "https://rdap.db.ripe.net/ip/192.0.2.0",
                    "claim": "allocation_context",
                }
            ],
        }
        record.update(overrides)
        return record

    return _make


@pytest.fixture
def verified_provider(make_provider):
    """A fully-evidenced provider_verified record that must validate cleanly."""
    return make_provider(
        provider_id="verified-example",
        name="Verified Example",
        status="provider_verified",
        service_types=["vps", "hosting"],
        payment_methods=["btc", "xmr"],
        summary="Official VPS/hosting service with documented crypto payments.",
        evidence=[
            {
                "type": "provider_site",
                "source": "Verified Example official site",
                "url": "https://verified.example",
                "claim": "official_vps_hosting_service",
            },
            {
                "type": "payment_page",
                "source": "Verified Example payment page",
                "url": "https://verified.example/payment",
                "claim": "official_crypto_payment_btc_xmr",
            },
        ],
    )


@pytest.fixture
def tiny_asn_csv(tmp_path) -> Path:
    """Write a tiny sapics-shaped asn-ipv4.csv snapshot into tmp_path."""
    path = tmp_path / "asn-ipv4.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["1.0.0.0", "1.0.0.255", "64500", "Example Networks"])
        writer.writerow(["2.0.0.0", "2.0.0.255", "20473", "The Constant Company, LLC"])
        writer.writerow(["3.0.0.0", "3.0.0.255", "39287", "Materialism s.r.l."])
    return path
