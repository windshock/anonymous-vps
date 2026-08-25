#!/usr/bin/env python3
"""
validation_common.py — shared vocabularies and evidence helpers for the validator.

Extracted from the former monolithic ``validate_data.py`` so record, ASN, and
CLI layers share one source of truth for controlled values and evidence rules.
Standard library only.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Controlled vocabularies
# --------------------------------------------------------------------------- #
PROVIDER_STATUSES = {"provider_verified", "candidate", "rejected"}
ASN_STATUSES = {"candidate", "abuse_candidate", "rejected"}
ASN_RELATIONSHIPS = {"owned_by_provider", "used_by_provider", "candidate_link", "unknown"}
CIDR_STATUSES = {"candidate", "abuse_candidate", "campaign_observed", "rejected"}
CIDR_SCOPES = {"provider_allocated", "high_risk_detection"}
IOC_STATUSES = {"ioc_only", "campaign_observed"}

SERVICE_TYPES = {"vpn", "vps", "hosting"}
PAYMENT_METHODS = {"crypto", "btc", "eth", "usdt", "ltc", "xmr", "lightning", "trx"}
GENERIC_PAYMENT = "crypto"  # historical catch-all; named currencies are the specific ones

ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)

# Tokens that mark an evidence item as substantiating a payment / service claim.
_PAYMENT_TOKENS = (
    "payment", "crypto", "bitcoin", "btc", "ethereum", "eth", "usdt", "tether",
    "ltc", "litecoin", "xmr", "monero", "lightning", "trx", "tron",
)
_SERVICE_TOKENS = ("service", "vps", "vpn", "hosting", "provider_site", "provider_exists")


def is_http_url(value: str) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_evidence(evidence: list, subject: str, errors: list[str]) -> None:
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{subject}: evidence must be a non-empty list")
        return
    for idx, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            errors.append(f"{subject}: evidence[{idx}] must be an object")
            continue
        for field in ("type", "source", "claim"):
            if not item.get(field):
                errors.append(f"{subject}: evidence[{idx}] missing '{field}'")
        url = item.get("url", "")
        if url and not is_http_url(url):
            errors.append(f"{subject}: evidence[{idx}] has invalid url '{url}'")


def validate_references(references: list, subject: str, errors: list[str]) -> None:
    if not isinstance(references, list) or not references:
        errors.append(f"{subject}: references must be a non-empty list")
        return
    for idx, item in enumerate(references, start=1):
        if not isinstance(item, dict):
            errors.append(f"{subject}: references[{idx}] must be an object")
            continue
        if not item.get("source"):
            errors.append(f"{subject}: references[{idx}] missing 'source'")
        if not is_http_url(item.get("url", "")):
            errors.append(f"{subject}: references[{idx}] requires a valid url")


def _evidence_matches(evidence: list, tokens: tuple[str, ...]) -> bool:
    if not isinstance(evidence, list):
        return False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        haystack = f"{item.get('claim', '')} {item.get('type', '')}".lower()
        if any(token in haystack for token in tokens):
            return True
    return False


def evidence_supports_payment(evidence: list) -> bool:
    """True if some evidence claim/type references a payment or cryptocurrency."""
    return _evidence_matches(evidence, _PAYMENT_TOKENS)


def evidence_supports_service(evidence: list) -> bool:
    """True if some evidence claim/type references the hosting/VPS/VPN service."""
    return _evidence_matches(evidence, _SERVICE_TOKENS)


def validate_controlled_list(
    values,
    allowed: set[str],
    field: str,
    subject: str,
    errors: list[str],
) -> None:
    """Reject wrong container types, non-string members, duplicates, unknown values."""
    if not isinstance(values, list):
        errors.append(f"{subject}: {field} must be a list")
        return
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            errors.append(f"{subject}: {field} value must be a string, got {type(value).__name__}")
            continue
        if value in seen:
            errors.append(f"{subject}: {field} has duplicate value '{value}'")
        seen.add(value)
        if value not in allowed:
            errors.append(f"{subject}: {field} has unknown value '{value}'")
