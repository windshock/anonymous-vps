#!/usr/bin/env python3
"""
validate_records.py — provider / CIDR / incident record validators.

Pure functions returning ``(errors, warnings)``; no I/O, no globals mutated.
Standard library only.
"""

from __future__ import annotations

import ipaddress

from validation_common import (
    CIDR_SCOPES,
    CIDR_STATUSES,
    GENERIC_PAYMENT,
    IOC_STATUSES,
    ISO_COUNTRY_RE,
    ISO_DATE_RE,
    LOCATION_CONTEXT_TAGS,
    PAYMENT_METHODS,
    PROVIDER_STATUSES,
    SERVICE_TYPES,
    evidence_supports_payment,
    evidence_supports_service,
    validate_controlled_list,
    validate_evidence,
    validate_references,
)

_LOCATION_FIELDS = ("tags", "registry_country", "advertised_location", "observed_location", "observed_at")


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
def _validate_provider_claims(provider: dict, subject: str, errors: list[str], warnings: list[str]) -> None:
    """provider_verified는 각 결제/서비스 주장에 claim-specific 근거를 요구.

    legacy candidate가 generic `crypto`를 넘어선 named currency를 근거 없이 선언하면
    hard error가 아니라 warning으로 남겨 기존 인벤토리를 보존한다.
    """
    status = provider.get("status")
    payments = provider.get("payment_methods", [])
    services = provider.get("service_types", [])
    evidence = provider.get("evidence", [])
    if not isinstance(payments, list):
        return

    if status == "provider_verified":
        if payments and not evidence_supports_payment(evidence):
            errors.append(
                f"{subject}: provider_verified declares payment {payments} without claim-specific evidence"
            )
        if services and not evidence_supports_service(evidence):
            errors.append(
                f"{subject}: provider_verified declares service {services} without claim-specific evidence"
            )
    elif status == "candidate":
        named = [p for p in payments if isinstance(p, str) and p != GENERIC_PAYMENT]
        if named and not evidence_supports_payment(evidence):
            warnings.append(
                f"{subject}: candidate declares named currencies {named} without payment evidence"
            )


def validate_providers(providers: list[dict]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for provider in providers:
        provider_id = provider.get("provider_id")
        subject = f"provider:{provider_id or '<missing>'}"
        if not provider_id:
            errors.append(f"{subject}: missing provider_id")
            continue
        if provider_id in seen:
            errors.append(f"{subject}: duplicate provider_id")
        seen.add(provider_id)
        if provider.get("status") not in PROVIDER_STATUSES:
            errors.append(f"{subject}: invalid status '{provider.get('status')}'")
        if not provider.get("name"):
            errors.append(f"{subject}: missing name")
        if not isinstance(provider.get("domains", []), list):
            errors.append(f"{subject}: domains must be a list")
        bridge = provider.get("bridge", {})
        if not isinstance(bridge, dict):
            errors.append(f"{subject}: bridge must be an object")
        else:
            for field in ("domain", "asn_link", "shodan_template", "abuse_template", "note", "source"):
                if field not in bridge:
                    errors.append(f"{subject}: bridge missing '{field}'")
        validate_controlled_list(provider.get("service_types", []), SERVICE_TYPES, "service_types", subject, errors)
        validate_controlled_list(provider.get("payment_methods", []), PAYMENT_METHODS, "payment_methods", subject, errors)
        validate_evidence(provider.get("evidence", []), subject, errors)
        _validate_provider_claims(provider, subject, errors, warnings)
    return errors, warnings


# --------------------------------------------------------------------------- #
# CIDRs
# --------------------------------------------------------------------------- #
def _validate_location_context(record: dict, subject: str, errors: list[str], warnings: list[str]) -> None:
    if record.get("status") != "candidate":
        errors.append(f"{subject}: location_context rows must stay status 'candidate'")

    tags = record.get("tags")
    if not isinstance(tags, list) or not tags:
        errors.append(f"{subject}: location_context requires a non-empty tags list")
        tags = tags if isinstance(tags, list) else []
    for tag in tags:
        if tag not in LOCATION_CONTEXT_TAGS:
            errors.append(f"{subject}: unknown location tag '{tag}'")

    registry = record.get("registry_country", "")
    registry_ok = isinstance(registry, str) and bool(ISO_COUNTRY_RE.match(registry))
    if not registry_ok:
        errors.append(f"{subject}: registry_country must be ISO 3166-1 alpha-2 uppercase, got '{registry}'")

    advertised = record.get("advertised_location", "")
    if not (isinstance(advertised, str) and advertised.strip()):
        errors.append(f"{subject}: advertised_location must be a non-empty string")

    is_mismatch = "geo-mismatch-candidate" in tags
    if is_mismatch:
        observed = record.get("observed_location", "")
        if not (isinstance(observed, str) and ISO_COUNTRY_RE.match(observed)):
            errors.append(f"{subject}: geo-mismatch-candidate requires ISO observed_location, got '{observed}'")
        elif registry_ok and observed == registry:
            errors.append(f"{subject}: geo-mismatch-candidate requires registry/observed countries to be distinct")
        observed_at = record.get("observed_at", "")
        if not (isinstance(observed_at, str) and ISO_DATE_RE.match(observed_at)):
            errors.append(f"{subject}: geo-mismatch-candidate requires observed_at as YYYY-MM-DD, got '{observed_at}'")
    elif "observed_location" in record or "observed_at" in record:
        errors.append(
            f"{subject}: observation fields (observed_location/observed_at) are only allowed on "
            f"geo-mismatch-candidate rows"
        )


def validate_cidrs(cidrs: list[dict], provider_index: dict, asn_index: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for record in cidrs:
        cidr = record.get("cidr", "")
        subject = f"cidr:{cidr or '<missing>'}"
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"{subject}: invalid CIDR '{cidr}'")
            continue
        if cidr in seen:
            errors.append(f"{subject}: duplicate CIDR")
        seen.add(cidr)
        if record.get("status") not in CIDR_STATUSES:
            errors.append(f"{subject}: invalid status '{record.get('status')}'")
        scope = record.get("scope")
        if scope not in CIDR_SCOPES:
            errors.append(f"{subject}: invalid scope '{scope}'")
        provider_id = record.get("provider_id")
        if provider_id and provider_id not in provider_index:
            errors.append(f"{subject}: unknown provider_id '{provider_id}'")
        asn = record.get("asn")
        if asn and asn.upper() not in asn_index:
            errors.append(f"{subject}: unknown ASN '{asn}'")
        validate_evidence(record.get("evidence", []), subject, errors)

        if scope == "location_context":
            _validate_location_context(record, subject, errors, warnings)
        else:
            present = [field for field in _LOCATION_FIELDS if field in record]
            if present:
                errors.append(f"{subject}: fields {present} are only valid on scope 'location_context'")
    return errors, warnings


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #
def validate_incidents(incidents: list[dict], provider_index: dict, asn_index: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen_incidents: set[str] = set()
    seen_iocs: set[tuple[str, str]] = set()
    for incident in incidents:
        incident_id = incident.get("incident_id")
        subject = f"incident:{incident_id or '<missing>'}"
        if not incident_id:
            errors.append(f"{subject}: missing incident_id")
            continue
        if incident_id in seen_incidents:
            errors.append(f"{subject}: duplicate incident_id")
        seen_incidents.add(incident_id)
        if not incident.get("name"):
            errors.append(f"{subject}: missing name")
        validate_references(incident.get("references", []), subject, errors)
        iocs = incident.get("iocs", [])
        if not isinstance(iocs, list) or not iocs:
            errors.append(f"{subject}: iocs must be a non-empty list")
            continue
        for idx, item in enumerate(iocs, start=1):
            ioc_subject = f"{subject}:ioc[{idx}]"
            if item.get("type") != "ipv4":
                errors.append(f"{ioc_subject}: only ipv4 IOCs are supported right now")
                continue
            value = item.get("value", "")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"{ioc_subject}: invalid IP '{value}'")
            if item.get("status") not in IOC_STATUSES:
                errors.append(f"{ioc_subject}: invalid status '{item.get('status')}'")
            if (incident_id, value) in seen_iocs:
                errors.append(f"{ioc_subject}: duplicate IOC within incident")
            seen_iocs.add((incident_id, value))
            provider_id = item.get("provider_id")
            if provider_id and provider_id not in provider_index:
                errors.append(f"{ioc_subject}: unknown provider_id '{provider_id}'")
            asn = item.get("asn")
            if asn and asn.upper() not in asn_index:
                errors.append(f"{ioc_subject}: unknown ASN '{asn}'")
    return errors, warnings
