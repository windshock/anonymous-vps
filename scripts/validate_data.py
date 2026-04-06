#!/usr/bin/env python3
"""
validate_data.py — Validate the slim anonymous VPS intelligence data model.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from urllib.parse import urlparse

from data_model import (
    build_asn_index,
    build_provider_index,
    load_asns,
    load_cidrs,
    load_incidents,
    load_providers,
)

PROVIDER_STATUSES = {"provider_verified", "candidate", "rejected"}
ASN_STATUSES = {"candidate", "abuse_candidate", "rejected"}
ASN_RELATIONSHIPS = {"owned_by_provider", "used_by_provider", "candidate_link", "unknown"}
CIDR_STATUSES = {"candidate", "abuse_candidate", "campaign_observed", "rejected"}
CIDR_SCOPES = {"provider_allocated", "high_risk_detection"}
IOC_STATUSES = {"ioc_only", "campaign_observed"}
ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)


def is_http_url(value: str) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_evidence(
    evidence: list[dict],
    subject: str,
    errors: list[str],
) -> None:
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


def validate_references(
    references: list[dict],
    subject: str,
    errors: list[str],
) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate intelligence data files")
    parser.add_argument("--quiet", action="store_true", help="Only print errors")
    args = parser.parse_args()

    providers = load_providers()
    asns = load_asns()
    cidrs = load_cidrs()
    incidents = load_incidents()

    provider_index = build_provider_index(providers)
    asn_index = build_asn_index(asns)
    errors: list[str] = []

    seen_provider_ids: set[str] = set()
    for provider in providers:
        subject = f"provider:{provider.get('provider_id', '<missing>')}"
        provider_id = provider.get("provider_id")
        if not provider_id:
            errors.append(f"{subject}: missing provider_id")
            continue
        if provider_id in seen_provider_ids:
            errors.append(f"{subject}: duplicate provider_id")
        seen_provider_ids.add(provider_id)
        if provider.get("status") not in PROVIDER_STATUSES:
            errors.append(f"{subject}: invalid status '{provider.get('status')}'")
        if not provider.get("name"):
            errors.append(f"{subject}: missing name")
        domains = provider.get("domains", [])
        if not isinstance(domains, list):
            errors.append(f"{subject}: domains must be a list")
        bridge = provider.get("bridge", {})
        if not isinstance(bridge, dict):
            errors.append(f"{subject}: bridge must be an object")
        else:
            for field in ("domain", "asn_link", "shodan_template", "abuse_template", "note", "source"):
                if field not in bridge:
                    errors.append(f"{subject}: bridge missing '{field}'")
        validate_evidence(provider.get("evidence", []), subject, errors)

    seen_asns: set[str] = set()
    for record in asns:
        subject = f"asn:{record.get('asn', '<missing>')}"
        asn = record.get("asn", "").upper()
        if not ASN_RE.match(asn):
            errors.append(f"{subject}: invalid ASN format")
            continue
        if asn in seen_asns:
            errors.append(f"{subject}: duplicate ASN")
        seen_asns.add(asn)
        if record.get("status") not in ASN_STATUSES:
            errors.append(f"{subject}: invalid status '{record.get('status')}'")
        if record.get("relationship") not in ASN_RELATIONSHIPS:
            errors.append(f"{subject}: invalid relationship '{record.get('relationship')}'")
        provider_id = record.get("provider_id")
        if provider_id and provider_id not in provider_index:
            errors.append(f"{subject}: unknown provider_id '{provider_id}'")
        validate_evidence(record.get("evidence", []), subject, errors)

    seen_cidrs: set[str] = set()
    for record in cidrs:
        subject = f"cidr:{record.get('cidr', '<missing>')}"
        cidr = record.get("cidr", "")
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"{subject}: invalid CIDR '{cidr}'")
            continue
        if cidr in seen_cidrs:
            errors.append(f"{subject}: duplicate CIDR")
        seen_cidrs.add(cidr)
        if record.get("status") not in CIDR_STATUSES:
            errors.append(f"{subject}: invalid status '{record.get('status')}'")
        if record.get("scope") not in CIDR_SCOPES:
            errors.append(f"{subject}: invalid scope '{record.get('scope')}'")
        provider_id = record.get("provider_id")
        if provider_id and provider_id not in provider_index:
            errors.append(f"{subject}: unknown provider_id '{provider_id}'")
        asn = record.get("asn")
        if asn and asn.upper() not in asn_index:
            errors.append(f"{subject}: unknown ASN '{asn}'")
        validate_evidence(record.get("evidence", []), subject, errors)

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

    if errors:
        print(f"❌ Validation failed with {len(errors)} issue(s):")
        for error in errors:
            print(f"   {error}")
        sys.exit(1)

    if not args.quiet:
        print("✅ Data validation passed")
        print(f"   providers : {len(providers)}")
        print(f"   asns      : {len(asns)}")
        print(f"   cidrs     : {len(cidrs)}")
        print(f"   incidents : {len(incidents)}")


if __name__ == "__main__":
    main()
