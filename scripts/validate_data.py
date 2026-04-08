#!/usr/bin/env python3
"""
validate_data.py — Validate the slim anonymous VPS intelligence data model.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from data_model import (
    ROOT,
    build_asn_index,
    build_provider_index,
    load_asns,
    load_cidrs,
    load_incidents,
    load_providers,
)

ASN_IPV4_CSV = ROOT / "data" / "asn-ipv4.csv"

# 대형 공개 클라우드 — 재판매 업체가 이 ASN을 "사용"하더라도
# ASN 자체로는 해당 업체를 구분할 수 없으므로 탐지에 부적합
MAJOR_CLOUD_ORGS = {
    "the constant company",  # Vultr AS20473
    "amazon",
    "microsoft",
    "google",
    "cloudflare",
    "digitalocean",
    "linode",
    "hetzner",
    "ovh",
    "path network",          # AS396998
}


def load_sapics_asn_orgs() -> dict[str, str]:
    """asn-ipv4.csv에서 ASN번호 → 첫 번째 공식 org명 인덱스 반환."""
    if not ASN_IPV4_CSV.exists():
        return {}
    index: dict[str, str] = {}
    with open(ASN_IPV4_CSV, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4:
                continue
            asn_num = row[2].strip()
            org = row[3].strip().strip('"')
            if asn_num and asn_num not in index:
                index[asn_num] = org
    return index


def _name_overlap(provider_name: str, org_name: str) -> bool:
    """provider명과 sapics org명 사이에 의미 있는 키워드 겹침이 있으면 True."""
    stop = {"ltd", "llc", "inc", "bv", "srl", "ehf", "ab", "limited", "networks",
            "group", "hosting", "host", "vps", "server", "servers", "internet",
            "solutions", "services", "technology", "systems", "uab", "the", "co"}
    def keywords(s: str) -> set[str]:
        return {w for w in re.split(r"[^a-z0-9]+", s.lower()) if w and w not in stop and len(w) > 1}
    return bool(keywords(provider_name) & keywords(org_name))


def validate_asn_ownership(
    asns: list[dict],
    provider_index: dict,
    sapics: dict[str, str],
    errors: list[str],
    warnings: list[str],
) -> None:
    """각 ASN을 sapics 공식 org명과 대조해 오귀속 탐지."""
    if not sapics:
        warnings.append("asn-ipv4.csv 없음 — ASN 소유자 검증 건너뜀 (fetch_asn.py 실행 필요)")
        return

    for record in asns:
        asn = record.get("asn", "").upper()
        asn_num = asn.lstrip("AS")
        relationship = record.get("relationship", "")
        provider_id = record.get("provider_id")
        provider_name = provider_index.get(provider_id, {}).get("name", record.get("name", "")) if provider_id else record.get("name", "")
        subject = f"asn:{asn}"

        if relationship == "candidate_link" or relationship == "unknown":
            continue  # 미확인 링크는 소유자 검증 제외

        org = sapics.get(asn_num)
        if not org:
            warnings.append(f"{subject}: sapics에서 찾을 수 없는 ASN (미라우팅 또는 신규)")
            continue

        org_lower = org.lower()

        # 대형 공개 클라우드 ASN을 다른 업체에 귀속시키는 건 탐지 오염
        for cloud in MAJOR_CLOUD_ORGS:
            if cloud in org_lower and not _name_overlap(provider_name, org):
                errors.append(
                    f"{subject}: 대형 클라우드 ASN 오귀속 — "
                    f"sapics 실제 소유자='{org}', 등록 provider='{provider_name}'. "
                    f"재판매 업체는 ASN 탐지 대상에서 제외해야 합니다."
                )
                break
        else:
            # 일반 불일치 — 브랜드명 vs 법인명 차이일 수 있으므로 경고만
            if not _name_overlap(provider_name, org):
                warnings.append(
                    f"{subject}: 이름 불일치 — sapics='{org}', provider='{provider_name}' "
                    f"(브랜드명/법인명 차이인지 확인 필요)"
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
    warnings: list[str] = []

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

    sapics = load_sapics_asn_orgs()
    validate_asn_ownership(asns, provider_index, sapics, errors, warnings)

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

    if warnings and not args.quiet:
        print(f"⚠️  {len(warnings)} warning(s):")
        for w in warnings:
            print(f"   {w}")

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
