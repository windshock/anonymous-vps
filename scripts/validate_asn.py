#!/usr/bin/env python3
"""
validate_asn.py — ASN ownership + format validation, split out of validate_data.py.

Pure functions that return ``(errors, warnings)`` instead of mutating caller lists.
Standard library only.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from data_model import ROOT
from validation_common import ASN_RE, ASN_RELATIONSHIPS, ASN_STATUSES, validate_evidence

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

_STOP_WORDS = {
    "ltd", "llc", "inc", "bv", "srl", "ehf", "ab", "limited", "networks",
    "group", "hosting", "host", "vps", "server", "servers", "internet",
    "solutions", "services", "technology", "systems", "uab", "the", "co",
}


def load_sapics_asn_orgs(path: Path = ASN_IPV4_CSV) -> dict[str, str]:
    """asn-ipv4.csv에서 ASN번호 → 첫 번째 공식 org명 인덱스 반환."""
    if not Path(path).exists():
        return {}
    index: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as f:
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

    def keywords(s: str) -> set[str]:
        return {w for w in re.split(r"[^a-z0-9]+", s.lower()) if w and w not in _STOP_WORDS and len(w) > 1}

    return bool(keywords(provider_name) & keywords(org_name))


def validate_asn_ownership(
    asns: list[dict],
    provider_index: dict,
    sapics: dict[str, str],
) -> tuple[list[str], list[str]]:
    """각 ASN을 sapics 공식 org명과 대조해 오귀속 탐지."""
    errors: list[str] = []
    warnings: list[str] = []
    if not sapics:
        warnings.append("asn-ipv4.csv 없음 — ASN 소유자 검증 건너뜀 (fetch_asn.py 실행 필요)")
        return errors, warnings

    for record in asns:
        asn = record.get("asn", "").upper()
        asn_num = asn.lstrip("AS")
        relationship = record.get("relationship", "")
        provider_id = record.get("provider_id")
        provider = provider_index.get(provider_id, {}) if provider_id else {}
        provider_name = (
            provider.get("name", record.get("name", ""))
            if provider_id
            else record.get("name", "")
        )
        provider_aliases = provider.get("aliases", []) if isinstance(provider.get("aliases", []), list) else []
        provider_names = [provider_name, *[alias for alias in provider_aliases if isinstance(alias, str)]]
        subject = f"asn:{asn}"

        if relationship in {"candidate_link", "unknown"}:
            continue  # 미확인 링크는 소유자 검증 제외

        org = sapics.get(asn_num)
        if not org:
            warnings.append(f"{subject}: sapics에서 찾을 수 없는 ASN (미라우팅 또는 신규)")
            continue

        org_lower = org.lower()
        owner_matches_provider = any(
            _name_overlap(candidate_name, org)
            for candidate_name in provider_names
            if candidate_name
        )

        # 대형 공개 클라우드 ASN을 다른 업체에 귀속시키는 건 탐지 오염
        for cloud in MAJOR_CLOUD_ORGS:
            if cloud in org_lower and not owner_matches_provider:
                errors.append(
                    f"{subject}: 대형 클라우드 ASN 오귀속 — "
                    f"sapics 실제 소유자='{org}', 등록 provider='{provider_name}'. "
                    f"재판매 업체는 ASN 탐지 대상에서 제외해야 합니다."
                )
                break
        else:
            # 일반 불일치 — 브랜드명 vs 법인명 차이일 수 있으므로 경고만
            if not owner_matches_provider:
                warnings.append(
                    f"{subject}: 이름 불일치 — sapics='{org}', provider='{provider_name}' "
                    f"(브랜드명/법인명 차이인지 확인 필요)"
                )

    return errors, warnings


def validate_asns(asns: list[dict], provider_index: dict) -> tuple[list[str], list[str]]:
    """ASN 레코드의 형식/상태/관계/참조 무결성 검증."""
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for record in asns:
        asn = record.get("asn", "").upper()
        subject = f"asn:{record.get('asn', '<missing>')}"
        if not ASN_RE.match(asn):
            errors.append(f"{subject}: invalid ASN format")
            continue
        if asn in seen:
            errors.append(f"{subject}: duplicate ASN")
        seen.add(asn)
        if record.get("status") not in ASN_STATUSES:
            errors.append(f"{subject}: invalid status '{record.get('status')}'")
        if record.get("relationship") not in ASN_RELATIONSHIPS:
            errors.append(f"{subject}: invalid relationship '{record.get('relationship')}'")
        provider_id = record.get("provider_id")
        if provider_id and provider_id not in provider_index:
            errors.append(f"{subject}: unknown provider_id '{provider_id}'")
        validate_evidence(record.get("evidence", []), subject, errors)
    return errors, warnings
