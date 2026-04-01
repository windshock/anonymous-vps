#!/usr/bin/env python3
"""
update_providers.py — Anonymous VPS Intelligence 공급자 목록 관리 스크립트

사용법:
    python3 scripts/update_providers.py                  # 검증 + 정렬 저장
    python3 scripts/update_providers.py --dry-run        # 변경 없이 결과만 출력
    python3 scripts/update_providers.py --lookup AS399629  # ASN IP 대역 조회
    python3 scripts/update_providers.py --add            # 대화형으로 공급자 추가
"""

import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PROVIDERS_CSV = ROOT / "data" / "vps-providers.csv"
ASN_IPV4_CSV  = ROOT / "data" / "asn-ipv4.csv"

REQUIRED_COLS = ["vendor", "domain", "asn", "asn_link", "shodan_template", "abuse_template", "note", "source"]
ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)


# ──────────────────────────────────────────────
# Load / Save
# ──────────────────────────────────────────────

def load_providers() -> list[dict]:
    with open(PROVIDERS_CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_providers(rows: list[dict], dry_run: bool = False) -> None:
    rows_sorted = sorted(rows, key=lambda r: r["vendor"].lower())
    if dry_run:
        writer = csv.DictWriter(sys.stdout, fieldnames=REQUIRED_COLS)
        writer.writeheader()
        writer.writerows(rows_sorted)
        return
    with open(PROVIDERS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_COLS)
        writer.writeheader()
        writer.writerows(rows_sorted)
    print(f"✅ Saved {len(rows_sorted)} providers → {PROVIDERS_CSV}")


# ──────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────

def validate(rows: list[dict]) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    seen_vendors: set[str] = set()
    seen_asns: set[str] = set()
    cleaned: list[dict] = []

    for i, row in enumerate(rows, start=2):  # row 1 = header
        vendor = row.get("vendor", "").strip()
        asn    = row.get("asn", "").strip().upper()

        # 필수 컬럼 존재 여부
        for col in REQUIRED_COLS:
            if col not in row:
                errors.append(f"Row {i} ({vendor}): missing column '{col}'")

        # Vendor 중복 (빈 vendor는 domain으로 식별)
        key = vendor.lower() if vendor else f"__domain__{row.get('domain','').lower()}"
        if key and key in seen_vendors:
            errors.append(f"Row {i}: duplicate entry '{vendor or row.get('domain', '')}'")
        seen_vendors.add(key)

        # ASN 형식
        if asn and not ASN_RE.match(asn):
            errors.append(f"Row {i} ({vendor}): invalid ASN format '{asn}' (expected ASnnnn)")
        else:
            row["asn"] = asn  # 정규화 (대문자)

        # ASN 중복 경고 (빈 ASN은 제외)
        if asn and asn in seen_asns:
            print(f"⚠️  Warning row {i} ({vendor}): ASN {asn} already exists in list")
        if asn:
            seen_asns.add(asn)

        cleaned.append({col: row.get(col, "").strip() for col in REQUIRED_COLS})

    return cleaned, errors


# ──────────────────────────────────────────────
# ASN Lookup
# ──────────────────────────────────────────────

def lookup_asn(asn_query: str) -> None:
    asn_num = re.sub(r"(?i)^AS", "", asn_query)
    print(f"🔎 Searching ASN {asn_num} in {ASN_IPV4_CSV} …")

    found = 0
    with open(ASN_IPV4_CSV, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 3:
                continue
            if row[2].strip() == asn_num:
                try:
                    start = ipaddress.IPv4Address(row[0])
                    end   = ipaddress.IPv4Address(row[1])
                    count = int(end) - int(start) + 1
                    print(f"  {row[0]} – {row[1]}  ({count:,} IPs)  org: {row[3] if len(row) > 3 else ''}")
                    found += 1
                except Exception:
                    print(f"  raw: {row}")
                    found += 1

    if found == 0:
        print(f"  No IP ranges found for AS{asn_num}")
    else:
        print(f"\n  Total: {found} range(s) found")


# ──────────────────────────────────────────────
# Interactive Add
# ──────────────────────────────────────────────

def interactive_add(rows: list[dict]) -> list[dict]:
    print("\n📝 새 공급자 추가 (빈칸 Enter = 건너뜀)")
    entry: dict = {}
    for col in REQUIRED_COLS:
        val = input(f"  {col}: ").strip()
        entry[col] = val

    # ASN 정규화
    asn = entry.get("asn", "").upper()
    if asn and not asn.startswith("AS"):
        asn = "AS" + asn
    entry["asn"] = asn

    # Shodan 템플릿 자동생성
    if not entry["shodan_template"] and entry["vendor"]:
        entry["shodan_template"] = f'https://shodan.io/search?query=org:"{entry["vendor"]}"'

    # Abuse 템플릿 기본값
    if not entry["abuse_template"]:
        entry["abuse_template"] = "https://www.abuseipdb.com/check/<IP>"

    rows.append(entry)
    print(f"\n  ✅ Added: {entry['vendor']} ({entry['asn']})")
    return rows


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Anonymous VPS provider list manager")
    parser.add_argument("--dry-run", action="store_true", help="검증 결과 출력만 (파일 저장 안 함)")
    parser.add_argument("--lookup", metavar="ASN", help="ASN에 해당하는 IP 대역 조회 (예: AS399629)")
    parser.add_argument("--add", action="store_true", help="대화형으로 새 공급자 추가")
    args = parser.parse_args()

    if args.lookup:
        lookup_asn(args.lookup)
        return

    rows = load_providers()
    print(f"📋 Loaded {len(rows)} providers from {PROVIDERS_CSV}")

    if args.add:
        rows = interactive_add(rows)

    cleaned, errors = validate(rows)

    if errors:
        print(f"\n❌ {len(errors)} validation error(s):")
        for e in errors:
            print(f"   {e}")
        if not args.dry_run:
            print("\nFix errors before saving. Use --dry-run to preview.")
            sys.exit(1)
    else:
        print(f"✅ All {len(cleaned)} providers passed validation")

    save_providers(cleaned, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
