#!/usr/bin/env python3
"""
generate_ranges.py — vps-providers.csv의 ASN을 asn-ipv4.csv와 조인하여
                     data/ip-ranges/known-providers.csv 자동 생성

사용법:
    python3 scripts/generate_ranges.py
    python3 scripts/generate_ranges.py --vendor BitLaunch   # 특정 공급자만
    python3 scripts/generate_ranges.py --dry-run            # 화면 출력만
"""

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

ROOT         = Path(__file__).parent.parent
PROVIDERS    = ROOT / "data" / "vps-providers.csv"
ASN_DB       = ROOT / "data" / "asn-ipv4.csv"
OUT_RANGES   = ROOT / "data" / "ip-ranges" / "known-providers.csv"
NOTES_FILE   = ROOT / "data" / "ip-ranges" / "notes.csv"   # 수동 메모 (optional)

FIELDNAMES   = ["vendor", "asn", "cidr", "start_ip", "end_ip", "org", "note"]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def load_notes() -> dict[tuple, str]:
    """notes.csv → {(vendor, cidr): note} 매핑 반환"""
    if not NOTES_FILE.exists():
        return {}
    notes = {}
    with open(NOTES_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["vendor"].strip(), row["cidr"].strip())
            notes[key] = row["note"].strip()
    return notes


def cidr_from_range(start: str, end: str) -> list[str]:
    """시작 IP ~ 끝 IP로부터 CIDR 목록 계산"""
    nets = ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start),
        ipaddress.IPv4Address(end)
    )
    return [str(n) for n in nets]


# ──────────────────────────────────────────────
# Core
# ──────────────────────────────────────────────

def load_providers(vendor_filter: str | None) -> dict[str, str]:
    """ASN이 있는 공급자만 반환 → {asn_num: vendor_name}"""
    mapping: dict[str, str] = {}
    with open(PROVIDERS, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            asn = row["asn"].strip().upper()
            vendor = row["vendor"].strip()
            if not asn:
                continue
            asn_num = asn.lstrip("AS")
            if vendor_filter and vendor.lower() != vendor_filter.lower():
                continue
            mapping[asn_num] = vendor
    return mapping


def scan_asn_db(asn_map: dict[str, str]) -> list[dict]:
    """asn-ipv4.csv를 스캔하여 해당 ASN 행 추출"""
    results: list[dict] = []
    print(f"🔍 Scanning {ASN_DB} for {len(asn_map)} ASN(s)…")

    with open(ASN_DB, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            asn_num = row[2].strip()
            if asn_num not in asn_map:
                continue
            start, end = row[0].strip(), row[1].strip()
            org = row[3].strip() if len(row) > 3 else ""
            vendor = asn_map[asn_num]
            for cidr in cidr_from_range(start, end):
                results.append({
                    "vendor": vendor,
                    "asn":    f"AS{asn_num}",
                    "cidr":   cidr,
                    "start_ip": start,
                    "end_ip":   end,
                    "org":    org,
                    "note":   "",
                })
    return results


def apply_notes(rows: list[dict], notes: dict[tuple, str]) -> list[dict]:
    for r in rows:
        key = (r["vendor"], r["cidr"])
        if key in notes:
            r["note"] = notes[key]
    return rows


def write_output(rows: list[dict], dry_run: bool) -> None:
    rows_sorted = sorted(rows, key=lambda r: (r["vendor"].lower(), r["cidr"]))
    if dry_run:
        w = csv.DictWriter(sys.stdout, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows_sorted)
        return
    OUT_RANGES.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_RANGES, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows_sorted)
    print(f"✅ {len(rows_sorted)} IP ranges written → {OUT_RANGES}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IP ranges from ASN database")
    parser.add_argument("--vendor", metavar="NAME", help="특정 공급자만 처리")
    parser.add_argument("--dry-run", action="store_true", help="파일 저장 없이 화면 출력")
    args = parser.parse_args()

    if not ASN_DB.exists():
        print(f"❌ ASN DB not found: {ASN_DB}")
        print("   먼저 실행: python3 scripts/fetch_asn.py")
        sys.exit(1)

    asn_map = load_providers(args.vendor)
    if not asn_map:
        print("⚠️  No providers with ASN found. Nothing to generate.")
        sys.exit(0)

    print(f"📋 Providers with ASN: {len(asn_map)}")
    for num, vendor in sorted(asn_map.items(), key=lambda x: x[1]):
        print(f"   AS{num:10} → {vendor}")

    rows = scan_asn_db(asn_map)
    notes = load_notes()
    rows = apply_notes(rows, notes)

    # 공급자별 요약
    from collections import Counter
    counts = Counter(r["vendor"] for r in rows)
    print(f"\n📊 IP ranges found: {len(rows)} total")
    for vendor, count in sorted(counts.items()):
        print(f"   {vendor:25} {count:4} ranges")

    if not rows:
        print("⚠️  No ranges found. Check ASN values in vps-providers.csv.")
        sys.exit(1)

    write_output(rows, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
