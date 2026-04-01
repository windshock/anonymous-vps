#!/usr/bin/env python3
"""
generate_queries.py — known-providers.csv로부터 Logpresso 탐지 쿼리 자동 생성

생성 파일:
    queries/logpresso/<vendor_slug>.logpresso     — 공급자별 (dst_ip 기준, 방화벽)
    queries/logpresso/<vendor_slug>-vpn.logpresso — 공급자별 (client_ip 기준, VPN 인바운드)
    queries/logpresso/all-vendors.logpresso       — 전체 합산 (dst_ip)
    queries/logpresso/all-vendors-vpn.logpresso   — 전체 합산 (VPN)

사용법:
    python3 scripts/generate_queries.py
    python3 scripts/generate_queries.py --vendor BitLaunch
    python3 scripts/generate_queries.py --dry-run
"""

import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT       = Path(__file__).parent.parent
RANGES_CSV = ROOT / "data" / "ip-ranges" / "known-providers.csv"
OUT_DIR    = ROOT / "queries" / "logpresso"


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def vendor_slug(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-")


def cidr_to_filter(cidr: str, ip_field: str) -> str:
    """'45.61.136.0/22' → 'network(client_ip,22) == \"45.61.136.0\"'"""
    net = ipaddress.IPv4Network(cidr, strict=False)
    return f'network({ip_field},{net.prefixlen}) == "{net.network_address}"'


def build_search_clause(cidrs: list[str], ip_field: str) -> str:
    return " or ".join(cidr_to_filter(c, ip_field) for c in cidrs)


# ──────────────────────────────────────────────
# Query templates
# ──────────────────────────────────────────────

VPN_QUERY_TMPL = """\
## {vendor} — VPN 인바운드 탐지 (Anonymous VPS: {asn})
## 생성: generate_queries.py  |  source: data/ip-ranges/known-providers.csv
##
## 사용법: Logpresso에서 직접 실행하거나 모니터링 쿼리에 search 절로 삽입
## IP 범위 수: {range_count}개  |  ASN: {asn}

fulltext "New" and "session" and "client" from *:SYS_VPN
  | rex field=line "New session from client IP (?<client_ip>[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}})"
  | search {search_clause}
"""

FW_QUERY_TMPL = """\
## {vendor} — 방화벽 아웃바운드 탐지 (Anonymous VPS: {asn})
## 생성: generate_queries.py  |  source: data/ip-ranges/known-providers.csv
##
## 사용법: Logpresso에서 직접 실행하거나 방화벽/IDS 쿼리에 search 절로 삽입
## IP 범위 수: {range_count}개  |  ASN: {asn}

{search_clause}
"""

FILTER_ONLY_TMPL = """\
## {vendor} ({asn}) — search 절만 (다른 쿼리에 삽입용)
{search_clause}
"""


def make_queries(vendor: str, asn: str, cidrs: list[str]) -> dict[str, str]:
    vpn_clause = build_search_clause(cidrs, "client_ip")
    fw_clause  = build_search_clause(cidrs, "dst_ip")
    ctx = dict(vendor=vendor, asn=asn, range_count=len(cidrs))
    return {
        "vpn": VPN_QUERY_TMPL.format(search_clause=vpn_clause, **ctx),
        "fw":  FW_QUERY_TMPL.format(search_clause=fw_clause, **ctx),
    }


# ──────────────────────────────────────────────
# Core
# ──────────────────────────────────────────────

def load_ranges(vendor_filter: str | None) -> dict[str, dict]:
    """known-providers.csv → {vendor: {asn, cidrs[]}}"""
    data: dict[str, dict] = defaultdict(lambda: {"asn": "", "cidrs": []})
    with open(RANGES_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            vendor = row["vendor"].strip()
            if vendor_filter and vendor.lower() != vendor_filter.lower():
                continue
            data[vendor]["asn"] = row["asn"].strip()
            data[vendor]["cidrs"].append(row["cidr"].strip())
    return dict(data)


def write_queries(vendor_data: dict[str, dict], dry_run: bool) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    all_vpn_clauses: list[str] = []
    all_fw_clauses:  list[str] = []
    all_vendor_names: list[str] = []

    for vendor, info in sorted(vendor_data.items()):
        asn   = info["asn"]
        cidrs = info["cidrs"]
        queries = make_queries(vendor, asn, cidrs)
        slug = vendor_slug(vendor)

        vpn_path = OUT_DIR / f"{slug}-vpn.logpresso"
        fw_path  = OUT_DIR / f"{slug}.logpresso"

        if dry_run:
            print(f"\n{'='*60}")
            print(f"[{vpn_path.name}]")
            print(queries["vpn"][:400] + "…")
        else:
            vpn_path.write_text(queries["vpn"], encoding="utf-8")
            fw_path.write_text(queries["fw"],  encoding="utf-8")
            print(f"  ✅ {vendor:25} → {slug}.logpresso + {slug}-vpn.logpresso  ({len(cidrs)} ranges)")

        all_vpn_clauses.append(f"## {vendor} ({asn})\n  " +
                               build_search_clause(cidrs, "client_ip"))
        all_fw_clauses.append(f"## {vendor} ({asn})\n  " +
                              build_search_clause(cidrs, "dst_ip"))
        all_vendor_names.append(vendor)

    # 전체 합산 쿼리
    all_vpn_search = " or\n  ".join(
        cidr_to_filter(c, "client_ip")
        for v in sorted(vendor_data)
        for c in vendor_data[v]["cidrs"]
    )
    all_fw_search = " or\n  ".join(
        cidr_to_filter(c, "dst_ip")
        for v in sorted(vendor_data)
        for c in vendor_data[v]["cidrs"]
    )
    total_ranges = sum(len(v["cidrs"]) for v in vendor_data.values())

    all_vpn = (
        f"## all-vendors — VPN 인바운드 탐지 (전체 {len(vendor_data)}개 공급자, {total_ranges}개 범위)\n"
        f"## 공급자: {', '.join(sorted(vendor_data))}\n\n"
        f"fulltext \"New\" and \"session\" and \"client\" from *:SYS_VPN\n"
        f"  | rex field=line \"New session from client IP "
        f"(?<client_ip>[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}})\"\n"
        f"  | search {all_vpn_search}\n"
    )
    all_fw = (
        f"## all-vendors — 방화벽 아웃바운드 탐지 (전체 {len(vendor_data)}개 공급자, {total_ranges}개 범위)\n"
        f"## 공급자: {', '.join(sorted(vendor_data))}\n\n"
        f"{all_fw_search}\n"
    )

    if not dry_run:
        (OUT_DIR / "all-vendors-vpn.logpresso").write_text(all_vpn, encoding="utf-8")
        (OUT_DIR / "all-vendors.logpresso").write_text(all_fw, encoding="utf-8")
        print(f"\n  ✅ all-vendors.logpresso + all-vendors-vpn.logpresso  ({total_ranges} total ranges)")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Logpresso detection queries from IP ranges")
    parser.add_argument("--vendor", metavar="NAME", help="특정 공급자만 처리")
    parser.add_argument("--dry-run", action="store_true", help="파일 저장 없이 화면 출력")
    args = parser.parse_args()

    if not RANGES_CSV.exists():
        print(f"❌ IP ranges not found: {RANGES_CSV}")
        print("   먼저 실행: python3 scripts/generate_ranges.py")
        sys.exit(1)

    vendor_data = load_ranges(args.vendor)
    if not vendor_data:
        print("⚠️  No ranges found.")
        sys.exit(0)

    total = sum(len(v["cidrs"]) for v in vendor_data.values())
    print(f"📋 Generating queries for {len(vendor_data)} vendor(s), {total} IP ranges…")
    write_queries(vendor_data, dry_run=args.dry_run)

    if not args.dry_run:
        print(f"\n✅ Done. Files written to {OUT_DIR}/")


if __name__ == "__main__":
    main()
