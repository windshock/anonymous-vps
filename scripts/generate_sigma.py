#!/usr/bin/env python3
"""
generate_sigma.py — known-providers.csv로부터 Sigma 탐지 룰 자동 생성

생성 파일:
    queries/sigma/<vendor_slug>.yml     — 공급자별 (방화벽/네트워크 아웃바운드)
    queries/sigma/all-vendors.yml       — 전체 합산

Sigma 룰은 pySigma / sigmac 등으로 Splunk, Elastic, MS Sentinel 등으로 변환 가능.

사용법:
    python3 scripts/generate_sigma.py
    python3 scripts/generate_sigma.py --vendor BitLaunch
    python3 scripts/generate_sigma.py --dry-run
"""

import argparse
import csv
import re
import sys
import uuid
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT       = Path(__file__).parent.parent
RANGES_CSV = ROOT / "data" / "ip-ranges" / "known-providers.csv"
OUT_DIR    = ROOT / "queries" / "sigma"

AUTHOR     = "windshock"
REPO_URL   = "https://github.com/windshock/anonymous-vps"
TODAY      = date.today().isoformat()

# MITRE ATT&CK tags relevant to anonymous VPS C2 / infra
MITRE_TAGS = [
    "attack.command_and_control",
    "attack.t1090",       # Proxy
    "attack.t1583.003",   # Acquire Infrastructure: Virtual Private Server
]


def vendor_slug(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-")


def load_ranges(vendor_filter: str | None) -> dict[str, dict]:
    data: dict[str, dict] = defaultdict(lambda: {"asn": "", "cidrs": [], "notes": []})
    with open(RANGES_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            vendor = row["vendor"].strip()
            if vendor_filter and vendor.lower() != vendor_filter.lower():
                continue
            data[vendor]["asn"] = row["asn"].strip()
            data[vendor]["cidrs"].append(row["cidr"].strip())
            if row.get("note", "").strip():
                data[vendor]["notes"].append(row["note"].strip())
    return dict(data)


def sigma_rule(
    rule_id: str,
    title: str,
    description: str,
    cidrs: list[str],
    level: str = "medium",
    extra_tags: list[str] = [],
) -> str:
    cidr_lines = "\n".join(f"      - '{c}'" for c in sorted(cidrs))
    tags_lines = "\n".join(f"    - {t}" for t in MITRE_TAGS + extra_tags)

    return f"""\
title: {title}
id: {rule_id}
status: experimental
description: {description}
references:
    - {REPO_URL}
    - {REPO_URL}/blob/main/data/vps-providers.csv
author: {AUTHOR}
date: {TODAY}
modified: {TODAY}
tags:
{tags_lines}
logsource:
    category: firewall
    product: any
detection:
    selection:
        dst_ip|cidr:
{cidr_lines}
    condition: selection
falsepositives:
    - Legitimate use of VPS services by internal users
    - Cloud workloads intentionally communicating with these providers
fields:
    - dst_ip
    - src_ip
    - dst_port
    - proto
level: {level}
"""


def make_vendor_rule(vendor: str, asn: str, cidrs: list[str], notes: list[str]) -> str:
    # APT-observed → high, otherwise medium
    level = "high" if any("apt" in n.lower() or "c2" in n.lower() for n in notes) else "medium"
    note_suffix = f" Observed in: {notes[0]}" if notes else ""
    description = (
        f"Detects outbound network connections to IP ranges associated with "
        f"anonymous VPS provider '{vendor}' ({asn}), which accepts cryptocurrency "
        f"payments and requires no KYC.{note_suffix}"
    )
    return sigma_rule(
        rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"anonymous-vps-{vendor_slug(vendor)}")),
        title=f"Network Connection to Anonymous VPS — {vendor}",
        description=description,
        cidrs=cidrs,
        level=level,
    )


def make_all_vendors_rule(vendor_data: dict[str, dict]) -> str:
    all_cidrs = [c for v in vendor_data.values() for c in v["cidrs"]]
    vendor_list = ", ".join(sorted(vendor_data.keys()))
    description = (
        f"Detects outbound network connections to IP ranges associated with "
        f"anonymous VPS providers that accept cryptocurrency payments and require no KYC. "
        f"Providers: {vendor_list}."
    )
    return sigma_rule(
        rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "anonymous-vps-all-vendors")),
        title="Network Connection to Anonymous VPS Provider",
        description=description,
        cidrs=all_cidrs,
        level="medium",
    )


def write_rules(vendor_data: dict[str, dict], dry_run: bool) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for vendor, info in sorted(vendor_data.items()):
        rule = make_vendor_rule(vendor, info["asn"], info["cidrs"], info["notes"])
        slug = vendor_slug(vendor)
        out_path = OUT_DIR / f"{slug}.yml"
        if dry_run:
            print(f"\n{'='*60}\n[{out_path.name}]\n")
            print(rule[:600] + "…")
        else:
            out_path.write_text(rule, encoding="utf-8")
            level = "high" if any("apt" in n.lower() or "c2" in n.lower() for n in info["notes"]) else "medium"
            print(f"  ✅ {vendor:25} → {slug}.yml  ({len(info['cidrs'])} CIDRs, level: {level})")

    # all-vendors
    all_rule = make_all_vendors_rule(vendor_data)
    all_path = OUT_DIR / "all-vendors.yml"
    total = sum(len(v["cidrs"]) for v in vendor_data.values())
    if not dry_run:
        all_path.write_text(all_rule, encoding="utf-8")
        print(f"\n  ✅ all-vendors.yml  ({total} total CIDRs, {len(vendor_data)} vendors)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Sigma detection rules from IP ranges")
    parser.add_argument("--vendor", metavar="NAME", help="특정 공급자만 처리")
    parser.add_argument("--dry-run", action="store_true", help="파일 저장 없이 화면 출력")
    args = parser.parse_args()

    if not RANGES_CSV.exists():
        print(f"❌ IP ranges not found: {RANGES_CSV}")
        print("   Run first: python3 scripts/generate_ranges.py")
        sys.exit(1)

    vendor_data = load_ranges(args.vendor)
    if not vendor_data:
        print("⚠️  No ranges found.")
        sys.exit(0)

    total = sum(len(v["cidrs"]) for v in vendor_data.values())
    print(f"📋 Generating Sigma rules for {len(vendor_data)} vendor(s), {total} CIDRs…")
    write_rules(vendor_data, dry_run=args.dry_run)

    if not args.dry_run:
        print(f"\n✅ Done. Files written to {OUT_DIR}/")


if __name__ == "__main__":
    main()
