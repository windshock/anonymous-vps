#!/usr/bin/env python3
"""
generate_provider_ranges.py — Build provider inventory CIDR views from linked ASNs.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

from data_model import (
    ROOT,
    build_provider_index,
    choose_primary_asn,
    load_asns,
    load_providers,
    provider_asn_map,
)

ASN_DB = ROOT / "data" / "asn-ipv4.csv"
OUT_PROVIDER_RANGES = ROOT / "generated" / "detection" / "provider-ranges.csv"
OUT_LEGACY = ROOT / "data" / "ip-ranges" / "known-providers.csv"

FIELDNAMES = [
    "provider_id",
    "vendor",
    "asn",
    "cidr",
    "start_ip",
    "end_ip",
    "org",
    "scope",
    "status",
]
LEGACY_FIELDNAMES = ["vendor", "asn", "cidr", "start_ip", "end_ip", "org", "note"]


def cidr_from_range(start: str, end: str) -> list[str]:
    nets = ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start),
        ipaddress.IPv4Address(end),
    )
    return [str(network) for network in nets]


def provider_targets(provider_filter: str | None) -> dict[str, dict[str, str]]:
    providers = load_providers()
    asn_records = load_asns()
    provider_index = build_provider_index(providers)
    targets: dict[str, dict[str, str]] = {}

    for provider_id, records in provider_asn_map(asn_records).items():
        provider = provider_index[provider_id]
        if provider_filter and provider["name"].lower() != provider_filter.lower():
            continue
        eligible = [
            record
            for record in records
            if record.get("relationship") in {"owned_by_provider", "used_by_provider"}
        ]
        primary = choose_primary_asn(eligible)
        if not primary:
            continue
        targets[primary["asn"].lstrip("AS")] = {
            "provider_id": provider_id,
            "vendor": provider["name"],
            "status": provider["status"],
        }

    return targets


def build_rows(provider_filter: str | None) -> list[dict[str, str]]:
    if not ASN_DB.exists():
        raise SystemExit(f"❌ ASN DB not found: {ASN_DB}")
    targets = provider_targets(provider_filter)
    rows_by_key: dict[tuple[str, str], dict[str, str]] = {}

    with open(ASN_DB, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 3:
                continue
            asn_num = row[2].strip()
            target = targets.get(asn_num)
            if not target:
                continue
            start_ip, end_ip = row[0].strip(), row[1].strip()
            org = row[3].strip() if len(row) > 3 else ""
            for cidr in cidr_from_range(start_ip, end_ip):
                key = (target["provider_id"], cidr)
                rows_by_key.setdefault(
                    key,
                    {
                        "provider_id": target["provider_id"],
                        "vendor": target["vendor"],
                        "asn": f"AS{asn_num}",
                        "cidr": cidr,
                        "start_ip": start_ip,
                        "end_ip": end_ip,
                        "org": org,
                        "scope": "provider_allocated",
                        "status": target["status"],
                    },
                )

    return sorted(rows_by_key.values(), key=lambda item: (item["vendor"].lower(), item["cidr"]))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]], dry_run: bool) -> None:
    if dry_run:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def legacy_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        {
            "vendor": row["vendor"],
            "asn": row["asn"],
            "cidr": row["cidr"],
            "start_ip": row["start_ip"],
            "end_ip": row["end_ip"],
            "org": row["org"],
            "note": "",
        }
        for row in rows
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate provider inventory ranges from ASN links")
    parser.add_argument("--vendor", metavar="NAME", help="Filter a single provider name")
    parser.add_argument("--dry-run", action="store_true", help="Print the new CSV instead of writing files")
    args = parser.parse_args()

    if args.vendor and not args.dry_run:
        raise SystemExit(
            "❌ Refusing to overwrite aggregate provider-range CSVs with a filtered provider set. "
            "Use --dry-run for inspection."
        )

    rows = build_rows(args.vendor)
    if not rows:
        print("⚠️  No provider ranges found.")
        return

    write_csv(OUT_PROVIDER_RANGES, FIELDNAMES, rows, dry_run=args.dry_run)
    if not args.dry_run:
        write_csv(OUT_LEGACY, LEGACY_FIELDNAMES, legacy_rows(rows), dry_run=False)
        print(f"✅ Generated {len(rows)} provider inventory CIDRs")
        print(f"   {OUT_PROVIDER_RANGES}")
        print(f"   {OUT_LEGACY}")


if __name__ == "__main__":
    main()
