#!/usr/bin/env python3
"""
generate_legacy_bridge.py — Rebuild legacy provider CSV views from the new data model.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from data_model import ROOT, asn_link, choose_primary_asn, load_asns, load_providers, primary_domain, provider_asn_map

OUT_GENERATED = ROOT / "generated" / "legacy" / "providers-bridge.csv"
OUT_LEGACY = ROOT / "data" / "vps-providers.csv"
FIELDNAMES = [
    "vendor",
    "domain",
    "asn",
    "asn_link",
    "shodan_template",
    "abuse_template",
    "note",
    "source",
]


def build_rows(provider_filter: str | None) -> list[dict[str, str]]:
    providers = load_providers()
    asn_map = provider_asn_map(load_asns())
    rows: list[dict[str, str]] = []

    for provider in sorted(providers, key=lambda item: item["name"].lower()):
        if provider_filter and provider["name"].lower() != provider_filter.lower():
            continue
        eligible = [
            record
            for record in asn_map.get(provider["provider_id"], [])
            if record.get("relationship") in {"owned_by_provider", "used_by_provider"}
        ]
        primary = choose_primary_asn(eligible)
        bridge = provider.get("bridge", {})
        asn = primary["asn"] if primary else ""
        rows.append(
            {
                "vendor": provider["name"],
                "domain": bridge.get("domain", primary_domain(provider)),
                "asn": asn,
                "asn_link": bridge.get("asn_link") or asn_link(asn),
                "shodan_template": bridge.get("shodan_template", ""),
                "abuse_template": bridge.get("abuse_template", "https://www.abuseipdb.com/check/<IP>"),
                "note": bridge.get("note", provider.get("summary", "")),
                "source": bridge.get("source", ""),
            }
        )

    return rows


def write_csv(path: Path, rows: list[dict[str, str]], dry_run: bool) -> None:
    if dry_run:
        writer = csv.DictWriter(sys.stdout, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate legacy provider CSV bridge files")
    parser.add_argument("--vendor", metavar="NAME", help="Filter a single provider name")
    parser.add_argument("--dry-run", action="store_true", help="Print CSV instead of writing files")
    args = parser.parse_args()

    if args.vendor and not args.dry_run:
        raise SystemExit(
            "❌ Refusing to overwrite aggregate bridge CSVs with a filtered provider set. "
            "Use --dry-run for inspection."
        )

    rows = build_rows(args.vendor)
    if not rows:
        print("⚠️  No provider rows found.")
        return

    write_csv(OUT_GENERATED, rows, dry_run=args.dry_run)
    if not args.dry_run:
        write_csv(OUT_LEGACY, rows, dry_run=False)
        print(f"✅ Generated {len(rows)} provider bridge rows")
        print(f"   {OUT_GENERATED}")
        print(f"   {OUT_LEGACY}")


if __name__ == "__main__":
    main()
