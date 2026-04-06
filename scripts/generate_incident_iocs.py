#!/usr/bin/env python3
"""
generate_incident_iocs.py — Export exact incident IOCs for conservative detection.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from data_model import ROOT, build_provider_index, load_incidents, load_providers

OUT_FILE = ROOT / "generated" / "detection" / "incident-iocs.csv"
FIELDNAMES = [
    "ioc",
    "type",
    "incident_id",
    "incident_name",
    "provider_id",
    "vendor",
    "asn",
    "status",
    "notes",
]


def build_rows(incident_filter: str | None) -> list[dict[str, str]]:
    provider_index = build_provider_index(load_providers())
    rows: list[dict[str, str]] = []

    for incident in load_incidents():
        if incident_filter and incident["incident_id"].lower() != incident_filter.lower():
            continue
        for item in incident.get("iocs", []):
            provider = provider_index.get(item.get("provider_id"))
            rows.append(
                {
                    "ioc": item["value"],
                    "type": item["type"],
                    "incident_id": incident["incident_id"],
                    "incident_name": incident["name"],
                    "provider_id": item.get("provider_id", ""),
                    "vendor": provider["name"] if provider else "",
                    "asn": item.get("asn", ""),
                    "status": item.get("status", ""),
                    "notes": item.get("notes", ""),
                }
            )

    return sorted(rows, key=lambda row: (row["incident_id"], row["ioc"]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate incident IOC CSV")
    parser.add_argument("--incident", metavar="ID", help="Filter a single incident_id")
    parser.add_argument("--dry-run", action="store_true", help="Print CSV instead of writing files")
    args = parser.parse_args()

    rows = build_rows(args.incident)
    if not rows:
        print("⚠️  No incident IOCs found.")
        return

    if args.dry_run:
        writer = csv.DictWriter(sys.stdout, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
        return

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    print(f"✅ Generated {len(rows)} incident IOC rows → {OUT_FILE}")


if __name__ == "__main__":
    main()
