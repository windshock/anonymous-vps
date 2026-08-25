#!/usr/bin/env python3
"""
generate_location_context.py — Emit the isolated KR location-context CSV.

This artifact is deliberately kept OUT of ``generated/detection/`` and out of the
Sigma / Logpresso generators. It is hunting/enrichment context (registry + active
geolocation observations), never a detection or high-risk verdict.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from data_model import ROOT, build_provider_index, load_cidrs, load_providers

OUT_FILE = ROOT / "generated" / "context" / "kr-localized-cidrs.csv"
FIELDNAMES = [
    "cidr",
    "provider_id",
    "vendor",
    "asn",
    "status",
    "tags",
    "registry_country",
    "advertised_location",
    "observed_location",
    "observed_at",
    "summary",
    "evidence_types",
    "source_urls",
]
JOIN = " | "  # repository-wide multi-value convention


def build_rows() -> list[dict[str, str]]:
    provider_index = build_provider_index(load_providers())
    rows: list[dict[str, str]] = []

    for record in load_cidrs():
        if record.get("scope") != "location_context":
            continue
        provider = provider_index.get(record.get("provider_id"))
        evidence = record.get("evidence", [])
        rows.append(
            {
                "cidr": record["cidr"],
                "provider_id": record.get("provider_id") or "",
                "vendor": provider["name"] if provider else "",
                "asn": record.get("asn", ""),
                "status": record.get("status", ""),
                "tags": JOIN.join(record.get("tags", [])),
                "registry_country": record.get("registry_country", ""),
                "advertised_location": record.get("advertised_location", ""),
                "observed_location": record.get("observed_location", ""),
                "observed_at": record.get("observed_at", ""),
                "summary": record.get("summary", ""),
                "evidence_types": JOIN.join(item.get("type", "") for item in evidence),
                "source_urls": JOIN.join(item.get("url", "") for item in evidence if item.get("url")),
            }
        )

    return sorted(rows, key=lambda row: row["cidr"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the isolated KR location-context CSV")
    parser.add_argument("--dry-run", action="store_true", help="Print CSV to stdout instead of writing files")
    args = parser.parse_args()

    rows = build_rows()
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
    print(f"✅ Generated {len(rows)} location-context rows → {OUT_FILE}")


if __name__ == "__main__":
    main()
