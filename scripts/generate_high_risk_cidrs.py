#!/usr/bin/env python3
"""
generate_high_risk_cidrs.py — Export generalized CIDRs that cleared the conservative bar.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from data_model import ROOT, build_provider_index, load_cidrs, load_providers

OUT_FILE = ROOT / "generated" / "detection" / "high-risk-cidrs.csv"
FIELDNAMES = [
    "cidr",
    "provider_id",
    "vendor",
    "asn",
    "status",
    "scope",
    "summary",
    "evidence_types",
    "source_urls",
]
HIGH_RISK_STATUSES = {"abuse_candidate", "campaign_observed"}


def build_rows() -> list[dict[str, str]]:
    provider_index = build_provider_index(load_providers())
    rows: list[dict[str, str]] = []

    for record in load_cidrs():
        if record.get("scope") != "high_risk_detection":
            continue
        if record.get("status") not in HIGH_RISK_STATUSES:
            continue
        provider = provider_index.get(record.get("provider_id"))
        evidence = record.get("evidence", [])
        rows.append(
            {
                "cidr": record["cidr"],
                "provider_id": record.get("provider_id", ""),
                "vendor": provider["name"] if provider else "",
                "asn": record.get("asn", ""),
                "status": record.get("status", ""),
                "scope": record.get("scope", ""),
                "summary": record.get("summary", ""),
                "evidence_types": " | ".join(item.get("type", "") for item in evidence),
                "source_urls": " | ".join(item.get("url", "") for item in evidence if item.get("url")),
            }
        )

    return sorted(rows, key=lambda row: row["cidr"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate high-risk CIDR CSV")
    parser.add_argument("--dry-run", action="store_true", help="Print CSV instead of writing files")
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
    print(f"✅ Generated {len(rows)} high-risk CIDR rows → {OUT_FILE}")


if __name__ == "__main__":
    main()
