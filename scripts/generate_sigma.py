#!/usr/bin/env python3
"""
generate_sigma.py — Build Sigma rules from provider inventory and conservative detection feeds.
"""

from __future__ import annotations

import argparse
import csv
import re
import uuid
from collections import defaultdict
from datetime import date
from pathlib import Path

from data_model import ROOT

PROVIDER_RANGES_CSV = ROOT / "generated" / "detection" / "provider-ranges.csv"
HIGH_RISK_CSV = ROOT / "generated" / "detection" / "high-risk-cidrs.csv"
INCIDENT_IOCS_CSV = ROOT / "generated" / "detection" / "incident-iocs.csv"
OUT_DIR = ROOT / "queries" / "sigma"

AUTHOR = "windshock"
REPO_URL = "https://github.com/windshock/anonymous-vps"
TODAY = date.today().isoformat()
MITRE_TAGS = [
    "attack.command_and_control",
    "attack.t1090",
    "attack.t1583.003",
]


def vendor_slug(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-")


def load_provider_ranges(vendor_filter: str | None) -> dict[str, dict[str, list[str] | str]]:
    data: dict[str, dict[str, list[str] | str]] = defaultdict(lambda: {"asn": "", "cidrs": []})
    if not PROVIDER_RANGES_CSV.exists():
        return {}
    with open(PROVIDER_RANGES_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            vendor = row["vendor"].strip()
            if vendor_filter and vendor.lower() != vendor_filter.lower():
                continue
            data[vendor]["asn"] = row["asn"].strip()
            data[vendor]["cidrs"].append(row["cidr"].strip())
    return dict(data)


def load_high_risk_cidrs() -> list[str]:
    if not HIGH_RISK_CSV.exists():
        return []
    with open(HIGH_RISK_CSV, newline="", encoding="utf-8") as handle:
        return [row["cidr"].strip() for row in csv.DictReader(handle) if row.get("cidr", "").strip()]


def load_incident_iocs() -> list[str]:
    if not INCIDENT_IOCS_CSV.exists():
        return []
    with open(INCIDENT_IOCS_CSV, newline="", encoding="utf-8") as handle:
        return [row["ioc"].strip() for row in csv.DictReader(handle) if row.get("ioc", "").strip()]


def sigma_rule(
    title: str,
    rule_id: str,
    description: str,
    references: list[str],
    level: str,
    cidrs: list[str] | None = None,
    ips: list[str] | None = None,
) -> str:
    tags_lines = "\n".join(f"    - {tag}" for tag in MITRE_TAGS)
    references_lines = "\n".join(f"    - {ref}" for ref in references)
    detection_lines: list[str] = []
    condition_parts: list[str] = []

    if ips:
        ip_lines = "\n".join(f"            - '{value}'" for value in sorted(set(ips)))
        detection_lines.append("    selection_iocs:\n        dst_ip:\n" + ip_lines)
        condition_parts.append("selection_iocs")
    if cidrs:
        cidr_lines = "\n".join(f"            - '{value}'" for value in sorted(set(cidrs)))
        detection_lines.append("    selection_cidrs:\n        dst_ip|cidr:\n" + cidr_lines)
        condition_parts.append("selection_cidrs")

    condition = " or ".join(condition_parts) if condition_parts else "selection_none"
    detection_block = (
        "\n".join(detection_lines)
        if detection_lines
        else "    selection_none:\n        dst_ip:\n            - '127.0.0.1'"
    )

    return f"""\
title: {title}
id: {rule_id}
status: experimental
description: {description}
references:
{references_lines}
author: {AUTHOR}
date: {TODAY}
modified: {TODAY}
tags:
{tags_lines}
logsource:
    category: firewall
    product: any
detection:
{detection_block}
    condition: {condition}
falsepositives:
    - Legitimate security research and authorized infrastructure testing
    - Internal cloud workloads intentionally using the listed providers
fields:
    - dst_ip
    - src_ip
    - dst_port
    - proto
level: {level}
"""


def write_rule(path: Path, content: str, dry_run: bool) -> None:
    if dry_run:
        print(f"\n{'=' * 60}\n[{path.name}]\n{content[:700]}…")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def provider_rule(vendor: str, asn: str, cidrs: list[str]) -> str:
    return sigma_rule(
        title=f"Network Connection to Anonymous VPS Provider Inventory — {vendor}",
        rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"anonymous-vps-provider-{vendor_slug(vendor)}")),
        description=(
            f"Detects outbound network connections to provider inventory ranges associated with "
            f"anonymous or crypto-friendly hosting provider '{vendor}' ({asn}). "
            "This is a broad hunting rule, not a malicious-infrastructure verdict."
        ),
        references=[
            REPO_URL,
            f"{REPO_URL}/blob/main/generated/detection/provider-ranges.csv",
        ],
        level="medium",
        cidrs=cidrs,
    )


def detection_rule(title: str, key: str, description: str, references: list[str], cidrs: list[str], ips: list[str]) -> str:
    return sigma_rule(
        title=title,
        rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, key)),
        description=description,
        references=references,
        level="high",
        cidrs=cidrs,
        ips=ips,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Sigma rules from detection feeds")
    parser.add_argument("--vendor", metavar="NAME", help="Filter provider inventory rules to a single provider")
    parser.add_argument("--dry-run", action="store_true", help="Print rules instead of writing files")
    args = parser.parse_args()

    provider_ranges = load_provider_ranges(args.vendor)
    high_risk_cidrs = load_high_risk_cidrs()
    incident_iocs = load_incident_iocs()

    if not provider_ranges and not high_risk_cidrs and not incident_iocs:
        raise SystemExit("❌ No generated detection inputs found. Run the pipeline first.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    all_provider_cidrs: list[str] = []
    for vendor, info in sorted(provider_ranges.items()):
        cidrs = list(info["cidrs"])
        all_provider_cidrs.extend(cidrs)
        write_rule(
            OUT_DIR / f"{vendor_slug(vendor)}.yml",
            provider_rule(vendor, str(info["asn"]), cidrs),
            args.dry_run,
        )

    if all_provider_cidrs:
        write_rule(
            OUT_DIR / "all-vendors.yml",
            sigma_rule(
                title="Network Connection to Anonymous VPS Provider Inventory",
                rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "anonymous-vps-provider-inventory-all")),
                description=(
                    "Detects outbound network connections to the broad provider inventory maintained "
                    "by the anonymous-vps repository. Use for hunting, not direct blocking."
                ),
                references=[
                    REPO_URL,
                    f"{REPO_URL}/blob/main/generated/detection/provider-ranges.csv",
                ],
                level="medium",
                cidrs=all_provider_cidrs,
            ),
            args.dry_run,
        )

    if high_risk_cidrs:
        write_rule(
            OUT_DIR / "high-risk-cidrs.yml",
            detection_rule(
                title="Network Connection to High-Risk Anonymous VPS CIDR",
                key="anonymous-vps-high-risk-cidrs",
                description=(
                    "Detects outbound network connections to generalized anonymous VPS CIDRs that "
                    "cleared the repository's conservative promotion policy."
                ),
                references=[
                    REPO_URL,
                    f"{REPO_URL}/blob/main/generated/detection/high-risk-cidrs.csv",
                ],
                cidrs=high_risk_cidrs,
                ips=[],
            ),
            args.dry_run,
        )

    if incident_iocs:
        write_rule(
            OUT_DIR / "incident-iocs.yml",
            detection_rule(
                title="Network Connection to Anonymous VPS Incident IOC",
                key="anonymous-vps-incident-iocs",
                description=(
                    "Detects outbound network connections to exact IOC IPs observed in public reports "
                    "and incident records tied to anonymous VPS or hosting infrastructure."
                ),
                references=[
                    REPO_URL,
                    f"{REPO_URL}/blob/main/generated/detection/incident-iocs.csv",
                ],
                cidrs=[],
                ips=incident_iocs,
            ),
            args.dry_run,
        )

    if high_risk_cidrs or incident_iocs:
        write_rule(
            OUT_DIR / "all-detection.yml",
            detection_rule(
                title="Network Connection to Anonymous VPS Detection Set",
                key="anonymous-vps-all-detection",
                description=(
                    "Detects outbound network connections to the repository's conservative detection "
                    "set, combining exact incident IOCs with high-risk generalized CIDRs."
                ),
                references=[
                    REPO_URL,
                    f"{REPO_URL}/blob/main/generated/detection/high-risk-cidrs.csv",
                    f"{REPO_URL}/blob/main/generated/detection/incident-iocs.csv",
                ],
                cidrs=high_risk_cidrs,
                ips=incident_iocs,
            ),
            args.dry_run,
        )

    if not args.dry_run:
        print(f"✅ Sigma rules written → {OUT_DIR}")


if __name__ == "__main__":
    main()
