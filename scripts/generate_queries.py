#!/usr/bin/env python3
"""
generate_queries.py — Build Logpresso queries from provider inventory and detection feeds.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from pathlib import Path

from data_model import ROOT

PROVIDER_RANGES_CSV = ROOT / "generated" / "detection" / "provider-ranges.csv"
HIGH_RISK_CSV = ROOT / "generated" / "detection" / "high-risk-cidrs.csv"
INCIDENT_IOCS_CSV = ROOT / "generated" / "detection" / "incident-iocs.csv"
OUT_DIR = ROOT / "queries" / "logpresso"


def vendor_slug(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-")


def cidr_to_filter(cidr: str, ip_field: str) -> str:
    network = ipaddress.IPv4Network(cidr, strict=False)
    return f'network({ip_field},{network.prefixlen}) == "{network.network_address}"'


def ip_to_filter(ip_value: str, ip_field: str) -> str:
    return f'{ip_field} == "{ip_value}"'


def build_search_clause(cidrs: list[str], ips: list[str], ip_field: str) -> str:
    clauses = [ip_to_filter(ip_value, ip_field) for ip_value in sorted(set(ips))]
    clauses.extend(cidr_to_filter(cidr, ip_field) for cidr in sorted(set(cidrs)))
    return " or ".join(clauses)


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


VPN_TMPL = """\
## {title}
## source: {source}
## indicators: {indicator_count}

fulltext "New" and "session" and "client" from *:SYS_VPN
  | rex field=line "New session from client IP (?<client_ip>[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}})"
  | search {search_clause}
"""

FW_TMPL = """\
## {title}
## source: {source}
## indicators: {indicator_count}

{search_clause}
"""


def write_text(path: Path, text: str, dry_run: bool) -> None:
    if dry_run:
        print(f"\n{'=' * 60}\n[{path.name}]\n{text[:700]}…")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_query(title: str, source: str, cidrs: list[str], ips: list[str], vpn: bool) -> str:
    ip_field = "client_ip" if vpn else "dst_ip"
    search_clause = build_search_clause(cidrs, ips, ip_field)
    indicator_count = len(set(cidrs)) + len(set(ips))
    template = VPN_TMPL if vpn else FW_TMPL
    return template.format(
        title=title,
        source=source,
        indicator_count=indicator_count,
        search_clause=search_clause,
    )


def write_detection_queries(high_risk_cidrs: list[str], incident_iocs: list[str], dry_run: bool) -> None:
    if high_risk_cidrs:
        write_text(
            OUT_DIR / "high-risk.logpresso",
            make_query(
                "high-risk-cidrs — generalized anonymous VPS CIDR detections",
                "generated/detection/high-risk-cidrs.csv",
                high_risk_cidrs,
                [],
                vpn=False,
            ),
            dry_run,
        )
        write_text(
            OUT_DIR / "high-risk-vpn.logpresso",
            make_query(
                "high-risk-cidrs — VPN inbound detections",
                "generated/detection/high-risk-cidrs.csv",
                high_risk_cidrs,
                [],
                vpn=True,
            ),
            dry_run,
        )

    if incident_iocs:
        write_text(
            OUT_DIR / "incident-iocs.logpresso",
            make_query(
                "incident-iocs — exact IP detections",
                "generated/detection/incident-iocs.csv",
                [],
                incident_iocs,
                vpn=False,
            ),
            dry_run,
        )
        write_text(
            OUT_DIR / "incident-iocs-vpn.logpresso",
            make_query(
                "incident-iocs — VPN inbound exact IP detections",
                "generated/detection/incident-iocs.csv",
                [],
                incident_iocs,
                vpn=True,
            ),
            dry_run,
        )

    combined_cidrs = sorted(set(high_risk_cidrs))
    combined_ips = sorted(set(incident_iocs))
    if combined_cidrs or combined_ips:
        write_text(
            OUT_DIR / "all-detection.logpresso",
            make_query(
                "all-detection — conservative anonymous VPS detection set",
                "generated/detection/high-risk-cidrs.csv + generated/detection/incident-iocs.csv",
                combined_cidrs,
                combined_ips,
                vpn=False,
            ),
            dry_run,
        )
        write_text(
            OUT_DIR / "all-detection-vpn.logpresso",
            make_query(
                "all-detection — conservative VPN inbound detection set",
                "generated/detection/high-risk-cidrs.csv + generated/detection/incident-iocs.csv",
                combined_cidrs,
                combined_ips,
                vpn=True,
            ),
            dry_run,
        )


def write_provider_queries(vendor_data: dict[str, dict[str, list[str] | str]], dry_run: bool) -> None:
    all_cidrs: list[str] = []
    for vendor, info in sorted(vendor_data.items()):
        asn = str(info["asn"])
        cidrs = list(info["cidrs"])
        slug = vendor_slug(vendor)
        write_text(
            OUT_DIR / f"{slug}.logpresso",
            make_query(
                f"{vendor} — provider inventory outbound hunt ({asn})",
                "generated/detection/provider-ranges.csv",
                cidrs,
                [],
                vpn=False,
            ),
            dry_run,
        )
        write_text(
            OUT_DIR / f"{slug}-vpn.logpresso",
            make_query(
                f"{vendor} — provider inventory VPN inbound hunt ({asn})",
                "generated/detection/provider-ranges.csv",
                cidrs,
                [],
                vpn=True,
            ),
            dry_run,
        )
        all_cidrs.extend(cidrs)

    if all_cidrs:
        write_text(
            OUT_DIR / "all-vendors.logpresso",
            make_query(
                "all-vendors — broad provider inventory hunt",
                "generated/detection/provider-ranges.csv",
                all_cidrs,
                [],
                vpn=False,
            ),
            dry_run,
        )
        write_text(
            OUT_DIR / "all-vendors-vpn.logpresso",
            make_query(
                "all-vendors — broad provider inventory VPN hunt",
                "generated/detection/provider-ranges.csv",
                all_cidrs,
                [],
                vpn=True,
            ),
            dry_run,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Logpresso queries from detection feeds")
    parser.add_argument("--vendor", metavar="NAME", help="Filter provider inventory queries to a single provider")
    parser.add_argument("--dry-run", action="store_true", help="Print queries instead of writing files")
    args = parser.parse_args()

    provider_ranges = load_provider_ranges(args.vendor)
    high_risk_cidrs = load_high_risk_cidrs()
    incident_iocs = load_incident_iocs()

    if not provider_ranges and not high_risk_cidrs and not incident_iocs:
        raise SystemExit("❌ No generated detection inputs found. Run the pipeline first.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_provider_queries(provider_ranges, args.dry_run)
    write_detection_queries(high_risk_cidrs, incident_iocs, args.dry_run)

    if not args.dry_run:
        print(f"✅ Queries written → {OUT_DIR}")


if __name__ == "__main__":
    main()
