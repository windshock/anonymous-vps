#!/usr/bin/env python3
"""
generate_location_context.py — Emit the KR location-context CSV, DB-driven.

Instead of hand-picking CIDRs, this intersects the IP ranges of the ASNs we
already track (owned/used by tracked providers) with the GeoLite2 country
database from sapics/ip-location-db. Every range that geolocates to the target
country (KR) is emitted objectively — no sampling, no manual selection.

The artifact is deliberately kept OUT of generated/detection/ and out of the
Sigma / Logpresso generators. It is hunting/enrichment context, never a
detection or high-risk verdict. A geolocation country is not proof of physical
server location.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import ipaddress
import sys
from pathlib import Path

from data_model import ROOT, build_provider_index, load_asns, load_providers

COUNTRY = "KR"
ASN_DB = ROOT / "data" / "asn-ipv4.csv"
COUNTRY_DB = ROOT / "data" / "country-ipv4.csv"
OUT_FILE = ROOT / "generated" / "context" / "kr-localized-cidrs.csv"
SOURCE = "sapics/ip-location-db geolite2-country"

FIELDNAMES = ["cidr", "provider_id", "vendor", "asn", "geo_country", "source"]

# Only ASNs a provider owns or uses are inventory; candidate_link/unknown are excluded.
ELIGIBLE_RELATIONSHIPS = {"owned_by_provider", "used_by_provider"}


def tracked_asn_map(asns: list[dict], provider_index: dict) -> dict[str, tuple[str, str, str]]:
    """asn_num -> (asn_str, provider_id, vendor) for owned/used ASNs."""
    tracked: dict[str, tuple[str, str, str]] = {}
    for record in asns:
        if record.get("relationship") not in ELIGIBLE_RELATIONSHIPS:
            continue
        asn_str = record["asn"].upper()
        num = asn_str.lstrip("AS")
        provider_id = record.get("provider_id") or ""
        vendor = provider_index.get(provider_id, {}).get("name", "") if provider_id else ""
        tracked[num] = (asn_str, provider_id, vendor)
    return tracked


def load_country_intervals(path: Path, country: str) -> list[tuple[int, int]]:
    """Sorted, disjoint (start_int, end_int) intervals for a single country code."""
    intervals: list[tuple[int, int]] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.reader(handle):
            if len(row) < 3 or row[2].strip() != country:
                continue
            try:
                start = int(ipaddress.IPv4Address(row[0].strip()))
                end = int(ipaddress.IPv4Address(row[1].strip()))
            except ValueError:
                continue
            intervals.append((start, end))
    intervals.sort()
    return intervals


def load_asn_intervals(path: Path, tracked: set[str]):
    """Yield (start_int, end_int, asn_num) for tracked ASNs only."""
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.reader(handle):
            if len(row) < 3:
                continue
            num = row[2].strip()
            if num not in tracked:
                continue
            try:
                yield (int(ipaddress.IPv4Address(row[0].strip())),
                       int(ipaddress.IPv4Address(row[1].strip())), num)
            except ValueError:
                continue


def _overlaps(start: int, end: int, starts: list[int], ends: list[int]) -> list[tuple[int, int]]:
    """Overlaps of [start,end] with disjoint sorted country intervals."""
    out: list[tuple[int, int]] = []
    i = bisect.bisect_left(ends, start)  # first interval whose end >= start
    n = len(starts)
    while i < n and starts[i] <= end:
        lo, hi = max(start, starts[i]), min(end, ends[i])
        if lo <= hi:
            out.append((lo, hi))
        i += 1
    return out


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent (start,end) integer intervals."""
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged = [intervals[0]]
    for lo, hi in intervals[1:]:
        if lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def kr_localized_rows(
    tracked: dict[str, tuple[str, str, str]],
    asn_intervals,
    country_intervals: list[tuple[int, int]],
    country: str = COUNTRY,
) -> list[dict[str, str]]:
    """Pure core: intersect tracked ASN ranges with country intervals -> CSV rows."""
    starts = [s for s, _ in country_intervals]
    ends = [e for _, e in country_intervals]
    per_asn: dict[str, list[tuple[int, int]]] = {}
    for start, end, num in asn_intervals:
        for lo, hi in _overlaps(start, end, starts, ends):
            per_asn.setdefault(num, []).append((lo, hi))

    rows: list[dict[str, str]] = []
    for num, ivs in per_asn.items():
        asn_str, provider_id, vendor = tracked[num]
        for lo, hi in _merge(ivs):
            for net in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
            ):
                rows.append(
                    {
                        "cidr": str(net),
                        "provider_id": provider_id,
                        "vendor": vendor,
                        "asn": asn_str,
                        "geo_country": country,
                        "source": SOURCE,
                    }
                )
    return sorted(
        rows,
        key=lambda r: (int(ipaddress.IPv4Address(r["cidr"].split("/")[0])), int(r["cidr"].split("/")[1])),
    )


def build_rows(asn_db: Path = ASN_DB, country_db: Path = COUNTRY_DB, country: str = COUNTRY) -> list[dict[str, str]]:
    if not Path(asn_db).exists():
        raise SystemExit(f"❌ ASN DB not found: {asn_db} (run scripts/fetch_asn.py)")
    if not Path(country_db).exists():
        raise SystemExit(f"❌ Country DB not found: {country_db} (run scripts/fetch_asn.py)")
    tracked = tracked_asn_map(load_asns(), build_provider_index(load_providers()))
    if not tracked:
        return []
    country_intervals = load_country_intervals(country_db, country)
    asn_intervals = load_asn_intervals(asn_db, set(tracked))
    return kr_localized_rows(tracked, asn_intervals, country_intervals, country)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the DB-driven KR location-context CSV")
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
    print(f"✅ Generated {len(rows)} {COUNTRY}-localized location-context rows → {OUT_FILE}")


if __name__ == "__main__":
    main()
