#!/usr/bin/env python3
"""
validate_data.py — stable CLI entry point for validating the slim intel data model.

The validation logic lives in focused modules:
    - validation_common.py — controlled vocabularies + evidence helpers
    - validate_asn.py       — ASN ownership (sapics) + ASN record checks
    - validate_records.py   — provider / CIDR / incident record checks

This file only loads data, orchestrates those validators, and prints the report.
"""

from __future__ import annotations

import argparse
import sys

from data_model import (
    build_asn_index,
    build_provider_index,
    load_asns,
    load_cidrs,
    load_incidents,
    load_providers,
)
from validate_asn import load_sapics_asn_orgs, validate_asn_ownership, validate_asns
from validate_records import validate_cidrs, validate_incidents, validate_providers

# Re-exported for backwards compatibility with any importer of these names.
from validation_common import is_http_url, validate_evidence, validate_references  # noqa: F401


def collect() -> tuple[list[str], list[str], dict[str, int]]:
    providers = load_providers()
    asns = load_asns()
    cidrs = load_cidrs()
    incidents = load_incidents()

    provider_index = build_provider_index(providers)
    asn_index = build_asn_index(asns)

    errors: list[str] = []
    warnings: list[str] = []

    def merge(result: tuple[list[str], list[str]]) -> None:
        errors.extend(result[0])
        warnings.extend(result[1])

    merge(validate_providers(providers))
    merge(validate_asn_ownership(asns, provider_index, load_sapics_asn_orgs()))
    merge(validate_asns(asns, provider_index))
    merge(validate_cidrs(cidrs, provider_index, asn_index))
    merge(validate_incidents(incidents, provider_index, asn_index))

    counts = {
        "providers": len(providers),
        "asns": len(asns),
        "cidrs": len(cidrs),
        "incidents": len(incidents),
    }
    return errors, warnings, counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate intelligence data files")
    parser.add_argument("--quiet", action="store_true", help="Only print errors")
    args = parser.parse_args()

    errors, warnings, counts = collect()

    if warnings and not args.quiet:
        print(f"⚠️  {len(warnings)} warning(s):")
        for warning in warnings:
            print(f"   {warning}")

    if errors:
        print(f"❌ Validation failed with {len(errors)} issue(s):")
        for error in errors:
            print(f"   {error}")
        sys.exit(1)

    if not args.quiet:
        print("✅ Data validation passed")
        print(f"   providers : {counts['providers']}")
        print(f"   asns      : {counts['asns']}")
        print(f"   cidrs     : {counts['cidrs']}")
        print(f"   incidents : {counts['incidents']}")


if __name__ == "__main__":
    main()
