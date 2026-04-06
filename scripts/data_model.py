#!/usr/bin/env python3
"""
data_model.py — JSON-compatible YAML loaders and helpers for the slim intel model.

The repository stores *.yml files in JSON-compatible YAML so the scripts can
parse them without external dependencies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
GENERATED_DIR = ROOT / "generated"

PROVIDERS_FILE = DATA_DIR / "providers.yml"
ASNS_FILE = DATA_DIR / "asns.yml"
CIDRS_FILE = DATA_DIR / "cidrs.yml"
INCIDENTS_DIR = DATA_DIR / "incidents"

SLUG_RE = re.compile(r"[^a-z0-9]+")


def load_json_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"❌ {path}: expected JSON-compatible YAML (JSON subset). {exc}"
        ) from exc


def load_providers() -> list[dict[str, Any]]:
    return load_json_yaml(PROVIDERS_FILE)


def load_asns() -> list[dict[str, Any]]:
    return load_json_yaml(ASNS_FILE)


def load_cidrs() -> list[dict[str, Any]]:
    return load_json_yaml(CIDRS_FILE)


def load_incidents() -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    if not INCIDENTS_DIR.exists():
        return incidents
    for path in sorted(INCIDENTS_DIR.glob("*.yml")):
        record = load_json_yaml(path)
        record["_path"] = str(path.relative_to(ROOT))
        incidents.append(record)
    return incidents


def slugify(value: str) -> str:
    return SLUG_RE.sub("-", value.lower()).strip("-")


def primary_domain(provider: dict[str, Any]) -> str:
    bridge = provider.get("bridge", {})
    if bridge.get("domain"):
        return bridge["domain"]
    domains = provider.get("domains", [])
    return domains[0] if domains else ""


def build_provider_index(providers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {provider["provider_id"]: provider for provider in providers}


def build_asn_index(asns: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["asn"].upper(): record for record in asns}


def provider_asn_map(asns: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = {}
    for record in asns:
        provider_id = record.get("provider_id")
        if not provider_id:
            continue
        mapping.setdefault(provider_id, []).append(record)
    return mapping


def choose_primary_asn(asn_records: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not asn_records:
        return None
    ranked = sorted(
        asn_records,
        key=lambda item: (
            0
            if item.get("relationship") == "owned_by_provider"
            else 1
            if item.get("relationship") == "used_by_provider"
            else 2,
            item["asn"],
        ),
    )
    return ranked[0]


def asn_link(asn: str) -> str:
    if not asn:
        return ""
    return f"https://bgp.tools/asn/{asn.lstrip('AS')}"
