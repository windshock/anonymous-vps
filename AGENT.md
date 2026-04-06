# AGENT.md — Anonymous VPS Intelligence

## Purpose

This repository tracks anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting and makes the result usable for detection engineering.

The repository is not a blanket malicious-provider list.

## Source Of Truth

Edit these files directly:

- `data/providers.yml`
- `data/asns.yml`
- `data/cidrs.yml`
- `data/incidents/*.yml`

These files use JSON-compatible YAML to avoid external parser dependencies.

## Generated Files

Do not edit these directly:

- `generated/detection/provider-ranges.csv`
- `generated/detection/high-risk-cidrs.csv`
- `generated/detection/incident-iocs.csv`
- `generated/legacy/providers-bridge.csv`
- `data/vps-providers.csv`
- `data/ip-ranges/known-providers.csv`
- `queries/logpresso/*.logpresso`
- `queries/sigma/*.yml`

## Data Roles

- `providers.yml`
  - anonymous or crypto-friendly provider inventory
  - context only
- `asns.yml`
  - linking / context layer between providers and infrastructure
  - not the default detection unit
- `cidrs.yml`
  - generalized CIDRs with explicit status and scope
- `incidents/*.yml`
  - exact IOC observations and incident references

## Status Rules

- Keep `/32` if evidence is limited to one IOC or one report
- Promote to generalized CIDR only when range-level evidence is defensible
- Keep `provider inventory` separate from `high-risk detection`
- Do not treat provider presence as proof of malicious activity

## Commands

```bash
# Full rebuild
python3 scripts/pipeline.py

# Skip ASN fetch
python3 scripts/pipeline.py --skip-fetch

# Validate source data
python3 scripts/validate_data.py

# Rebuild legacy bridge only
python3 scripts/generate_legacy_bridge.py

# Rebuild provider inventory ranges
python3 scripts/generate_provider_ranges.py

# Rebuild incident IOC CSV
python3 scripts/generate_incident_iocs.py

# Rebuild high-risk CIDR CSV
python3 scripts/generate_high_risk_cidrs.py
```

`--vendor` should be used with query/rule generation or with `--dry-run` inspection only. Aggregate CSV generators refuse filtered overwrite mode.

## Review Expectations

Each new record should include:

- a clear status
- a short summary
- at least one evidence item or reference
- a source URL whenever available

Do not promote `/24` or broader ranges from a single IOC without additional independent support.
