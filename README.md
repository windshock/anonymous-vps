# Anonymous VPS Intelligence

A curated defensive repository for tracking anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting.

The repository is intentionally detection-first:

- `provider inventory` is kept for context and hunting
- `incident IOC` stays at `/32` when evidence is narrow
- `high-risk CIDR` is only promoted when range-level generalization is justified

This repository does not label all VPS providers as malicious. It separates:

- providers that offer anonymous or crypto-friendly infrastructure
- exact IOC IPs seen in incidents
- generalized CIDRs that cleared a conservative promotion policy

## Repository Model

Source of truth:

- `data/providers.yml`
- `data/asns.yml`
- `data/cidrs.yml`
- `data/incidents/*.yml`

Generated outputs:

- `generated/detection/provider-ranges.csv`
- `generated/detection/high-risk-cidrs.csv`
- `generated/detection/incident-iocs.csv`
- `generated/legacy/providers-bridge.csv`
- `data/vps-providers.csv`
- `data/ip-ranges/known-providers.csv`

The `*.yml` files are stored as JSON-compatible YAML so the scripts can parse them without external dependencies.

## Detection Outputs

Primary detection inputs:

- `generated/detection/incident-iocs.csv`
  - exact IPs from public incident reporting
  - safest starting point for blocking or high-confidence alerting
- `generated/detection/high-risk-cidrs.csv`
  - generalized CIDRs that cleared the repo's conservative policy
  - intended for broader detection once range-level evidence exists

Context / hunting input:

- `generated/detection/provider-ranges.csv`
  - provider inventory ranges derived from linked ASNs
  - useful for hunting and enrichment
  - not a malicious-infrastructure verdict by itself

## Status Model

Providers:

- `provider_verified`
- `candidate`
- `rejected`

ASNs:

- `candidate`
- `abuse_candidate`
- `rejected`

CIDRs:

- `candidate`
- `abuse_candidate`
- `campaign_observed`
- `rejected`

Incident IOCs:

- `ioc_only`
- `campaign_observed`

## Conservative Promotion Rules

- A single IOC remains `/32`
- A single report does not justify `/24` promotion
- `provider inventory` and `high-risk CIDR` are separate outputs
- ASN is used for context and linking, not as the default detection unit
- Automatic collection results are not auto-merged

## Queries

Broad hunting queries:

- `queries/logpresso/all-vendors.logpresso`
- `queries/logpresso/all-vendors-vpn.logpresso`
- `queries/sigma/all-vendors.yml`

Conservative detection queries:

- `queries/logpresso/all-detection.logpresso`
- `queries/logpresso/all-detection-vpn.logpresso`
- `queries/logpresso/incident-iocs.logpresso`
- `queries/sigma/all-detection.yml`
- `queries/sigma/incident-iocs.yml`

Per-provider Logpresso and Sigma files are still generated from `provider-ranges.csv` for hunting workflows.

## Pipeline

```bash
# Full pipeline
python3 scripts/pipeline.py

# Skip ASN download
python3 scripts/pipeline.py --skip-fetch

# Single provider query/rule regeneration
python3 scripts/pipeline.py --skip-fetch --vendor BitLaunch

# Validate source data only
python3 scripts/validate_data.py
```

Pipeline stages:

1. `fetch_asn.py`
2. `validate_data.py`
3. `generate_legacy_bridge.py`
4. `generate_provider_ranges.py`
5. `generate_incident_iocs.py`
6. `generate_high_risk_cidrs.py`
7. `generate_queries.py`
8. `generate_sigma.py`

## Current Seed Examples

- `GhostVPS`
  - provider record only
  - official site confirms VPS service and crypto payments
- `AS48090`
  - tracked as ASN context with abuse-related public telemetry
- `83.142.209.0/24`
  - retained as `candidate`, not promoted into `high-risk-cidrs.csv`
- `83.142.209.11`, `45.148.10.212`, `142.11.206.73`
  - retained as incident IOC `/32` entries

## Policy

- [policy.md](docs/policy.md)
- [review-checklist.md](docs/review-checklist.md)

## Disclaimer

This repository is for defensive security research, detection engineering, and threat hunting. It must not be used to justify blanket blocking of an entire provider without validating operational impact and additional context.
