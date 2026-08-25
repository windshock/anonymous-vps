# Anonymous VPS Intelligence

A curated defensive repository for tracking anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting.

> **What's new (2026-08)**
> - Data model now keeps **four separate evidence layers** (provider inventory · ASN relationship · CIDR location context · incident/high-risk detection) — crypto payment alone qualifies a provider for inventory, never for detection.
> - New **CIDR location-context** layer + isolated artifact `generated/context/kr-localized-cidrs.csv` (tags `kr-localized`, `geo-mismatch-candidate`), deliberately kept out of every detection output.
> - Provider identity corrected: **Datacamp Limited** (`datacamp.co.uk`, owns AS212238) is separated from the crypto-payment `coin-host` provider record; verified `coin-host` and `evoxt` added with no ASN.
> - Tooling: validator split into focused modules + an offline `pytest` harness (dev-only; runtime stays dependency-free); pipeline `--dry-run` now writes nothing.
>
> Full details in [CHANGELOG.md](CHANGELOG.md).

The repository is intentionally detection-first:

- `provider inventory` is kept for context and hunting
- `incident IOC` stays at `/32` when evidence is narrow
- `high-risk CIDR` is only promoted when range-level generalization is justified

This repository does not label all VPS providers as malicious. It keeps **four
separate evidence layers** so that one fact never silently implies another:

1. **provider inventory** — crypto-friendly and/or privacy-focused hosting kept for
   context and hunting. Cryptocurrency payment support alone can qualify a provider
   for inventory inclusion, but it is **never** grounds for a malicious / high-risk
   detection verdict.
2. **ASN relationship** — which ASN a provider owns or uses (linking/context, not a
   detection unit). Reselling another operator's cloud does not transfer ASN ownership.
3. **CIDR location context** — registry country plus advertised/observed location.
   A registry country is not proof of physical server location; it is hunting context.
4. **incident / high-risk detection** — exact IOC IPs and generalized CIDRs that
   cleared a conservative promotion policy.

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
- `generated/context/kr-localized-cidrs.csv`
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

## Location Context

- `generated/context/kr-localized-cidrs.csv`
  - registry/geolocation context for country-localized allocations (currently KR)
  - fields: `cidr, provider_id, vendor, asn, status, tags, registry_country,
    advertised_location, observed_location, observed_at, summary, evidence_types, source_urls`
  - controlled tags:
    - `kr-localized` — the block is registered/advertised inside Korea
    - `geo-mismatch-candidate` — a *dated* active-geolocation observation differs from
      the registry country (`observed_location` + `observed_at`); a time-bound
      measurement, not proof of deception or of a permanent physical location
  - registry country and active-location evidence are **non-authoritative and
    time-bound**; a registry country never proves the physical server location
  - **detection-exclusion rule:** location-context rows are hunting/enrichment only.
    They are deliberately kept out of `high-risk-cidrs.csv`, the incident IOC set,
    and every Sigma / Logpresso detection rule. A location tag alone never promotes a
    block to high-risk detection.

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

## Data Sources

### ASN IP 대역 — sapics/ip-location-db

- Repository: https://github.com/sapics/ip-location-db
- File: `data/asn-ipv4.csv` (자동 다운로드)
- Format: `ip_range_start, ip_range_end, asn_number, org_name`
- Update: 매주 자동 갱신 (GitHub Actions)
- Origin: RouteViews + DB-IP + 5개 RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC)

ASN → IP 대역 변환과 **ASN 소유자 검증**에 사용됩니다.
`validate_data.py`가 `asns.yml` 등록 시 sapics 대조를 통해 오귀속을 자동 차단합니다.

### 공급자 목록 — 수동 연구

`data/providers.yml`의 공급자 목록은 외부 자동 수집 소스가 없습니다.
위협 인텔리전스 보고서, LLM 보조 검색, 사고 분석을 통해 사람이 직접 추가합니다.

## Pipeline

```
[사람/LLM 연구]        [sapics/ip-location-db]
providers.yml    +      asn-ipv4.csv (매주 갱신)
asns.yml
cidrs.yml
incidents/*.yml
        │                    │
        └────────┬───────────┘
                 ▼
         validate_data.py
         (형식 검증 + sapics ASN 오귀속 검출)
                 │
    ┌────────────┼──────────────────────┐
    ▼            ▼                      ▼
vps-providers  known-providers.csv  generated/detection/
.csv                                provider-ranges.csv
                                    high-risk-cidrs.csv
                                    incident-iocs.csv
                                         │
                                queries/logpresso/
                                queries/sigma/
```

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

1. `fetch_asn.py` — sapics에서 최신 ASN IP 대역 다운로드
2. `validate_data.py` — 형식 검증 + sapics ASN 소유자 대조
3. `generate_legacy_bridge.py`
4. `generate_provider_ranges.py`
5. `generate_incident_iocs.py`
6. `generate_high_risk_cidrs.py`
7. `generate_location_context.py` — KR location-context CSV (isolated from detection)
8. `generate_queries.py`
9. `generate_sigma.py`

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
