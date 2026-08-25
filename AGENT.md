# AGENT.md — Anonymous VPS Intelligence

## Purpose

This repository tracks anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting and makes the result usable for detection engineering.

The repository is not a blanket malicious-provider list.

## External Data Sources

### sapics/ip-location-db (ASN IP 대역)

- URL: https://github.com/sapics/ip-location-db
- 파일: `data/asn-ipv4.csv` + `data/country-ipv4.csv` (fetch_asn.py가 자동 다운로드)
- 포맷: ASN `ip_range_start, ip_range_end, asn_number, org_name` /
  국가 `ip_range_start, ip_range_end, country_code`
- 갱신: 매주 GitHub Actions (`update-asn.yml`)
- 역할: **ASN 번호 → IP 대역 + 공식 등록 org명** 제공
- 출처: RouteViews(2시간) + DB-IP(월간) + 5개 RIR(ARIN/RIPE/APNIC 등)

이 파일은 `generate_provider_ranges.py`가 `asns.yml`의 ASN을 실제 IP 대역으로 변환할 때 사용하며,
`validate_data.py`가 ASN 오귀속(재판매 업체를 대형 클라우드 ASN에 연결하는 등)을 자동으로 검출할 때도 사용합니다.

### 공급자 목록 (providers.yml)

공급자 목록은 외부 자동 수집 소스가 없습니다.
LLM 보조 검색, 위협 인텔리전스 보고서, 사고 분석 등을 통해 **사람이 직접 연구하여 추가**합니다.
각 항목에는 evidence(근거)와 출처 URL을 반드시 포함해야 합니다.

## Data Flow

```
[사람/LLM 연구]          [sapics GitHub — 매주 자동 갱신]
providers.yml                  asn-ipv4.csv
asns.yml          +       (IP대역↔ASN↔공식org명)
cidrs.yml
incidents/*.yml
       │                        │
       └──────────┬─────────────┘
                  ▼
          validate_data.py
          (형식 검증 + sapics 대조 → ASN 오귀속 차단)
                  │
       ┌──────────┼────────────────────────┐
       ▼          ▼                        ▼
 vps-providers  known-providers.csv   generated/detection/
 .csv           (IP 대역 목록)        provider-ranges.csv
                                      high-risk-cidrs.csv
                                      incident-iocs.csv
                                           │
                                  queries/logpresso/*.logpresso
                                  queries/sigma/*.yml
```

## Source Of Truth

Edit these files directly:

- `data/providers.yml` — 공급자 인벤토리 (사람이 연구하여 추가)
- `data/asns.yml` — ASN 연결 레이어 (sapics 대조 검증 필수)
- `data/cidrs.yml` — 명시적 CIDR
- `data/incidents/*.yml` — 사고별 IOC

These files use JSON-compatible YAML to avoid external parser dependencies.

## Generated Files

Do not edit these directly:

- `generated/detection/provider-ranges.csv`
- `generated/detection/high-risk-cidrs.csv`
- `generated/detection/incident-iocs.csv`
- `generated/context/kr-localized-cidrs.csv`
- `generated/legacy/providers-bridge.csv`
- `data/vps-providers.csv`
- `data/ip-ranges/known-providers.csv`
- `queries/logpresso/*.logpresso`
- `queries/sigma/*.yml`

## Data Roles

- `providers.yml`
  - anonymous or crypto-friendly provider inventory
  - context only
  - 공급자가 익명 VPS 서비스를 제공하는지는 사람이 판단 (LLM + 검색 + 사례 분석)
- `asns.yml`
  - linking / context layer between providers and infrastructure
  - not the default detection unit
  - **ASN은 반드시 sapics 대조 검증 후 등록** — 재판매 업체(자체 ASN 없음)는 등록 금지
- `cidrs.yml`
  - generalized CIDRs with explicit status and scope (`provider_allocated`, `high_risk_detection`)
- `incidents/*.yml`
  - exact IOC observations and incident references

## Location Context (generated, DB-driven)

- `generate_location_context.py` intersects tracked-ASN ranges with the GeoLite2
  country DB (`data/country-ipv4.csv`) and emits KR-geolocated ranges to
  `generated/context/kr-localized-cidrs.csv`. It is **not** hand-edited data.
- Hunting context only — kept out of every detection output. Geolocation is not proof
  of physical server location.

## Evidence Rules (contributors)

- Use **claim-specific official evidence** for each declared service / payment /
  location fact. A `provider_verified` record must back every such claim; do not
  upgrade a record to `provider_verified` on a generic site link alone.
- **Do not infer ASN ownership from resale.** A provider reselling another
  operator's cloud does not own that ASN. Only register an ASN under a provider when
  ownership/use is evidenced (see ASN registration rules below).
- **Keep location-only context out of detection.** The generated
  `kr-localized-cidrs.csv` (geolocation of tracked-ASN ranges) is hunting/enrichment
  only. It must never enter `high-risk-cidrs.csv`, incident IOCs, Sigma, or Logpresso.
  A geolocation country is not proof of physical server location.

## ASN 등록 규칙

`asns.yml`에 ASN을 추가할 때:

1. **sapics에서 공식 org명 확인** — `asn-ipv4.csv`에서 해당 ASN 검색
2. **org명이 provider명과 일치해야 등록 가능** — 브랜드명/법인명 차이는 허용
3. **대형 클라우드 ASN 금지** — Vultr(AS20473), Path Network(AS396998) 등 업스트림 ISP의 ASN을
   재판매 업체에 귀속시키면 `validate_data.py`가 오류로 차단
4. **재판매 업체 처리** — 자체 ASN이 없으면 `providers.yml`에만 등록하고 `asns.yml`에는 추가하지 않음

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
