# Changelog

All notable changes to the Anonymous VPS Intelligence dataset and tooling.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — 2026-08-26

### Fixed
- **CI: dead ASN source URL (HTTP 404).** The *Weekly Detection Data Refresh*
  workflow had failed every run since 2026-06-22. Root cause: `sapics/ip-location-db`
  restructured its repository, replacing the single `asn/` directory with
  per-source directories (`dbip-asn`, `geolite2-asn`, `iptoasn-asn`, `origin-asn`),
  so the hard-coded `asn/asn-ipv4.csv` path returned 404 in `fetch_asn.py`.
  Switched the source to `geolite2-asn/geolite2-asn-ipv4.csv`.
  - The GeoLite2 file matches the previous format byte-for-byte
    (`start,end,asn,"org name"`) — in fact the old `asn/asn-ipv4.csv` **was** the
    GeoLite2 dataset.
  - It keeps the **org-name column populated**, which `validate_data.py`'s ASN
    ownership check depends on. `dbip-asn-ipv4.csv` was rejected because its
    org-name column is empty.

### Added
- **CIDR location-context layer + isolated artifact.** New CIDR scope
  `location_context` (tags `kr-localized`, `geo-mismatch-candidate`) records registry
  country and advertised/observed location as hunting context. Three KR allocations
  were added — `79.110.55.0/24` (M247, with a dated KR-registry/JP-observed
  geo-mismatch measurement), `84.233.167.0/24` (Datacamp Limited / CDNEXT-SEO), and
  `141.98.213.0/24` (EstNOC / EstNOC-Korea) — and are emitted to the new
  `generated/context/kr-localized-cidrs.csv`. **Isolation guarantee:** these rows are
  deliberately kept out of the high-risk CSV, incident IOCs, and every Sigma /
  Logpresso rule. A registry country is not proof of physical server location, and a
  location tag alone never promotes a block to detection.
- **Verified providers: `coin-host` and `evoxt`.** Both added as `provider_verified`
  (official crypto-payment evidence; `evoxt` also advertises a Seoul/KINX region),
  each with **no** ASN record because ownership is not evidenced.
- **Payment evidence enriched** for Njalla, Shinjiru, Black.host, VSYS, Impreza.host,
  and Cherry Servers using official pages; Seoul-offering evidence added to BitLaunch
  and GhostVPS without any provider-wide country tag.
- **Providers / ASNs: M247 (AS9009) and EstNOC (AS206804).** Both operate their
  own ASN (registered `owned_by_provider`, `abuse_candidate`). Added to close a
  coverage gap for **country-localized anonymous hosting/VPN allocations** —
  foreign providers that register/geolocate blocks inside a target country to
  evade geo-IP blocking.
  - Evidence is **public only**: official sites + RIPE RDAP registry records.
  - Notable public signal: some M247 and EstNOC `/24`s carry a RIPE
    `LEGAL CONCERNS` remark (e.g. `M247-SOUTH-KOREA`, `EstNOC-Korea`).
  - See `reports/kr-localized-anonymous-vps-2026-08.md`.

### Changed
- **Provider identity corrected.** `datacamp-limited` is now modeled as the UK
  hosting/CDN operator that owns AS212238 (`datacamp.co.uk`, service type `hosting`,
  no payment methods, relationship `owned_by_provider`). It was previously
  mis-modeled with the crypto-payment brand's domain and service. That crypto-payment
  brand is now a **separate** `coin-host` provider record (operator Solar
  Communications GmbH) with no ASN attributed. AS212238 links **only** to
  `datacamp-limited`, which remains foreign-operated KR/Seoul hosting inventory.
- **Validator modularized + offline test harness.** `validate_data.py` is now a thin
  CLI over `validation_common.py`, `validate_asn.py`, and `validate_records.py`, which
  enforce controlled `service_types` / `payment_methods` vocabularies and the new
  `location_context` schema. A dev-only `pytest` suite (`tests/`, `uv` dev group)
  locks current behavior and the new contracts; runtime scripts stay
  standard-library-only. The pipeline `--dry-run` now correctly writes no files.
- **ASN data source migrated** from `asn/asn-ipv4.csv` → `geolite2-asn/geolite2-asn-ipv4.csv`
  (see Fixed). `data/asn-meta.json` `source` field updated accordingly.
- **Refreshed ASN data to 2026-08-25** (403,434 rows) and regenerated all outputs.
  `provider-ranges.csv` grew from ~3.1k to ~6.7k rows, mostly from M247's large
  allocation footprint.

### Data-quality note
- The earlier local fix removing misattributed ASNs (`AS20473` The Constant
  Company/Vultr, `AS396998` Path Network) and adding the sapics ownership check
  in `validate_data.py` was preserved on top of the refreshed upstream data.
  `validate_data.py` passes with only brand-vs-legal-name warnings.

> **Caution:** M247 is a large backbone used by many commercial VPNs; its ranges
> carry legitimate traffic. `provider-ranges` is a **hunting/context** input, not
> a blanket blocklist. Validate operational impact before range-level blocking.
