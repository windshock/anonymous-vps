# AGENT.md — Anonymous VPS Intelligence Project

## Purpose

A curated **Threat Intelligence** repository of anonymous VPS providers that support cryptocurrency payments, linked to real-world APT and ransomware campaigns, and shared publicly on GitHub.

---

## File Roles (Manual vs Auto-generated)

| File | Type | How to manage |
|------|------|---------------|
| `data/vps-providers.csv` | **Source of truth** | ✅ Edit directly |
| `data/asn-ipv4.csv` | ASN reference DB | 🔄 Auto-downloaded via `fetch_asn.py` |
| `data/ip-ranges/known-providers.csv` | IP range list | ❌ Auto-generated (do not edit) |
| `data/ip-ranges/notes.csv` | IP range annotations | ✅ Edit directly (optional) |
| `queries/logpresso/*.logpresso` | Detection queries | ❌ Auto-generated (do not edit) |
| `reports/*.md` | Incident analysis reports | ✅ Edit directly |

---

## Data Flow

```
[Edit directly]
vps-providers.csv  (vendor + ASN)
        +
asn-ipv4.csv  ←  fetch_asn.py (downloaded from sapics/ip-location-db on GitHub)
        ↓  generate_ranges.py
data/ip-ranges/known-providers.csv  (auto-generated)
        ↓  generate_queries.py
queries/logpresso/<vendor>.logpresso  (auto-generated)
queries/logpresso/all-vendors.logpresso
```

---

## Core Schema: `data/vps-providers.csv`

| Column | Description |
|--------|-------------|
| `vendor` | Provider name |
| `domain` | Official domain |
| `asn` | AS Number (e.g. AS399629) — skipped in pipeline if empty |
| `asn_link` | bgp.tools link |
| `shodan_template` | Shodan search URL |
| `abuse_template` | AbuseIPDB lookup URL template |
| `note` | Payment method, APT observation history, etc. |
| `source` | Reference source |

---

## Adding a New Provider

### Case A: ASN is known (fastest)
```bash
# 1. Add a row to vps-providers.csv (vendor, domain, asn required)
# 2. Run pipeline (skip ASN DB download)
python3 scripts/pipeline.py --skip-fetch
```

### Case B: ASN is unknown
```bash
# 1. Try DNS → ASN lookup by domain
python3 scripts/update_providers.py --lookup <domain>

# 2. If the domain is behind a CDN, find ASN via web search:
#    - https://bgp.tools/search?q=<vendor_name>
#    - https://bgp.he.net/search?search[search]=<vendor_name>
#    - Web search: "<vendor> ASN autonomous system"

# 3. Add row to vps-providers.csv, then run pipeline
python3 scripts/pipeline.py --skip-fetch
```

### Case C: Refresh ASN DB and regenerate everything
```bash
# Download latest asn-ipv4.csv from sapics + regenerate all
python3 scripts/pipeline.py
```

### Case D: Regenerate a single provider only
```bash
python3 scripts/pipeline.py --skip-fetch --vendor BitLaunch
```

---

## Adding IP Range Annotations (notes.csv)

To annotate specific IP ranges with APT observation history or incident context:

```csv
# data/ip-ranges/notes.csv
vendor,cidr,note
BitLaunch,64.190.113.0/24,APT observed: Donot Team (APT-C-35) login attempt 2025-09
Hostwinds,142.11.192.0/18,C2 IP 142.11.206.73 observed in Axios npm supply-chain attack (Mar 2026)
```

Notes are automatically merged into `known-providers.csv` on each pipeline run.

---

## Script Reference

```bash
# Full pipeline
python3 scripts/pipeline.py

# Update ASN DB only
python3 scripts/fetch_asn.py
python3 scripts/fetch_asn.py --check          # check for updates without downloading

# Regenerate IP ranges
python3 scripts/generate_ranges.py
python3 scripts/generate_ranges.py --vendor Hostwinds

# Regenerate Logpresso queries
python3 scripts/generate_queries.py
python3 scripts/generate_queries.py --vendor BitLaunch

# Validate and sort provider list
python3 scripts/update_providers.py
python3 scripts/update_providers.py --add     # interactive add
python3 scripts/update_providers.py --lookup AS399629  # look up IP ranges for ASN
```

---

## Provider Selection Criteria

Include providers that meet **one or more** of the following:

1. **Cryptocurrency payment accepted** (Bitcoin, Monero, ETH, etc.)
2. **No KYC** (identity verification not required)
3. **DMCA / abuse complaints ignored** (Bulletproof Hosting)
4. **Offshore registration** (Iceland, Russia, Romania, Netherlands, etc.)
5. **Observed in real APT or ransomware infrastructure**

---

## Adding a Report

Add a Markdown file to `reports/`. Naming convention: `<topic>-<YYYY>.md`
```
reports/lazarus-infrastructure-2025.md
reports/apt-c-35-donot-team-2025.md
```

---

## Disclaimer

This repository is intended for **defensive security research and Threat Intelligence purposes only**.  
Do not use for offensive activity, attacking services, or any illegal purpose.  
All IOC data references verified public sources only.

