# 🕵️ Anonymous VPS Intelligence

A curated **Threat Intelligence** repository of anonymous VPS providers that support cryptocurrency payments.  
Focused on infrastructure data observed in real-world APT and ransomware campaigns.

---

## 📦 Data

### [`data/vps-providers.csv`](data/vps-providers.csv)
Curated list of anonymous VPS providers (30+). Includes ASN, Shodan search links, and notes.

| Column | Description |
|--------|-------------|
| `vendor` | Service name |
| `domain` | Official domain |
| `asn` | Autonomous System Number |
| `shodan_template` | Shodan search URL |
| `abuse_template` | AbuseIPDB lookup URL |
| `note` | Payment method, anonymity notes, APT observations |

### [`data/asn-ipv4.csv`](data/asn-ipv4.csv)
Global ASN ↔ IPv4 range mapping reference (~400k records). Not committed to repo — fetched via `fetch_asn.py`.

---

## 📑 Analysis Reports

| File | Description |
|------|-------------|
| [apt-analysis-2020-2025.md](reports/apt-analysis-2020-2025.md) | Anonymous VPS abuse by APT groups (China, Russia, Middle East) — 2020–2025 |
| [axios-supply-chain-2026.md](reports/axios-supply-chain-2026.md) | Deep-dive: Axios npm supply-chain compromise (2026) |

---

## 🔍 Provider Selection Criteria

Providers are included if they meet **one or more** of the following:

- Cryptocurrency payment accepted (BTC / XMR / ETH)
- No KYC (identity verification not required)
- DMCA / abuse complaints ignored (Bulletproof Hosting)
- Offshore registration (Iceland, Russia, Romania, Netherlands, etc.)
- Observed in real APT or ransomware infrastructure

---

## 🎯 Usage Guide

| Use Case | File | Notes |
|----------|------|-------|
| **Logpresso — VPN inbound detection** | [`queries/logpresso/all-vendors-vpn.logpresso`](queries/logpresso/all-vendors-vpn.logpresso) | Detects anonymous VPS connections in VPN logs |
| **Logpresso — Firewall outbound detection** | [`queries/logpresso/all-vendors.logpresso`](queries/logpresso/all-vendors.logpresso) | Detects internal→external comms to anonymous VPS |
| **Per-vendor queries** | [`queries/logpresso/`](queries/logpresso/) | Focus monitoring on a specific provider |
| **Other SIEM / Firewall ACL** | [`data/ip-ranges/known-providers.csv`](data/ip-ranges/known-providers.csv) (`cidr` column) | Import CIDR list into any SIEM or firewall |
| **Splunk / Elastic / Sentinel (Sigma)** | [`queries/sigma/all-vendors.yml`](queries/sigma/all-vendors.yml) | Convert with [pySigma](https://github.com/SigmaHQ/pySigma) to any backend |
| **Per-vendor Sigma rules** | [`queries/sigma/`](queries/sigma/) | `level: high` for APT-observed providers |
| **Provider reference** | [`data/vps-providers.csv`](data/vps-providers.csv) | vendor, ASN, Shodan links |

> ⚠️ **False positive warning**: Datacamp Limited (1,834 ranges), QloudHost (677), and Hostinger (343) have very broad IP ranges.  
> It is recommended to start monitoring with providers that have confirmed APT observations: `BitLaunch`, `FlokiNET`, `Shinjiru`, `Hostwinds`.

---

## ⚙️ Pipeline

```bash
# Full pipeline: fetch latest ASN DB + regenerate IP ranges + queries
python3 scripts/pipeline.py

# Skip ASN download (use existing asn-ipv4.csv)
python3 scripts/pipeline.py --skip-fetch

# Single provider
python3 scripts/pipeline.py --skip-fetch --vendor BitLaunch

# Validate & sort provider list
python3 scripts/update_providers.py

# Look up IP ranges for an ASN
python3 scripts/update_providers.py --lookup AS399629
```

See [AGENT.md](AGENT.md) for detailed instructions on adding providers and updating data.

---

## 🔄 ASN Data Source

`data/asn-ipv4.csv` is fetched from:

> **[sapics/ip-location-db](https://github.com/sapics/ip-location-db/tree/main/asn)** — `asn/asn-ipv4.csv`  
> Public Domain (CC0). Global ASN ↔ IPv4 mapping (~400k records).

```bash
python3 scripts/fetch_asn.py        # download latest
python3 scripts/fetch_asn.py --check  # check for updates only
```

### Automatic Weekly Updates (GitHub Actions)

The repository includes a scheduled workflow ([`.github/workflows/update-asn.yml`](.github/workflows/update-asn.yml)) that runs every **Monday at 00:00 UTC**:

1. Downloads the latest `asn-ipv4.csv` from sapics/ip-location-db
2. Regenerates `data/ip-ranges/known-providers.csv`
3. Regenerates all `queries/logpresso/*.logpresso` files
4. Regenerates all `queries/sigma/*.yml` Sigma rules (APT-observed providers → `level: high`)
5. Auto-commits and pushes if any changes are detected

You can also trigger it manually via **Actions → Weekly ASN Update → Run workflow** on GitHub.

---

## ⚠️ Disclaimer

This repository is provided for **defensive security research and Threat Intelligence purposes only**.  
Any malicious use, offensive activity, or violation of applicable laws is strictly prohibited.

---

## 📚 References

- [BushidoToken Blog — Investigating Anonymous VPS Services (2025)](https://blog.bushidotoken.net/2025/02/investigating-anonymous-vps-services.html)
- [Volexity — Operation EmailThief (2022)](https://www.volexity.com/blog/2022/02/03/operation-emailthief-active-exploitation-of-zero-day-xss-vulnerability-in-zimbra/)
- [own.security — Bulletproof Hosting Landscape](https://www.own.security/en/ressources/blog/50-shades-of-bulletproof-hosting-bph-landscape-on-russian-language-cybercrime-forums)

