# Country-Localized Anonymous VPS Allocations — KR case study (2026-08)

## Executive summary

A recurring evasion pattern in anonymous/crypto-friendly hosting is **country
localization**: a foreign provider registers or geolocates an IP block *inside a
target country* so that traffic sourced from it survives naive geo-IP blocking
("block everything not KR"). This report documents concrete, publicly verifiable
examples of **Korea-localized (KR) allocations** operated by providers this
dataset tracks, and the detection posture they warrant.

All facts below come from **public sources only** — RIPE RDAP registry records and
provider sites. Nothing here attributes the allocations to a specific actor or
campaign; the value is the *infrastructure shape*, not attribution.

## Observed KR-localized allocations

| CIDR | ASN | Operator | RIPE netname | Country | Public signal |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `79.110.55.0/24` | AS9009 | M247 | `M247-SOUTH-KOREA` | KR | RIPE `LEGAL CONCERNS` remark |
| `84.233.167.0/24` | AS212238 | Datacamp (coin.host) | `CDNEXT-SEO` | KR | crypto-payment VPS brand |
| `141.98.213.0/24` | AS206804 | EstNOC | `EstNOC-Korea` | KR | RIPE `LEGAL CONCERNS` remark |
| `188.214.106.0/24` | AS9009 | M247 | `RO-M247RO` | TW | remark "M247 Taipei Infrastructure" |

Verification (public RDAP), e.g.:

```
curl -s https://rdap.db.ripe.net/ip/79.110.55.0   | jq '.name, .country'
# "M247-SOUTH-KOREA"  "KR"
curl -s https://rdap.db.ripe.net/ip/141.98.213.0  | jq '.name, .country'
# "EstNOC-Korea"      "KR"
```

### Why this shape matters

1. **Geo-IP evasion.** A block registered/geolocated as KR is not caught by a
   "drop non-KR sources" firewall policy, yet the operator (M247, EstNOC,
   Datacamp) is a foreign anonymous/crypto-friendly host — the same category
   used for throwaway proxy/VPN/C2 infrastructure.
2. **Single ASN, many countries.** M247 (AS9009) alone spans KR, JP, TW and
   more under one ASN. Blocking or hunting by *country* misses it; the ASN /
   per-`/24` netname is the reliable pivot.
3. **`LEGAL CONCERNS` marker.** The M247-KR and EstNOC-KR blocks carry a RIPE
   `LEGAL CONCERNS` remark — a public, low-trust signal on the registration.
   Treat as an enrichment flag, not a verdict.

## A note on transcription errors (`188.21` vs `188.214`)

When triaging IP lists, watch for a common transcription slip between
`188.21.106.x` and `188.214.106.x`:

- `188.214.106.0/24` → **AS9009 M247** (TW), an anonymous-hosting block.
- `188.21.106.x` → falls inside `188.20.0.0/14` → **AS8447 A1 Telekom Austria**,
  a legitimate residential/business ISP (`AT-TELEKOM-*`, Privacy: false).

Dropping the `4` turns a hosting IOC into an unrelated Austrian ISP range.
Always resolve the *actual* source IP against RDAP before blocking — an
ISP-range block causes collateral impact with zero effect on the real infra.

## Detection guidance

- **Prefer ASN / `/24`-level hunting over country filters** for these operators.
  This dataset now ships M247 (AS9009) and EstNOC (AS206804) provider ranges plus
  Datacamp (AS212238), with Sigma and Logpresso rules under `queries/`.
- **Do not blanket-block whole ASNs.** M247 in particular is a mainstream backbone
  for commercial VPNs; ranges carry legitimate traffic. Use `provider-ranges` as a
  hunting/enrichment input and confirm with request-level evidence before blocking.
- **Confirm intent at the application layer.** IPs are cheap to rotate. Whether an
  observation is opportunistic scanning or a targeted operation is decided by
  payload / User-Agent / beacon-cadence (TTP) analysis, not by the IP alone.

## Dataset changes backing this report

- Added M247 (AS9009) and EstNOC (AS206804) to `providers.yml` / `asns.yml`
  (`abuse_candidate`, public evidence only).
- Fixed the weekly refresh CI (sapics source migration) and refreshed ASN data.
- See `CHANGELOG.md`.
