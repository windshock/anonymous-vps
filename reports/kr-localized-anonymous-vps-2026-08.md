# Country-Localized Anonymous VPS Allocations — KR case study (2026-08)

## Executive summary

A recurring pattern in anonymous/crypto-friendly hosting is **country
localization**: a foreign-operated provider registers or advertises an IP block
*inside a target country* so that traffic sourced from it survives naive geo-IP
blocking ("block everything not KR"). This report documents concrete, publicly
verifiable examples of **Korea-localized (KR) allocations** operated by providers
this dataset tracks, and the hunting posture they warrant.

All facts below come from **public sources only** — registry records (RIPE RDAP /
BGP) and provider sites. Nothing here attributes the allocations to a specific
actor, campaign, or intent; the value is the *infrastructure shape*, not attribution.

These allocations are recorded as **location context**, not detection indicators.
This dataset keeps four separate evidence layers, and this report only concerns the
third one:

1. **provider inventory** — who offers anonymous/crypto-friendly hosting
2. **ASN relationship** — which ASN a provider owns or uses
3. **CIDR location context** — registry country + advertised/observed location (this report)
4. **incident / high-risk detection** — exact IOCs and generalized high-risk CIDRs

A registry country is **not** proof of physical server location, and a KR-localized
tag alone never promotes a block into the detection set.

## Observed KR-localized allocations

| CIDR | ASN | Operator | Registry netname | Registry country | Note |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `79.110.55.0/24` | AS9009 | M247 | `M247-SOUTH-KOREA` | KR | KR-registered; active geolocation observed JP (see below) |
| `84.233.167.0/24` | AS212238 | Datacamp Limited | `CDNEXT-SEO` | KR | KR-registered CDN/hosting allocation |
| `141.98.213.0/24` | AS206804 | EstNOC | `EstNOC-Korea` | KR | KR-registered hosting allocation |

> Datacamp Limited (`datacamp.co.uk`) is the UK operator that owns AS212238. It is
> a **separate entity** from the crypto-payment hosting brand tracked in this
> dataset as the `coin-host` provider record; do not conflate the two.

Verification (public RDAP), e.g.:

```
curl -s https://rdap.db.ripe.net/ip/79.110.55.0   | jq '.name, .country'
# "M247-SOUTH-KOREA"  "KR"
curl -s https://rdap.db.ripe.net/ip/141.98.213.0  | jq '.name, .country'
# "EstNOC-Korea"      "KR"
```

These three rows are shipped as `generated/context/kr-localized-cidrs.csv`
(status `candidate`, scope `location_context`, tag `kr-localized`). They are
**absent** from every detection artifact (high-risk CSV, incident IOC CSV, Sigma,
Logpresso).

### Dated active-geolocation measurement (`79.110.55.0/24`)

The M247 `/24` is **registered** as KR (`M247-SOUTH-KOREA`) but was **observed**
by public active-geolocation sources to answer from **JP** on the recorded
measurement date. This is captured as a `geo-mismatch-candidate` with an
`observed_at` date — a **time-bound measurement**, not a claim of deception or of a
permanent physical location. IP geolocation and routing change over time; re-verify
before acting.

### A separate TW allocation (not KR-localized)

`188.214.106.0/24` (AS9009 M247, netname context "M247 Taipei") is a **Taiwan**
allocation, not a KR-localized one. It is listed here only to keep it out of the KR
set and to support the transcription-error caution below — it is **not** part of the
KR location-context data.

## Why this shape matters

1. **Geo-IP evasion.** A block registered/advertised as KR is not caught by a
   "drop non-KR sources" firewall policy, yet the operator (M247, EstNOC, Datacamp)
   is a foreign hosting provider whose ranges are commonly reused for throwaway
   proxy/VPN infrastructure. Registry country is a routing/registration fact, not a
   physical-location proof.
2. **Single ASN, many countries.** M247 (AS9009) alone spans KR, JP, TW and more
   under one ASN. Blocking or hunting by *country* misses it; the ASN / per-`/24`
   netname is the reliable pivot.

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
  This dataset ships M247 (AS9009) and EstNOC (AS206804) provider ranges plus the
  Datacamp (AS212238) allocation, with Sigma and Logpresso rules under `queries/`.
- **Location context is not a verdict.** The KR-localized rows live in
  `generated/context/kr-localized-cidrs.csv`, deliberately isolated from the
  detection outputs. Use them for hunting/enrichment, never as an automatic block.
- **Do not blanket-block whole ASNs.** M247 in particular is a mainstream backbone
  for commercial VPNs; ranges carry legitimate traffic. Confirm with request-level
  evidence before range-level blocking.
- **Confirm at the application layer.** IPs are cheap to rotate. Whether an
  observation is opportunistic scanning or a targeted operation is decided by
  payload / User-Agent / beacon-cadence (TTP) analysis, not by the IP alone.

## Dataset changes backing this report

- Corrected provider identity: `datacamp-limited` (`datacamp.co.uk`, hosting, owns
  AS212238) is separated from the `coin-host` provider record (the crypto-payment
  hosting brand operated by Solar Communications GmbH). AS212238 is linked **only**
  to Datacamp Limited, with no ASN attributed to `coin-host`.
- Added a CIDR `location_context` layer and the isolated
  `generated/context/kr-localized-cidrs.csv` artifact for the three KR allocations
  above (one carrying a dated KR/JP geo-mismatch measurement).
- See `CHANGELOG.md`.
