# Country-Localized Anonymous VPS Allocations — KR case study (2026-08)

## Executive summary

A recurring pattern in anonymous/crypto-friendly hosting is **country
localization**: a foreign-operated provider runs IP blocks that geolocate *inside a
target country* so that traffic sourced from them survives naive geo-IP blocking
("block everything not KR"). This report documents **Korea-localized (KR)
allocations** operated by ASNs this dataset tracks, and the hunting posture they
warrant.

The KR set is **derived, not hand-picked**. `generate_location_context.py` takes the
IP ranges of the ASNs we already track (owned/used by tracked providers) and
intersects them with the GeoLite2 **country** database from `sapics/ip-location-db`.
Every tracked-ASN range that geolocates to KR is emitted to
`generated/context/kr-localized-cidrs.csv`.

These rows are **location context**, not detection indicators. This dataset keeps
four separate evidence layers, and this report concerns only the third:

1. **provider inventory** — who offers anonymous/crypto-friendly hosting
2. **ASN relationship** — which ASN a provider owns or uses
3. **CIDR location context** — geolocation country of tracked-ASN ranges (this report)
4. **incident / high-risk detection** — exact IOCs and generalized high-risk CIDRs

A geolocation country is **not** proof of physical server location (different
providers can disagree), and a KR geolocation alone never promotes a block into the
detection set.

## Observed KR-localized allocations (auto-extracted)

As of the 2026-08 ASN/country snapshots, the intersection yields **12 KR-geolocated
CIDRs across three tracked ASNs**:

| ASN | Operator | KR-geolocated ranges |
| :--- | :--- | :---: |
| AS212238 | Datacamp Limited | 9 |
| AS206804 | EstNOC | 2 |
| AS9009 | M247 | 1 |

The full, current list (with per-CIDR provider/vendor) is
`generated/context/kr-localized-cidrs.csv` — columns
`cidr, provider_id, vendor, asn, geo_country, source`. Counts change automatically as
the weekly ASN/country snapshots refresh.

> Datacamp Limited (`datacamp.co.uk`) is the UK operator that owns AS212238 — the
> largest KR-localizer here (CDNEXT Seoul allocations). It is a **separate entity**
> from the crypto-payment hosting brand tracked as the `coin-host` provider record;
> do not conflate the two.

Registry cross-check (public RDAP) still corroborates the KR netnames, e.g.:

```
curl -s https://rdap.db.ripe.net/ip/141.98.213.0 | jq '.name, .country'
# "EstNOC-Korea"  "KR"
```

These rows are **absent** from every detection artifact (high-risk CSV, incident IOC
CSV, Sigma, Logpresso).

## Why this shape matters

1. **Geo-IP evasion.** A block that geolocates as KR is not caught by a "drop non-KR
   sources" firewall policy, yet the operator (Datacamp, EstNOC, M247) is a foreign
   hosting provider whose ranges are commonly reused for throwaway proxy/VPN
   infrastructure. Geolocation is a routing/registration fact, not physical proof.
2. **Single ASN, many countries.** M247 (AS9009) alone spans KR, JP, TW and more
   under one ASN. Blocking or hunting by *country* misses it; the ASN / per-`/24`
   is the reliable pivot.

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
  This dataset ships their provider ranges plus the auto-extracted KR context list.
- **Location context is not a verdict.** The KR rows live in
  `generated/context/kr-localized-cidrs.csv`, deliberately isolated from the detection
  outputs. Use them for hunting/enrichment, never as an automatic block.
- **Do not blanket-block whole ASNs.** M247 in particular is a mainstream backbone
  for commercial VPNs; ranges carry legitimate traffic. Confirm with request-level
  evidence before range-level blocking.
- **Geolocation is one source.** GeoLite2 country data is non-authoritative and
  time-bound; other providers may disagree. Re-verify before acting.
- **Confirm at the application layer.** IPs are cheap to rotate. Whether an
  observation is opportunistic scanning or a targeted operation is decided by
  payload / User-Agent / beacon-cadence (TTP) analysis, not by the IP alone.

## Dataset changes backing this report

- Corrected provider identity: `datacamp-limited` (`datacamp.co.uk`, hosting, owns
  AS212238) is separated from the `coin-host` provider record (the crypto-payment
  hosting brand operated by Solar Communications GmbH). AS212238 links **only** to
  Datacamp Limited, with no ASN attributed to `coin-host`.
- Added a DB-driven location-context artifact
  `generated/context/kr-localized-cidrs.csv`: tracked-ASN ranges intersected with the
  GeoLite2 country DB (`data/country-ipv4.csv`, auto-fetched) to extract KR-geolocated
  ranges objectively.
- See `CHANGELOG.md`.
