# Policy

## Purpose

This repository maintains a conservative detection-oriented map of anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting.

## Principles

- Do not equate `provider` with `malicious infrastructure`
- Cryptocurrency payment support alone qualifies a provider for inventory inclusion,
  never for a malicious / high-risk detection verdict
- Keep exact IOCs separate from generalized CIDRs
- Use ASN for linking and context, not as the default blocking unit
- Do not infer ASN ownership from resale; require claim-specific official evidence
- Keep location-only context (registry/geolocation) out of detection outputs
- Prefer under-classification to over-generalization

## Inclusion

Provider:

- official site exists and offers hosting / VPS / related infrastructure
- anonymous, privacy-oriented, or crypto-friendly characteristics are documented or preserved as context

ASN:

- linked to a provider, or
- repeatedly appears in public abuse-related context

CIDR:

- keep as `candidate` if evidence is narrow
- promote only when range-level generalization is justified

CIDR location context:

- scope `location_context` records registry country + advertised/observed location
  (tags `kr-localized`, `geo-mismatch-candidate`) as hunting context
- a registry country is not proof of physical server location
- location-context rows stay `candidate` and never enter detection outputs

Incident IOC:

- keep exact `/32` when public reporting gives a specific IP

## Exclusion

- one IOC does not justify ASN-wide or provider-wide labeling
- one IOC does not justify `/24` promotion
- shared cloud or broad hosting space should not be promoted without clear repeated evidence

## Output Handling

- `incident-iocs.csv` is the safest blocking input
- `high-risk-cidrs.csv` is a stronger generalized detection input
- `provider-ranges.csv` is for hunting and enrichment, not blanket blocking
- `generated/context/kr-localized-cidrs.csv` is location context for hunting only —
  it is isolated from all detection outputs and must never be used for blocking
