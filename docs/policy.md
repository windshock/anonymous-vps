# Policy

## Purpose

This repository maintains a conservative detection-oriented map of anonymous or crypto-friendly VPS / hosting infrastructure that appears in public incident reporting.

## Principles

- Do not equate `provider` with `malicious infrastructure`
- Keep exact IOCs separate from generalized CIDRs
- Use ASN for linking and context, not as the default blocking unit
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
