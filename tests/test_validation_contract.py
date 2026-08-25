"""Contract for the modular validator (Todo 2).

Imports happen INSIDE each test so the suite still *collects* before the
``validate_records`` / ``validation_common`` modules exist — the tests fail
(RED) rather than erroring at collection time, then go green once Todo 2 lands.
"""

from __future__ import annotations


# --------------------------------------------------------------------------- #
# provider_verified / candidate payment + service contracts
# --------------------------------------------------------------------------- #
def test_accepts_fully_evidenced_verified_provider(verified_provider):
    from validate_records import validate_providers

    errors, warnings = validate_providers([verified_provider])
    assert errors == [], errors


def test_rejects_unknown_payment(make_provider):
    from validate_records import validate_providers

    provider = make_provider(payment_methods=["btc", "dogecoin"], status="provider_verified")
    errors, _ = validate_providers([provider])
    assert any("dogecoin" in e for e in errors)


def test_rejects_unknown_service_type(make_provider):
    from validate_records import validate_providers

    provider = make_provider(service_types=["vps", "smtp-relay"])
    errors, _ = validate_providers([provider])
    assert any("smtp-relay" in e for e in errors)


def test_rejects_duplicate_payment_value(make_provider):
    from validate_records import validate_providers

    provider = make_provider(payment_methods=["btc", "btc"], status="provider_verified")
    errors, _ = validate_providers([provider])
    assert any("btc" in e and "duplicate" in e.lower() for e in errors)


def test_rejects_wrong_container_type_for_payment(make_provider):
    from validate_records import validate_providers

    provider = make_provider(payment_methods="crypto")  # string, not a list
    errors, _ = validate_providers([provider])
    assert any("payment_methods" in e for e in errors)


def test_rejects_unsubstantiated_verified_payment_claim(make_provider):
    """A provider_verified record claiming payment needs claim-specific evidence."""
    from validate_records import validate_providers

    provider = make_provider(
        provider_id="unsubstantiated",
        status="provider_verified",
        payment_methods=["btc"],
        # only a generic service_domain evidence — nothing supports the payment claim
    )
    errors, _ = validate_providers([provider])
    assert any("unsubstantiated" in e and "payment" in e.lower() for e in errors)


def test_candidate_named_currency_without_evidence_warns_not_errors(make_provider):
    """Legacy candidates get a warning (not a hard error) for unbacked named currencies."""
    from validate_records import validate_providers

    provider = make_provider(
        provider_id="legacy-candidate",
        status="candidate",
        payment_methods=["btc"],  # named currency, no payment evidence
    )
    errors, warnings = validate_providers([provider])
    assert not any("legacy-candidate" in e for e in errors)
    assert any("legacy-candidate" in w for w in warnings)


def test_generic_crypto_candidate_stays_silent(make_provider):
    """Generic `crypto` on a candidate is the historical norm — no warning/error."""
    from validate_records import validate_providers

    provider = make_provider(provider_id="generic", status="candidate", payment_methods=["crypto"])
    errors, warnings = validate_providers([provider])
    assert not any("generic" in e for e in errors)
    assert not any("generic" in w for w in warnings)


# --------------------------------------------------------------------------- #
# CIDR location_context contract
# --------------------------------------------------------------------------- #
def _index(make_provider, make_asn):
    provider_index = {"example": make_provider()}
    asn_index = {"AS64500": make_asn()}
    return provider_index, asn_index


def test_accepts_location_context_kr_localized_row(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    errors, _ = validate_cidrs([make_location_cidr()], provider_index, asn_index)
    assert errors == [], errors


def test_accepts_location_context_geo_mismatch_row(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(
        tags=["kr-localized", "geo-mismatch-candidate"],
        registry_country="KR",
        observed_location="JP",
        observed_at="2026-08-20",
    )
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert errors == [], errors


def test_rejects_unknown_location_tag(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(tags=["kr-localized", "high-risk"])
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("high-risk" in e for e in errors)


def test_rejects_location_mismatch_without_observation(make_location_cidr, make_provider, make_asn):
    """geo-mismatch-candidate requires observed_location + observed_at."""
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(tags=["kr-localized", "geo-mismatch-candidate"])  # no observation fields
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("observ" in e.lower() for e in errors)


def test_rejects_same_country_mismatch(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(
        tags=["kr-localized", "geo-mismatch-candidate"],
        registry_country="KR",
        observed_location="KR",
        observed_at="2026-08-20",
    )
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("distinct" in e.lower() or "same" in e.lower() for e in errors)


def test_rejects_malformed_country(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(registry_country="kor")  # not ISO alpha-2 uppercase
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("registry_country" in e for e in errors)


def test_rejects_malformed_observed_at(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(
        tags=["kr-localized", "geo-mismatch-candidate"],
        observed_location="JP",
        observed_at="2026/08/20",  # wrong format
    )
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("observed_at" in e for e in errors)


def test_rejects_observation_fields_on_non_mismatch_row(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(tags=["kr-localized"], observed_location="JP", observed_at="2026-08-20")
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("observ" in e.lower() for e in errors)


def test_rejects_high_risk_status_on_location_context(make_location_cidr, make_provider, make_asn):
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_location_cidr(status="abuse_candidate")
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("location_context" in e and "candidate" in e for e in errors)


def test_rejects_location_fields_on_non_location_scope(make_cidr, make_provider, make_asn):
    """kr-localized tags/observation fields must not ride along on other scopes."""
    from validate_records import validate_cidrs

    provider_index, asn_index = _index(make_provider, make_asn)
    record = make_cidr(scope="provider_allocated", tags=["kr-localized"], registry_country="KR")
    errors, _ = validate_cidrs([record], provider_index, asn_index)
    assert any("location_context" in e for e in errors)
