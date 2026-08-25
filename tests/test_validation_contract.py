"""Contract for the modular validator: provider payment/service vocabularies.

Imports happen INSIDE each test so the suite still *collects* before the
``validate_records`` / ``validation_common`` modules exist.
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
