"""Contract for the extracted ASN validator module (Todo 2).

Imports are inside the tests so collection succeeds before ``validate_asn`` exists.
"""

from __future__ import annotations


def test_major_cloud_misattribution_is_error(make_asn):
    from validate_asn import validate_asn_ownership

    asns = [make_asn(asn="AS20473", name="Reseller", provider_id="reseller")]
    provider_index = {"reseller": {"name": "Reseller"}}
    sapics = {"20473": "The Constant Company, LLC"}
    errors, warnings = validate_asn_ownership(asns, provider_index, sapics)
    assert any("AS20473" in e for e in errors)


def test_name_mismatch_is_warning_only(make_asn):
    from validate_asn import validate_asn_ownership

    asns = [make_asn(asn="AS39287", name="Njalla", provider_id="njalla")]
    provider_index = {"njalla": {"name": "Njalla"}}
    sapics = {"39287": "Materialism s.r.l."}
    errors, warnings = validate_asn_ownership(asns, provider_index, sapics)
    assert errors == []
    assert any("AS39287" in w for w in warnings)


def test_name_overlap_produces_no_warning(make_asn):
    from validate_asn import validate_asn_ownership

    asns = [make_asn(asn="AS9009", name="M247 Europe SRL", provider_id="m247")]
    provider_index = {"m247": {"name": "M247"}}
    sapics = {"9009": "M247 Europe SRL"}
    errors, warnings = validate_asn_ownership(asns, provider_index, sapics)
    assert errors == []
    assert warnings == []


def test_candidate_link_is_skipped(make_asn):
    from validate_asn import validate_asn_ownership

    asns = [make_asn(asn="AS20473", relationship="candidate_link", provider_id="reseller")]
    provider_index = {"reseller": {"name": "Reseller"}}
    sapics = {"20473": "The Constant Company, LLC"}
    errors, warnings = validate_asn_ownership(asns, provider_index, sapics)
    assert errors == []


def test_sapics_snapshot_loads_from_disk(tiny_asn_csv):
    from validate_asn import load_sapics_asn_orgs

    index = load_sapics_asn_orgs(tiny_asn_csv)
    assert index["64500"] == "Example Networks"
    assert index["20473"] == "The Constant Company, LLC"


def test_asn_format_and_reference_checks(make_asn):
    from validate_asn import validate_asns

    bad = make_asn(asn="9009")  # missing AS prefix
    provider_index = {"example": {"name": "Example"}}
    errors, _ = validate_asns([bad], provider_index)
    assert any("format" in e.lower() for e in errors)


def test_asn_unknown_provider_id_is_error(make_asn):
    from validate_asn import validate_asns

    rec = make_asn(asn="AS64500", provider_id="ghost")
    errors, _ = validate_asns([rec], provider_index={})
    assert any("ghost" in e for e in errors)
