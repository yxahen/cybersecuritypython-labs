import copy

import pytest

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.tests.conftest import CVE_ID, get_cve, get_metrics

VARIANT = 7
RULE = {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"}


def analyze(payload, variant=VARIANT):
    return build_report(extract_record(payload, CVE_ID), CVE_ID, variant)


def make_entry(score, availability, entry_type="Primary", source="nvd@nist.gov"):
    return {
        "source": source,
        "type": entry_type,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "availabilityImpact": availability,
            "baseScore": score,
        },
    }


def test_sample_report_for_variant_7(payload):
    assert analyze(payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 7,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE,
        "observed": "HIGH",
        "decision": "review",
    }


@pytest.mark.parametrize(
    "score, availability, expected",
    [
        (6.9, "HIGH", "other"),
        (7.0, "HIGH", "review"),
        (7.1, "HIGH", "review"),
        (10, "HIGH", "review"),
        (0, "HIGH", "other"),
        (9.8, "LOW", "other"),
        (9.8, "NONE", "other"),
        (7.0, "LOW", "other"),
        (6.9, "LOW", "other"),
    ],
)
def test_variant_7_decision(payload, score, availability, expected):
    metric = get_metrics(payload)[0]
    metric["cvssData"]["baseScore"] = score
    metric["cvssData"]["availabilityImpact"] = availability
    report = analyze(payload)
    assert report["decision"] == expected
    assert report["observed"] == availability
    assert report["score"] == score


@pytest.mark.parametrize(
    "variant, expected",
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_decision_for_every_variant(payload, variant, expected):
    assert analyze(payload, variant)["decision"] == expected


def test_not_found(payload):
    payload["vulnerabilities"] = []
    assert analyze(payload) == {
        "cve_id": CVE_ID,
        "variant": 7,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE,
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score(payload):
    get_cve(payload)["vulnStatus"] = "Rejected"
    report = analyze(payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_metrics(payload):
    cve = get_cve(payload)
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = None
    assert analyze(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_data(payload):
    del get_cve(payload)["vulnStatus"]
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] is not None
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize("mutation", ["no_metrics", "no_v31", "empty_list"])
def test_missing_score_is_insufficient_data(payload, mutation):
    cve = get_cve(payload)
    if mutation == "no_metrics":
        del cve["metrics"]
    elif mutation == "no_v31":
        cve["metrics"] = {"cvssMetricV30": []}
    else:
        cve["metrics"]["cvssMetricV31"] = []
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_is_insufficient_data(payload):
    del get_metrics(payload)[0]["cvssData"]["availabilityImpact"]
    report = analyze(payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad_value", [None, "MEDIUM", "high", 5, ["HIGH"], ""])
def test_invalid_variant_field_raises(payload, bad_value):
    get_metrics(payload)[0]["cvssData"]["availabilityImpact"] = bad_value
    with pytest.raises(ValueError):
        analyze(payload)


def test_primary_wins_over_earlier_secondary(payload):
    cve = get_cve(payload)
    cve["metrics"]["cvssMetricV31"] = [
        make_entry(10.0, "LOW", "Secondary", "other@example.invalid"),
        make_entry(7.0, "HIGH", "Primary", "nvd@nist.gov"),
    ]
    report = analyze(payload)
    assert report["score"] == 7.0
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "review"


def test_first_entry_used_without_primary(payload):
    get_cve(payload)["metrics"]["cvssMetricV31"] = [
        make_entry(8.0, "HIGH", "Secondary", "first@example.invalid"),
        make_entry(3.0, "LOW", "Secondary", "second@example.invalid"),
    ]
    report = analyze(payload)
    assert report["score"] == 8.0
    assert report["score_source"] == "first@example.invalid"
    assert report["decision"] == "review"


def test_first_primary_is_used_when_several(payload):
    get_cve(payload)["metrics"]["cvssMetricV31"] = [
        make_entry(5.0, "HIGH", "Secondary"),
        make_entry(6.0, "LOW", "Primary", "first-primary@example.invalid"),
        make_entry(9.0, "HIGH", "Primary", "second-primary@example.invalid"),
    ]
    report = analyze(payload)
    assert report["score"] == 6.0
    assert report["decision"] == "other"


def test_description_first_non_empty_english(payload):
    get_cve(payload)["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First English"},
        {"lang": "en", "value": "Second English"},
    ]
    assert analyze(payload)["description"] == "First English"


@pytest.mark.parametrize("descriptions", [None, [], [{"lang": "es", "value": "x"}]])
def test_description_absent_is_none(payload, descriptions):
    cve = get_cve(payload)
    if descriptions is None:
        del cve["descriptions"]
    else:
        cve["descriptions"] = descriptions
    assert analyze(payload)["description"] is None


def test_optional_report_fields_absent_are_none(payload):
    data = get_metrics(payload)[0]["cvssData"]
    metric = get_metrics(payload)[0]
    del data["version"]
    del data["vectorString"]
    del metric["source"]
    report = analyze(payload)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.__setitem__("vulnerabilities", {}),
        lambda p: p.__setitem__("vulnerabilities", None),
        lambda p: p.pop("vulnerabilities"),
        lambda p: p["vulnerabilities"].append(copy.deepcopy(p["vulnerabilities"][0])),
        lambda p: p.__setitem__("vulnerabilities", ["not-a-dict"]),
        lambda p: p["vulnerabilities"][0].pop("cve"),
        lambda p: p["vulnerabilities"][0].__setitem__("cve", []),
        lambda p: get_cve(p).__setitem__("id", "CVE-2099-99999"),
        lambda p: get_cve(p).pop("id"),
        lambda p: get_cve(p).__setitem__("vulnStatus", None),
        lambda p: get_cve(p).__setitem__("vulnStatus", ""),
        lambda p: get_cve(p).__setitem__("vulnStatus", 5),
        lambda p: get_cve(p).__setitem__("descriptions", "text"),
        lambda p: get_cve(p).__setitem__("descriptions", ["text"]),
        lambda p: get_cve(p).__setitem__("descriptions", [{"lang": "en", "value": 1}]),
        lambda p: get_cve(p).__setitem__(
            "descriptions", [{"lang": None, "value": "x"}]
        ),
        lambda p: get_cve(p).__setitem__("metrics", None),
        lambda p: get_cve(p).__setitem__("metrics", []),
        lambda p: get_cve(p)["metrics"].__setitem__("cvssMetricV31", None),
        lambda p: get_cve(p)["metrics"].__setitem__("cvssMetricV31", {}),
        lambda p: get_cve(p)["metrics"].__setitem__("cvssMetricV31", ["x"]),
        lambda p: get_metrics(p)[0].pop("cvssData"),
        lambda p: get_metrics(p)[0].__setitem__("cvssData", None),
        lambda p: get_metrics(p)[0].__setitem__("cvssData", []),
        lambda p: get_metrics(p)[0]["cvssData"].__setitem__("version", "3.0"),
        lambda p: get_metrics(p)[0]["cvssData"].__setitem__("version", None),
        lambda p: get_metrics(p)[0]["cvssData"].__setitem__("vectorString", ""),
        lambda p: get_metrics(p)[0]["cvssData"].__setitem__("vectorString", 5),
        lambda p: get_metrics(p)[0].__setitem__("source", ""),
        lambda p: get_metrics(p)[0].__setitem__("source", None),
    ],
)
def test_structure_violations_raise(payload, mutate):
    mutate(payload)
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("bad_payload", [None, [], "text", 5])
def test_non_dict_payload_raises(bad_payload):
    with pytest.raises(ValueError):
        extract_record(bad_payload, CVE_ID)


@pytest.mark.parametrize(
    "bad_score",
    [
        "9.8",
        True,
        False,
        None,
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        10.1,
        [9],
    ],
)
def test_invalid_base_score_raises(payload, bad_score):
    get_metrics(payload)[0]["cvssData"]["baseScore"] = bad_score
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_missing_base_score_raises(payload):
    del get_metrics(payload)[0]["cvssData"]["baseScore"]
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("score", [0, 0.0, 10, 10.0])
def test_score_bounds_accepted(payload, score):
    get_metrics(payload)[0]["cvssData"]["baseScore"] = score
    assert analyze(payload)["score"] == score


@pytest.mark.parametrize("variant", [0, 16, -1, True, "7", 7.0, None])
def test_invalid_variant_raises(payload, variant):
    record = extract_record(payload, CVE_ID)
    with pytest.raises(ValueError):
        build_report(record, CVE_ID, variant)


def test_functions_do_not_mutate_payload(payload):
    before = copy.deepcopy(payload)
    record = extract_record(payload, CVE_ID)
    record_before = copy.deepcopy(record)
    build_report(record, CVE_ID, VARIANT)
    assert payload == before
    assert record == record_before
