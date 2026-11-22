import copy
import math
from typing import Any, NoReturn

RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

ALLOWED_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def _invalid(message: str) -> NoReturn:
    raise ValueError(message)


def _optional_str(container: dict[str, Any], key: str, label: str) -> str | None:
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        _invalid(f"Поле {label} має бути непорожнім рядком.")
    return value


def _pick_description(cve: dict[str, Any]) -> str | None:
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        _invalid("Поле descriptions має бути списком.")
    chosen = None
    for item in descriptions:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("lang"), str)
            or not isinstance(item.get("value"), str)
        ):
            _invalid("Елемент descriptions має містити рядки lang і value.")
        if chosen is None and item["lang"] == "en" and item["value"].strip():
            chosen = item["value"]
    return chosen


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        _invalid("Поле metrics має бути об'єктом.")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    if not isinstance(items, list):
        _invalid("Поле cvssMetricV31 має бути списком.")
    if not items:
        return None
    if not all(isinstance(item, dict) for item in items):
        _invalid("Елементи cvssMetricV31 мають бути об'єктами.")
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def _parse_cvss(entry: dict[str, Any]) -> dict[str, Any]:
    data = entry.get("cvssData")
    if not isinstance(data, dict):
        _invalid("Поле cvssData має бути об'єктом.")
    score = data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        _invalid("baseScore має бути скінченним числом від 0 до 10.")
    version = _optional_str(data, "version", "cvssData.version")
    if version is not None and version != "3.1":
        _invalid("Підтримується лише CVSS версії 3.1.")
    return {
        "version": version,
        "vector": _optional_str(data, "vectorString", "cvssData.vectorString"),
        "source": _optional_str(entry, "source", "source"),
        "score": score,
        "data": copy.deepcopy(data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    Запис має вигляд::

        {
            "description": str | None,   # перший англійський непорожній опис
            "vuln_status": str | None,
            "cvss": None | {
                "version": str | None,   # "3.1" або None
                "vector": str | None,
                "source": str | None,
                "score": int | float,    # скінченне, 0..10, не bool
                "data": dict,            # копія cvssData вибраної оцінки
            },
        }

    ``cvss`` дорівнює None, якщо статус Rejected або відсутній, або оцінки v3.1
    немає. Некоректна структура піднімає ValueError. payload не змінюється.
    """
    if not isinstance(payload, dict):
        _invalid("Відповідь має бути JSON-об'єктом.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        _invalid("Поле vulnerabilities має бути списком.")
    if len(vulnerabilities) > 1:
        _invalid("Для точного cveId очікується не більше одного запису.")
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        _invalid("Елемент vulnerabilities має містити об'єкт cve.")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        _invalid("Ідентифікатор у відповіді не збігається із запитаним.")

    status = _optional_str(cve, "vulnStatus", "vulnStatus")
    description = _pick_description(cve)
    record: dict[str, Any] = {
        "description": description,
        "vuln_status": status,
        "cvss": None,
    }
    if status is None or status == "Rejected":
        return record

    entry = _select_metric(cve)
    if entry is not None:
        record["cvss"] = _parse_cvss(entry)
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта до запису й повертає словник звіту."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in RULES
    ):
        _invalid("Номер варіанта має бути цілим числом від 1 до 15.")
    threshold, field, expected = RULES[variant]
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]
    if field not in cvss["data"]:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss["data"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        _invalid(f"Недопустиме значення поля {field}.")
    report["observed"] = observed
    matches = cvss["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
