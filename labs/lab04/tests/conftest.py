import copy
import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"
CVE_ID = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_path() -> Path:
    return SAMPLE_PATH


@pytest.fixture
def payload() -> dict:
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        return copy.deepcopy(json.load(file))


def get_cve(payload: dict) -> dict:
    return payload["vulnerabilities"][0]["cve"]


def get_metrics(payload: dict) -> list:
    return get_cve(payload)["metrics"]["cvssMetricV31"]
