import os
from typing import Any

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"Unexpected HTTP status: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту; apiKey додається, лише якщо ключ задано."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON.

    Піднімає requests.exceptions.* для мережевих помилок, HTTPError для
    помилкових статусів, JSONDecodeError для неправильного тіла та
    UnexpectedStatusError для статусів, відмінних від 200 (зокрема 3xx).
    """
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
