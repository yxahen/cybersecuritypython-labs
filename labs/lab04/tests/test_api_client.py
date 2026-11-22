from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE = "CVE-2099-10001"


def make_response(status=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def patch_get(monkeypatch, **kwargs):
    fake_get = Mock(**kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_headers_key_is_stripped(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123 \n")
    assert api_client.build_headers()["apiKey"] == "fake-key-123"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_key_is_read_at_call_time(monkeypatch):
    first = api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "later-key")
    assert "apiKey" not in first
    assert api_client.build_headers()["apiKey"] == "later-key"


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(200, payload)
    fake_get = patch_get(monkeypatch, return_value=response)

    assert api_client.fetch_response(CVE) == payload

    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_api_key_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = patch_get(monkeypatch, return_value=make_response(200, {}))
    api_client.fetch_response(CVE)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"]["apiKey"] == "fake-key-123"
    assert "fake-key-123" not in str(fake_get.call_args.args)
    assert "fake-key-123" not in str(kwargs["params"])


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ConnectTimeout("boom"),
        requests.exceptions.ReadTimeout("boom"),
    ],
)
def test_network_errors_propagate(monkeypatch, error):
    patch_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response(CVE)


@pytest.mark.parametrize("status", [404, 429, 500])
def test_http_error_propagates(monkeypatch, status):
    response = make_response(status)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status} error", response=response
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.HTTPError) as info:
        api_client.fetch_response(CVE)
    assert info.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [201, 204, 301, 302])
def test_unexpected_success_or_redirect_status(monkeypatch, status):
    patch_get(monkeypatch, return_value=make_response(status, {}))
    with pytest.raises(api_client.UnexpectedStatusError) as info:
        api_client.fetch_response(CVE)
    assert info.value.status_code == status


def test_invalid_json_propagates(monkeypatch):
    response = make_response(200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE)
