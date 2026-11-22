import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main

CVE = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def variant_7(monkeypatch):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 7)


def run(capsys, argv):
    code = main.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def fail_if_called(*args, **kwargs):
    raise AssertionError("мережевий запит не мав виконуватися")


def test_local_run_makes_report_without_network(monkeypatch, capsys, sample_path):
    monkeypatch.setattr(main.api_client, "fetch_response", fail_if_called)
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(sample_path)])
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["cve_id"] == CVE
    assert report["variant"] == 7
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "availabilityImpact",
        "expected": "HIGH",
    }
    assert report["observed"] == "HIGH"
    assert report["decision"] == "review"


def test_network_mode_uses_fetch_response(monkeypatch, capsys, payload):
    fake_fetch = Mock(return_value=payload)
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)
    code, out, _ = run(capsys, ["--cve", CVE])
    assert code == 0
    fake_fetch.assert_called_once_with(CVE)
    assert json.loads(out)["decision"] == "review"


def test_not_found_exit_code_is_zero(monkeypatch, capsys, payload):
    payload["vulnerabilities"] = []
    monkeypatch.setattr(main.api_client, "fetch_response", lambda _: payload)
    code, out, err = run(capsys, ["--cve", CVE])
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["decision"] == "not_found"
    assert report["score"] is None


def test_output_keeps_unicode(tmp_path, capsys, payload):
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Тестовий опис"
    path = tmp_path / "ua.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    code, out, _ = run(capsys, ["--cve", CVE, "--input", str(path)])
    assert code == 0
    assert "Тестовий опис" in out
    assert "\\u" not in out


def test_load_response_reads_utf8_json(tmp_path):
    path = tmp_path / "data.json"
    path.write_text('{"a": "ї"}', encoding="utf-8")
    assert main.load_response(path) == {"a": "ї"}


@pytest.mark.parametrize(
    "bad_cve",
    [
        "cve-2099-10001",
        "CVE-99-10001",
        "CVE-2099-123",
        "CVE-2099-10001 ",
        "CVE-2099-10001\n",
        "CVE-2099-1000a",
        "xCVE-2099-10001",
        "",
    ],
)
def test_invalid_cve_format_exits_2(capsys, bad_cve):
    with pytest.raises(SystemExit) as info:
        main.main(["--cve", bad_cve])
    assert info.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_exits_2(capsys):
    with pytest.raises(SystemExit) as info:
        main.main([])
    assert info.value.code == 2


@pytest.mark.parametrize("bad_variant", [0, 16, -3, True, "7", 7.0, None])
def test_invalid_variant_returns_2(monkeypatch, capsys, sample_path, bad_variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad_variant)
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(sample_path)])
    assert code == 2
    assert out == ""
    assert err != ""


def test_missing_file_returns_1(tmp_path, capsys):
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(tmp_path / "none.json")])
    assert code == 1
    assert out == ""
    assert err != ""
    assert "Traceback" not in err


def test_invalid_json_file_returns_1(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(path)])
    assert code == 1
    assert out == ""
    assert "JSON" in err


def test_non_utf8_file_returns_1(tmp_path, capsys):
    path = tmp_path / "bin.json"
    path.write_bytes(b"\xff\xfe\x00\x80")
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(path)])
    assert code == 1
    assert out == ""
    assert err != ""


def test_id_mismatch_returns_1(capsys, sample_path):
    code, out, err = run(
        capsys, ["--cve", "CVE-2099-99999", "--input", str(sample_path)]
    )
    assert code == 1
    assert out == ""
    assert err != ""


def test_invalid_score_in_file_returns_1(tmp_path, capsys, payload):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = "9.8"
    path = tmp_path / "bad_score.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    code, out, err = run(capsys, ["--cve", CVE, "--input", str(path)])
    assert code == 1
    assert out == ""
    assert err != ""


def make_http_error(status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "server said no", response=response
    )
    return response


def test_http_404_is_error_not_not_found(monkeypatch, capsys):
    monkeypatch.setattr(
        main.api_client.requests, "get", Mock(return_value=make_http_error(404))
    )
    code, out, err = run(capsys, ["--cve", CVE])
    assert code == 1
    assert out == ""
    assert "404" in err
    assert "not_found" not in err


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ReadTimeout("slow"),
        requests.exceptions.ConnectTimeout("slow"),
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.TooManyRedirects("loop"),
    ],
)
def test_network_errors_return_1(monkeypatch, capsys, error):
    monkeypatch.setattr(main.api_client.requests, "get", Mock(side_effect=error))
    code, out, err = run(capsys, ["--cve", CVE])
    assert code == 1
    assert out == ""
    assert err != ""
    assert "Traceback" not in err


def test_invalid_json_from_server_returns_1(monkeypatch, capsys):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(main.api_client.requests, "get", Mock(return_value=response))
    code, out, err = run(capsys, ["--cve", CVE])
    assert code == 1
    assert out == ""
    assert "JSON" in err


def test_redirect_status_returns_1(monkeypatch, capsys):
    response = Mock(spec=requests.Response)
    response.status_code = 302
    monkeypatch.setattr(main.api_client.requests, "get", Mock(return_value=response))
    code, _, err = run(capsys, ["--cve", CVE])
    assert code == 1
    assert "302" in err


def test_secrets_and_exception_text_are_not_printed(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    error = requests.exceptions.ConnectionError("failed with apiKey fake-key-123")
    monkeypatch.setattr(main.api_client.requests, "get", Mock(side_effect=error))
    code, out, err = run(capsys, ["--cve", CVE])
    assert code == 1
    assert "fake-key-123" not in out + err
    assert "apiKey" not in out + err
