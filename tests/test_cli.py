"""CLI wiring: the serving policy (TLS, credentials) lives here, so it is tested here."""

from __future__ import annotations

import base64

import pytest

from tsf_anonymizer import cli


@pytest.fixture
def uvicorn_calls(monkeypatch):
    calls = []
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    return calls


def test_serve_defaults_to_plain_http(uvicorn_calls, tmp_path):
    assert cli.main(["serve", "--data-dir", str(tmp_path)]) == 0
    assert uvicorn_calls[0]["ssl_certfile"] is None
    assert uvicorn_calls[0]["ssl_keyfile"] is None


def test_serve_passes_the_tls_material_to_uvicorn(uvicorn_calls, tmp_path):
    cert, key = tmp_path / "server.crt", tmp_path / "server.key"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    assert cli.main(["serve", "--data-dir", str(tmp_path),
                     "--ssl-certfile", str(cert), "--ssl-keyfile", str(key)]) == 0
    assert uvicorn_calls[0] == {"host": "0.0.0.0", "port": 8090,
                                "ssl_certfile": str(cert), "ssl_keyfile": str(key)}


def test_a_certificate_without_its_key_is_refused(uvicorn_calls, tmp_path):
    cert = tmp_path / "server.crt"
    cert.write_text("cert", encoding="utf-8")
    assert cli.main(["serve", "--data-dir", str(tmp_path), "--ssl-certfile", str(cert)]) == 2
    assert not uvicorn_calls


def test_a_missing_certificate_stops_the_server_instead_of_downgrading(uvicorn_calls, tmp_path):
    # Silently serving plain HTTP because a file moved is how an exposed port
    # ends up in the clear.
    assert cli.main(["serve", "--data-dir", str(tmp_path),
                     "--ssl-certfile", str(tmp_path / "gone.crt"),
                     "--ssl-keyfile", str(tmp_path / "gone.key")]) == 2
    assert not uvicorn_calls


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def probes(monkeypatch):
    seen = []
    import urllib.request

    def fake_urlopen(req, timeout=None, context=None):
        seen.append((req, context))
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return seen


def test_healthcheck_authenticates_like_any_other_client(probes, monkeypatch):
    monkeypatch.setenv("TSF_USERNAME", "ops")
    monkeypatch.setenv("TSF_PASSWORD", "s3cret")
    monkeypatch.delenv("TSF_TLS_CERT", raising=False)
    assert cli.main(["healthcheck"]) == 0
    req, context = probes[0]
    assert req.full_url == "http://127.0.0.1:8090/api/health"
    assert req.get_header("Authorization") == "Basic " + base64.b64encode(b"ops:s3cret").decode()
    assert context is None


def test_healthcheck_speaks_https_when_the_server_does(probes, monkeypatch):
    monkeypatch.setenv("TSF_TLS_CERT", "/certs/server.crt")
    monkeypatch.delenv("TSF_PASSWORD", raising=False)
    assert cli.main(["healthcheck", "--port", "9443"]) == 0
    req, context = probes[0]
    assert req.full_url == "https://127.0.0.1:9443/api/health"
    assert req.get_header("Authorization") is None
    assert context is not None and not context.check_hostname


def test_healthcheck_reports_a_dead_server(monkeypatch):
    import urllib.request

    def boom(*a, **kw):
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert cli.main(["healthcheck"]) == 1
