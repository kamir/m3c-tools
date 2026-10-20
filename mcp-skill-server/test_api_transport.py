"""API credentials and request bodies must remain bound to their origin."""

import asyncio
import io
import json
import urllib.error
import urllib.request
from unittest.mock import Mock

import pytest

import server


@pytest.fixture(autouse=True)
def api_configuration(monkeypatch):
    monkeypatch.setattr(server, "API_URL", "https://registry.example")
    monkeypatch.setattr(server, "API_KEY", "synthetic-test-credential")
    monkeypatch.setenv("M3C_USER_ID", "alice")


@pytest.mark.parametrize("url", [
    "https://REGISTRY.example/path", "https://registry.example:443/path",
])
def test_equivalent_origins_receive_credentials(url):
    assert server._api_credentials(url, "alice") == {
        "X-API-KEY": "synthetic-test-credential", "X-User-ID": "alice",
    }


@pytest.mark.parametrize("url", [
    "https://other.example/path", "https://registry.example:8443/path",
    "https://registry.example:0/path",
    "http://localhost:8080/path", "https://registry.example.evil.example/path",
])
def test_other_origins_do_not_receive_local_credentials(url):
    assert server._api_credentials(url, "alice") == {}


@pytest.mark.parametrize("url", [
    "http://registry.example/path", "file:///tmp/data", "ftp://registry.example/data",
    "https://alice:password@registry.example/path", "https://registry.example/#fragment",
    "https://registry.example:invalid/path", "https://registry.example:65536/path",
    "//registry.example/path",
    "https://registry.example/\npath", " https://registry.example/path",
])
def test_invalid_or_insecure_api_url_is_rejected(url):
    with pytest.raises(ValueError):
        server._api_origin(url)


@pytest.mark.parametrize("url", [
    "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
])
def test_loopback_development_api_is_supported(url, monkeypatch):
    monkeypatch.setattr(server, "API_URL", url)
    assert server._api_credentials(url + "/api", "alice")["X-API-KEY"]


@pytest.mark.parametrize("target", [
    "https://other.example/path", "https://registry.example:8443/path",
    "http://registry.example/path", "http://localhost/path",
    "https://alice:password@registry.example/path",
])
@pytest.mark.parametrize("method,code", [
    ("GET", 301), ("GET", 302), ("POST", 302), ("POST", 303), ("POST", 307), ("POST", 308),
])
def test_unsafe_redirect_is_blocked_before_followup(target, method, code):
    request = urllib.request.Request(
        "https://registry.example/api", method=method,
        data=b"private body" if method == "POST" else None,
        headers={"X-API-KEY": "synthetic-test-credential", "X-User-ID": "alice"},
    )
    handler = server._SameOriginRedirectHandler()
    handler.parent = Mock()
    with pytest.raises(urllib.error.URLError, match="redirect blocked"):
        handler.http_error_302(request, io.BytesIO(), code, "Redirect", {"location": target})
    handler.parent.open.assert_not_called()


def test_same_origin_redirect_preserves_authentication():
    request = urllib.request.Request(
        "https://registry.example/api", headers={"X-API-KEY": "synthetic-test-credential"},
    )
    redirected = server._SameOriginRedirectHandler().redirect_request(
        request, None, 302, "Redirect", {}, "https://registry.example:443/new",
    )
    assert redirected.get_header("X-api-key") == "synthetic-test-credential"


@pytest.mark.parametrize("operation", ["get", "post", "data_source", "external_data_source"])
def test_all_api_entrypoints_use_restrictive_opener(operation, monkeypatch):
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return io.BytesIO(json.dumps({"id": "ds:example"}).encode())

    def build_opener(handler):
        assert isinstance(handler, server._SameOriginRedirectHandler)
        return Opener()

    monkeypatch.setattr(server.urllib.request, "build_opener", build_opener)
    if operation == "get":
        result = asyncio.run(server._api_get("/api/test"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api/test", {"private": "body"}))
    else:
        external = operation == "external_data_source"
        result = asyncio.run(server.skill_data_source_query(
            "ds:example", registry_url="https://other.example" if external else "",
        ))
        assert result["ok"] is True
    request = captured["request"]
    if operation == "external_data_source":
        assert request.get_header("X-api-key") is None
        assert request.get_header("X-user-id") is None
    else:
        assert request.get_header("X-api-key") == "synthetic-test-credential"
    assert isinstance(result, dict)


def test_plaintext_external_query_never_opens_connection(monkeypatch):
    opener = Mock()
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    result = asyncio.run(server.skill_data_source_query("ds:example", registry_url="http://other.example"))
    assert result["ok"] is False
    assert "HTTPS" in result["stderr"]
    opener.assert_not_called()
