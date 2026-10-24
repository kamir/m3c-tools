"""Initial target assignment must be validated before any API-key lookup."""

import asyncio
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request
from unittest.mock import Mock

import pytest

from api_connection import parse_api_base, resolve_api_connection
import server


@pytest.mark.parametrize("raw,allow,origin,base", [
    ("HTTPS://API.Example/api/v1/", False, ("https", "api.example", 443), "https://api.example:443/api/v1/"),
    ("https://api.example:00443/root", False, ("https", "api.example", 443), "https://api.example:443/root"),
    ("https://api.example/über/[v1]", False, ("https", "api.example", 443), "https://api.example:443/%C3%BCber/%5Bv1%5D"),
    ("https://api.example:8443/a%2Fb", False, ("https", "api.example", 8443), "https://api.example:8443/a%2Fb"),
    ("https://[0:0:0:0:0:0:0:1]/api", False, ("https", "::1", 443), "https://[::1]:443/api"),
    ("http://LOCALHOST/api", True, ("http", "localhost", 80), "http://localhost:80/api"),
    ("http://127.10.20.30:8080/api", True, ("http", "127.10.20.30", 8080), "http://127.10.20.30:8080/api"),
    ("http://[::ffff:127.0.0.1]/", True, ("http", "127.0.0.1", 80), "http://127.0.0.1:80/"),
])
def test_go_origin_positive_contract(raw, allow, origin, base):
    assert parse_api_base(raw, allow) == (base, origin)
    assert parse_api_base(base, allow) == (base, origin)


@pytest.mark.parametrize("raw", [
    "", "api.example", "//api.example", "https:api.example", "ftp://api.example", "http://api.example",
    "http://localhost", "http://127.0.0.1", "http://[::1]", "https://user:secret@api.example",
    "https://api.example?", "https://api.example?key=synthetic", "https://api.example#",
    " https://api.example", "https://api.example\n", "https://api.example/%0d%0a", "https://api.example/%7f",
    "https://api.example/\\x", "https://api.example/%5cx", "https://api.example:", "https://api.example:0",
    "https://api.example:65536", "https://api.example:-1", "https://api.example:+443", "https://api.example:abc",
    "https://api.example:999999999999999999999", "https://", "https://.example", "https://example..com",
    "https://-example.com", "https://example-.com", "https://exa_mple.com", "https://éxample.com",
    "https://[127.0.0.1]", "https://::1:443", "https://[fe80::1%25lo0]", "https://api.example/%XX",
])
def test_go_origin_negative_contract(raw):
    with pytest.raises(ValueError):
        parse_api_base(raw)


@pytest.mark.parametrize("raw", [
    "http://localhost.evil.example", "http://localhost.", "http://127.1", "http://2130706433",
    "http://0x7f000001", "http://192.168.1.1", "http://[::]", "http://[::ffff:192.168.1.1]", "http://loopback.example",
])
def test_go_nonloopback_contract(raw):
    with pytest.raises(ValueError):
        parse_api_base(raw, True)


def test_query_is_only_permitted_in_request():
    raw = "https://api.example/prefix/discover?limit=10"
    with pytest.raises(ValueError):
        parse_api_base(raw)
    assert parse_api_base(raw, request=True)[1] == ("https", "api.example", 443)


@pytest.mark.parametrize("target,pin,http", [
    ("https://b.example", "https://a.example", ""),
    ("https://a.example", "", ""),
    ("https://user:secret@a.example", "https://a.example", ""),
    ("http://localhost:8000", "http://localhost:8000", ""),
    ("http://localhost:8000", "http://localhost:8000", "true"),
    ("https://a.example", "https://a.example/api", ""),
    ("https://a.example", "https://a.example?", ""),
])
def test_bootstrap_rejection_never_reads_secret(target, pin, http):
    env = {"M3C_API_URL": target, "M3C_API_KEY_ORIGIN": pin, "M3C_ALLOW_LOOPBACK_HTTP": http}
    reader = Mock(side_effect=AssertionError("must not read session"))

    def getenv(name, default=""):
        assert name != "M3C_API_KEY", "must not even read environment key"
        return env.get(name, default)

    config = resolve_api_connection(getenv, reader)
    assert config.error and not config.key
    assert "secret" not in config.error
    reader.assert_not_called()


def test_priority_default_and_source_provenance():
    reader = Mock(return_value="legacy-key")
    env = {"M3C_API_KEY_ORIGIN": "https://ONBOARDING.guide:443", "M3C_API_KEY": "env-key"}
    config = resolve_api_connection(env.get, reader)
    assert config.base_url == "https://onboarding.guide:443"
    assert config.key == "env-key" and config.source == "environment-operator-assignment"
    assert "env-key" not in repr(config)
    reader.assert_not_called()
    env["M3C_API_KEY"] = ""
    config = resolve_api_connection(env.get, reader)
    assert config.key == "legacy-key" and config.source == "legacy-session-operator-assignment"
    reader.assert_called_once()


@pytest.mark.parametrize("value", [None, {}, 123, "", "   ", "synthetic\nkey", "synthetic\x00key"])
def test_invalid_legacy_session_never_claims_login_repair(value):
    config = resolve_api_connection({"M3C_API_KEY_ORIGIN": "https://onboarding.guide"}.get, lambda: value)
    assert config.error and not config.key
    assert "context-only" in config.error
    assert "authenticate via skillctl" not in config.error


def test_reader_error_is_redacted():
    def read():
        raise OSError("synthetic-secret-path")
    config = resolve_api_connection({"M3C_API_KEY_ORIGIN": "https://onboarding.guide"}.get, read)
    assert config.error and "synthetic-secret-path" not in config.error


@pytest.fixture
def bound_api(monkeypatch):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "")
    monkeypatch.setattr(server, "API_URL", "https://a.example:443/prefix")
    monkeypatch.setattr(server, "API_KEY", "synthetic-key")
    monkeypatch.setattr(server, "API_KEY_ORIGIN", ("https", "a.example", 443))
    monkeypatch.setattr(server, "ALLOW_LOOPBACK_HTTP", False)


@pytest.mark.parametrize("operation", ["get", "post", "data_source", "direct"])
def test_mutable_target_cannot_rebind_existing_key(operation, monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_URL", "https://b.example")
    opener = Mock(side_effect=AssertionError("transport must not run"))
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    if operation == "get":
        result = asyncio.run(server._api_get("/api/discover?limit=10"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api/import", {"private": "payload"}))
    elif operation == "data_source":
        result = asyncio.run(server.skill_data_source_query("ds:example"))
    else:
        with pytest.raises(ValueError):
            server._open_api_request(urllib.request.Request("https://b.example/api", headers={"X-API-KEY": "synthetic-key"}), 1)
        return
    assert "synthetic-key" not in str(result)
    assert not isinstance(result, dict) or result["ok"] is False
    opener.assert_not_called()


@pytest.mark.parametrize("operation", ["get", "post", "data_source"])
def test_http_and_transport_errors_do_not_reflect_secrets(operation, monkeypatch, bound_api):
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "synthetic-key", {}, io.BytesIO(b"synthetic-key body"))
    monkeypatch.setattr(server.urllib.request, "build_opener", lambda _: Opener())
    if operation == "get":
        result = asyncio.run(server._api_get("/api"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api", {}))
    else:
        result = asyncio.run(server.skill_data_source_query("ds:example"))
    assert "401" in str(result) and "synthetic-key" not in str(result)


@pytest.mark.parametrize("pin", ["", "https://b.example", "https://a.example?query"])
def test_real_import_keeps_local_tools_available_without_session_read(tmp_path, pin):
    env = os.environ.copy()
    for name in ("M3C_API_KEY", "M3C_ALLOW_LOOPBACK_HTTP"):
        env.pop(name, None)
    env.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path), M3C_TOKEN_STORE="file", M3C_TEST_KEYCHAIN="0",
               M3C_API_URL="https://a.example", M3C_API_KEY_ORIGIN=pin, PYTHONDONTWRITEBYTECODE="1")
    code = '''
import asyncio, builtins, json
original_open = builtins.open
reads = []
def guarded_open(path, *args, **kwargs):
    if str(path).endswith("er1_session.json"):
        reads.append(str(path))
        raise AssertionError("session must not be opened")
    return original_open(path, *args, **kwargs)
builtins.open = guarded_open
import server
assert server.API_CONFIG_ERROR and not server.API_KEY
assert reads == [], "bootstrap attempted a forbidden session read"
async def verify():
    tools = await server.mcp.list_tools()
    assert any(tool.name == "skill_scan" for tool in tools)
    assert await server._api_get("/api/discover?limit=10") == server.API_CONFIG_ERROR
asyncio.run(verify())
print(json.dumps({"blocked": True, "local_tools": True}))
'''
    result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"blocked": True, "local_tools": True}


def test_standalone_script_imports_sibling_module_from_other_cwd(tmp_path):
    env = os.environ.copy()
    env.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path), M3C_API_KEY="", M3C_API_KEY_ORIGIN="",
               M3C_API_URL="https://a.example", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, str(Path(server.__file__).resolve())], cwd=tmp_path,
                            env=env, input="", capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "ModuleNotFoundError" not in result.stderr


def test_invalid_bootstrap_is_visible_without_transport(monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "API configuration blocked: independent pin required")
    opener = Mock()
    save = Mock()
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    monkeypatch.setattr(server, "_save_usage_local", save)
    result = asyncio.run(server.skill_usage("synthetic-skill"))
    assert "configuration blocked" in result
    save.assert_called_once()
    opener.assert_not_called()


@pytest.mark.parametrize("session,env_key,expected_source", [
    ({"api_key": "synthetic-session-key"}, "", "legacy-session-operator-assignment"),
    ({"api_key": "synthetic-session-key"}, "synthetic-env-key", "environment-operator-assignment"),
    ({"context_id": "synthetic-context", "saved_at": "2026-01-01"}, "", "missing"),
])
def test_real_bootstrap_legacy_priority_and_context_only(tmp_path, session, env_key, expected_source):
    directory = tmp_path / ".m3c-tools"
    directory.mkdir()
    (directory / "er1_session.json").write_text(json.dumps(session))
    env = os.environ.copy()
    env.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path), M3C_API_KEY=env_key,
               M3C_API_KEY_ORIGIN="https://a.example", M3C_API_URL="https://a.example/prefix",
               M3C_ALLOW_LOOPBACK_HTTP="", PYTHONDONTWRITEBYTECODE="1")
    code = """
import json, server
print(json.dumps({"source": server._api_connection.source if server.API_KEY else "missing",
                  "error": server.API_CONFIG_ERROR, "base": server.API_URL}))
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent,
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source"] == expected_source
    assert report["base"] == "https://a.example:443/prefix"
    if expected_source == "missing":
        assert "context-only" in report["error"]
    else:
        assert report["error"] == ""


@pytest.mark.parametrize("operation", ["get", "post", "data_source"])
def test_arbitrary_transport_exception_is_redacted(operation, monkeypatch, bound_api):
    opener = Mock(side_effect=OSError("synthetic-key private-response-body"))
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    if operation == "get":
        result = asyncio.run(server._api_get("/api"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api", {}))
    else:
        result = asyncio.run(server.skill_data_source_query("ds:example"))
    assert "synthetic-key" not in str(result)
    assert "private-response-body" not in str(result)


@pytest.mark.parametrize("raw", [
    '{"api_key":"synthetic-first","api_key":"synthetic-last"}',
    '{"api_key":"synthetic-first","api\\u005fkey":"synthetic-last"}',
    '{"api_key":"synthetic-key","metadata":{"x":1,"x":2}}',
])
def test_legacy_session_duplicate_keys_fail_closed(tmp_path, monkeypatch, raw):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    directory = tmp_path / ".m3c-tools"
    directory.mkdir()
    (directory / "er1_session.json").write_text(raw)
    with pytest.raises(ValueError, match="ambiguous legacy session"):
        server._read_legacy_api_key()
    config = resolve_api_connection({"M3C_API_KEY_ORIGIN": "https://onboarding.guide"}.get, server._read_legacy_api_key)
    assert config.error and not config.key
    assert "synthetic" not in config.error


@pytest.mark.parametrize("base", ["https://a.example/prefix", "https://a.example/prefix/"])
@pytest.mark.parametrize("operation", ["get", "post"])
def test_base_suffix_does_not_add_route_separator(base, operation, monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_URL", base)
    seen = []

    class Opener:
        def open(self, req, timeout):
            seen.append(req.full_url)
            return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda _: Opener())
    if operation == "get":
        result = asyncio.run(server._api_get("/api/discover?limit=10"))
        assert seen == ["https://a.example/prefix/api/discover?limit=10"]
    else:
        result = asyncio.run(server._api_post("/api/import", {"skills": []}))
        assert seen == ["https://a.example/prefix/api/import"]
    assert result == {"ok": True}


@pytest.mark.parametrize("bootstrap_error", ["independent pin missing", "invalid transport", "key unavailable"])
def test_explicit_anonymous_data_source_survives_invalid_bootstrap(bootstrap_error, monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", bootstrap_error)
    seen = []

    class Opener:
        def open(self, req, timeout):
            seen.append(req)
            assert req.get_method() == "GET" and req.data is None
            assert not any(name.lower().startswith("x-") or name.lower() in ("authorization", "cookie") for name, _ in req.header_items())
            return io.BytesIO(b'{"id":"ds:example"}')

    def build_opener(handler):
        assert isinstance(handler, server._SameOriginRedirectHandler)
        return Opener()

    monkeypatch.setattr(server.urllib.request, "build_opener", build_opener)
    result = asyncio.run(server.skill_data_source_query("ds:example", registry_url="https://external.example/prefix"))
    assert result["ok"] is True and len(seen) == 1
    assert seen[0].full_url == "https://external.example/prefix/api/skills/data-sources/ds:example"
    # A default/global target is never reclassified as an explicit anonymous URL.
    assert asyncio.run(server.skill_data_source_query("ds:example"))["ok"] is False
    assert asyncio.run(server._api_get("/api/profile")) == bootstrap_error
    assert asyncio.run(server._api_post("/api/import", {})) == bootstrap_error
    assert len(seen) == 1


@pytest.mark.parametrize("url", ["http://external.example", "https://user:synthetic@external.example", "https://external.example:0"])
def test_invalid_explicit_anonymous_source_never_opens(url, monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "pin missing")
    opener = Mock()
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    result = asyncio.run(server.skill_data_source_query("ds:example", registry_url=url))
    assert result["ok"] is False
    opener.assert_not_called()


@pytest.mark.parametrize("method,body,headers,explicit", [
    ("GET", None, {}, False),
    ("GET", None, {"X-API-KEY": "synthetic-key"}, True),
    ("GET", None, {"Authorization": "Bearer synthetic-key"}, True),
    ("GET", None, {"Proxy-Authorization": "synthetic-key"}, True),
    ("GET", None, {"Cookie": "synthetic-key"}, True),
    ("GET", None, {"X-User-ID": "synthetic-user"}, True),
    ("GET", None, {"X-Context-ID": "synthetic-context"}, True),
    ("GET", None, {"X-Device-ID": "synthetic-device"}, True),
    ("POST", b"private", {}, True),
    ("POST", None, {}, True),
    ("GET", b"private", {}, True),
])
def test_invalid_bootstrap_cannot_bypass_via_direct_opener(method, body, headers, explicit, monkeypatch, bound_api):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "pin missing")
    opener = Mock()
    monkeypatch.setattr(server.urllib.request, "build_opener", opener)
    req = urllib.request.Request("https://external.example/api", data=body, headers=headers, method=method)
    with pytest.raises(ValueError):
        server._open_api_request(req, 1, allow_anonymous=explicit)
    opener.assert_not_called()



def test_explicit_same_origin_registry_preserves_bound_credentials(monkeypatch, bound_api):
    seen = []

    class Opener:
        def open(self, req, timeout):
            seen.append(req)
            return io.BytesIO(b'{"id":"ds:example"}')

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda _: Opener())
    result = asyncio.run(server.skill_data_source_query("ds:example", registry_url="https://A.example:443/prefix"))
    assert result["ok"] is True and len(seen) == 1
    assert seen[0].get_header("X-api-key") == "synthetic-key"
    assert seen[0].get_header("X-user-id") is not None
