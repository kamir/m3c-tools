"""Successful API JSON must not copy the loaded cleartext key into MCP output."""

import asyncio
import io
import json

import pytest

import server


@pytest.fixture(autouse=True)
def bound_api(monkeypatch):
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "")
    monkeypatch.setattr(server, "API_URL", "https://a.example:443/prefix")
    monkeypatch.setattr(server, "API_KEY", "synthetic-key")
    monkeypatch.setattr(server, "API_KEY_ORIGIN", ("https", "a.example", 443))
    monkeypatch.setattr(server, "ALLOW_LOOPBACK_HTTP", False)


def respond(monkeypatch, payload):
    class Opener:
        def open(self, req, timeout):
            return io.BytesIO(payload)

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda _: Opener())


@pytest.mark.parametrize("payload", [
    '"synthetic-key"',
    '{"display_name":"prefix synthetic-key suffix","skills":[]}',
    '{"nested":[false,null,12,{"inside":["prefix synthetic-key suffix"]}]}',
    '{"prefix synthetic-key suffix":{"safe":"value"}}',
    '{"name":"synthetic\\u002dkey"}',
    '{"synthetic\\u002dkey":"safe"}',
])
@pytest.mark.parametrize("operation", ["get", "post", "data_source"])
def test_reflected_success_response_is_rejected(operation, payload, monkeypatch):
    respond(monkeypatch, payload.encode())
    if operation == "get":
        result = asyncio.run(server._api_get("/api/profile"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api/import", {}))
    else:
        result = asyncio.run(server.skill_data_source_query("ds:example"))
        assert result["ok"] is False and result["error_class"] == "unsafe_response"
        assert "data_source" not in result
    assert server._UNSAFE_API_RESPONSE in str(result)
    assert "synthetic-key" not in str(result)
    assert "display_name" not in str(result)


@pytest.mark.parametrize("payload", [
    {"safe": [1, 0, True, False, None, "synthetic", {"key": "ordinary text"}]},
    [None, False, 1.5, ["safe", {"name": "Alice"}]],
    "ordinary text",
    None,
    True,
    123,
])
def test_safe_json_is_returned_without_mutation(payload):
    original = json.dumps(payload)
    assert server._checked_api_response(payload) is payload
    assert json.dumps(payload) == original


@pytest.mark.parametrize("key", ["", "123", "True", "None"])
def test_empty_key_and_nonstring_json_values_do_not_match(key, monkeypatch):
    monkeypatch.setattr(server, "API_KEY", key)
    payload = {"items": [123, True, None]}
    assert server._checked_api_response(payload) is payload


@pytest.mark.parametrize("operation", ["profile", "discover", "usage", "import", "data_source"])
def test_public_tools_do_not_render_reflected_key(operation, tmp_path, monkeypatch):
    respond(monkeypatch, b'{"display_name":"synthetic-key","skills":[],"suggestions":[],"new_mastery":"synthetic-key"}')
    save = []
    monkeypatch.setattr(server, "_save_usage_local", save.append)
    if operation == "profile":
        result = asyncio.run(server.skill_profile())
    elif operation == "discover":
        result = asyncio.run(server.skill_discover())
    elif operation == "usage":
        result = asyncio.run(server.skill_usage("synthetic-skill"))
        assert len(save) == 1
    elif operation == "import":
        scan = tmp_path / "scan.json"
        scan.write_text('{"skills":[]}')
        result = asyncio.run(server.skill_import(str(scan)))
    else:
        result = asyncio.run(server.skill_data_source_query("ds:example"))
        assert result["ok"] is False
    assert "synthetic-key" not in str(result)
    assert server._UNSAFE_API_RESPONSE in str(result)


@pytest.mark.parametrize("operation", ["get", "post", "data_source"])
def test_safe_response_consumers_continue_working(operation, monkeypatch):
    payload = {"id": "ds:example", "items": [1, False, None, {"name": "Alice"}]}
    respond(monkeypatch, json.dumps(payload).encode())
    if operation == "get":
        result = asyncio.run(server._api_get("/api/profile"))
    elif operation == "post":
        result = asyncio.run(server._api_post("/api/import", {}))
    else:
        result = asyncio.run(server.skill_data_source_query("ds:example"))
        assert result["ok"] is True
        result = result["data_source"]
    assert result == payload


def test_anonymous_registry_without_loaded_key_still_returns_json(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server, "API_KEY_ORIGIN", None)
    monkeypatch.setattr(server, "API_CONFIG_ERROR", "independent pin missing")
    # Without a loaded key there is no known value to match, even for this fixture.
    payload = {"id": "ds:example", "nested": ["synthetic-key"]}
    respond(monkeypatch, json.dumps(payload).encode())
    result = asyncio.run(server.skill_data_source_query("ds:example", registry_url="https://external.example"))
    assert result["ok"] is True and result["data_source"] == payload
