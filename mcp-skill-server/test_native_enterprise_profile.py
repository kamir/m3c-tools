"""Native operator intent is a denial disposition, never a mutation grant."""
import asyncio
import json
from pathlib import Path
import sys
from contextlib import ExitStack
from unittest.mock import patch

import server
from native_agent_binding import capture_native_agent_binding
from test_enterprise_profile import test_real_cli_enterprise_profile_and_stdio as run_http_bridge


UNAVAILABLE = (
    "native Enterprise mutation requires durable verified revocation history; "
    "this version denies the operation"
)


def test_native_enterprise_profile_denied_before_exec(monkeypatch, tmp_path):
    profile = tmp_path / "native.json"
    # Python discriminates the schema; only Go performs native trust validation.
    profile.write_text(json.dumps({"schema": "m3c.enterprise-project-profile/v2"}))
    for name, value in {
        "SKILLCTL_ENTERPRISE_PROFILE": str(profile),
        "SKILLCTL_PROJECT_ROOT": str(tmp_path),
        "SKILLCTL_ARTIFACT_HOME": str(tmp_path),
        "SKILLCTL_BIN": str(tmp_path / "must-not-be-resolved"),
    }.items():
        monkeypatch.setenv(name, value)
    with patch.object(server, "_resolve_skillctl_bin", side_effect=AssertionError("binary selected before native denial")) as resolve:
        native = server._capture_enterprise_install_binding()
    resolve.assert_not_called()
    assert native.configured and native.native_blocked and not native.error
    assert native.digest and not native.binary
    profile.write_text(json.dumps({"schema": "m3c.enterprise-project-profile/v4"}))
    monkeypatch.setenv("SKILLCTL_ENTERPRISE_PROFILE", str(profile))
    with patch.object(server, "_resolve_skillctl_bin", side_effect=AssertionError("v4 native intent selected a binary")) as resolve:
        native_v4 = server._capture_enterprise_install_binding()
    resolve.assert_not_called()
    assert native_v4.configured and native_v4.native_blocked and not native_v4.error
    assert native_v4.digest and not native_v4.binary

    async def invoke_all():
        return [
            await server.skill_install("native-fixture"),
            await server.skill_install("native-fixture", enterprise_profile="/foreign/profile.json", ignore_deps=True),
            await server.skill_attest("sha256:" + "a" * 64, "green", "fixture", "qa-reviewer", "/missing-key"),
            await server.skill_revoke("sha256:" + "a" * 64, "author_request"),
            await server.skill_awareness_sync(dry_run=False, confirm=True),
        ]

    # Unsupported schemas are controlled operator errors, including unhashable JSON types.
    invalid_bindings = []
    for raw in ('{"schema":"m3c.enterprise-project-profile/v3"}', '{"schema":[]}', '{"schema":{}}', '{"schema":null}',
                '{"schema":"m3c.enterprise-project-profile/v2","schema":"m3c.enterprise-project-profile/v1"}'):
        profile.write_text(raw)
        monkeypatch.setenv("SKILLCTL_ENTERPRISE_PROFILE", str(profile))
        with patch.object(server, "_resolve_skillctl_bin", side_effect=AssertionError("invalid schema selected a binary")):
            invalid = server._capture_enterprise_install_binding()
        assert invalid.configured and invalid.error and not invalid.binary
        invalid_bindings.append((invalid, invalid.error))

    # Dedicated opt-in never clears the existing generic native mutation guard.
    profile.write_text(json.dumps({"schema": "m3c.enterprise-project-profile/v4",
        "project_root": str(tmp_path.resolve()), "artifact_home": str(tmp_path.resolve()),
        "native": {"carrier": {"kind": "er1", "base_url": "https://example.invalid/bound",
            "context_id": "agents", "auth": {"mode": "none"}, "tls": {"mode": "system"}}}}))
    opt_in = capture_native_agent_binding({"SKILLCTL_NATIVE_AGENT_INSTALL": "1",
        "SKILLCTL_ENTERPRISE_PROFILE": str(profile.resolve()), "SKILLCTL_PROJECT_ROOT": str(tmp_path.resolve()),
        "SKILLCTL_ARTIFACT_HOME": str(tmp_path.resolve()), "SKILLCTL_BIN": str(Path(sys.executable).resolve())})
    assert opt_in.enabled and not opt_in.error
    monkeypatch.setattr(server, "_NATIVE_AGENT_BINDING", opt_in)
    dedicated_generic = server._capture_enterprise_install_binding()
    assert dedicated_generic.native_blocked and not dedicated_generic.binary

    for binding, exact in ((native, UNAVAILABLE), (native_v4, UNAVAILABLE), (dedicated_generic, UNAVAILABLE),
                           (server._EnterpriseInstallBinding(configured=True, error="invalid operator fixture"),
                            "invalid operator fixture"), *invalid_bindings):
        monkeypatch.setattr(server, "_ENTERPRISE_INSTALL_BINDING", binding)
        profile.write_text('{"schema":"m3c.enterprise-project-profile/v1"}')
        monkeypatch.delenv("SKILLCTL_ENTERPRISE_PROFILE", raising=False)
        monkeypatch.setenv("SKILLCTL_PROJECT_ROOT", "/foreign")
        with ExitStack() as stack:
            forbidden = [stack.enter_context(patch.object(server, name,
                         side_effect=AssertionError(f"native intent reached {name}")))
                         for name in ("_resolve_skillctl_bin", "_run_skillctl_blocking", "_api_get", "_api_post")]
            process = stack.enter_context(patch.object(server.subprocess, "run",
                                          side_effect=AssertionError("native intent executed a child")))
            results = asyncio.run(invoke_all())
        for result in results:
            assert result["ok"] is False
            assert result["exit_code"] == 12
            assert result["error_class"] == "registry_not_trusted"
            assert result["stderr"] == exact
        for counter in forbidden:
            counter.assert_not_called()
        process.assert_not_called()


def test_native_enterprise_profile_http_compatibility(tmp_path):
    # Existing bridge builds the real CLI, installs signed HTTP fixtures and
    # verifies the exact successful Go parent through real MCP stdio.
    run_http_bridge(tmp_path)
