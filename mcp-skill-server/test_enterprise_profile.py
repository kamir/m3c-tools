"""Operator-bound install selection. These offline fixtures do not assert Go trust."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

import server


def capture(monkeypatch, tmp_path):
    profile = tmp_path / "project.json"
    profile.write_text('{"operator_fixture":true}')
    for key in ("SKILLCTL_ENTERPRISE_PROFILE", "SKILLCTL_PROJECT_ROOT", "SKILLCTL_ARTIFACT_HOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SKILLCTL_ENTERPRISE_PROFILE", str(profile))
    monkeypatch.setenv("SKILLCTL_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("SKILLCTL_ARTIFACT_HOME", str(tmp_path))
    monkeypatch.setenv("SKILLCTL_BIN", sys.executable)
    binding = server._capture_enterprise_install_binding()
    assert binding.configured and not binding.error
    monkeypatch.setattr(server, "_ENTERPRISE_INSTALL_BINDING", binding)
    return binding, profile


def success():
    return json.dumps({"schema": "m3c.skillctl.trust-result/v1", "operation": "install", "ok": True,
                       "exit_code": 0, "digest": "sha256:" + "a" * 64, "author_identity": "synthetic",
                       "registry_key_id": "synthetic-key", "governance_level": "green", "governance_verified": False,
                       "self_attested": None, "chain_summary": "synthetic wire fixture", "install_path": "/synthetic/skill"})


@pytest.mark.parametrize("fields", [
    {}, {"SKILLCTL_PROJECT_ROOT": "relative"}, {"SKILLCTL_ENTERPRISE_PROFILE": ""},
    {"SKILLCTL_ARTIFACT_HOME": "relative"}, {"SKILLCTL_PROJECT_ROOT": "missing"},
])
def test_partial_or_invalid_operator_binding_never_executes(monkeypatch, tmp_path, fields):
    for key in ("SKILLCTL_ENTERPRISE_PROFILE", "SKILLCTL_PROJECT_ROOT", "SKILLCTL_ARTIFACT_HOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SKILLCTL_ENTERPRISE_PROFILE", str(tmp_path / "absent.json"))
    for key, value in fields.items():
        monkeypatch.setenv(key, value)
    bound = server._capture_enterprise_install_binding()
    assert bound.configured and bound.error
    monkeypatch.setattr(server, "_ENTERPRISE_INSTALL_BINDING", bound)
    with patch.object(server.subprocess, "run") as run:
        result = asyncio.run(server.skill_install("fixture"))
    assert result["ok"] is False and result["exit_code"] == 12
    run.assert_not_called()


@pytest.mark.parametrize("extra", [
    {"enterprise_profile": "/other/project.json"}, {"registry": "https://foreign.invalid"},
    {"governance_min": "green"}, {"allow_yellow": True}, {"ignore_deps": True},
])
def test_request_cannot_replace_or_weaken_operator_policy(monkeypatch, tmp_path, extra):
    capture(monkeypatch, tmp_path)
    with patch.object(server.subprocess, "run") as run:
        result = asyncio.run(server.skill_install("fixture", **extra))
    assert result["ok"] is False and result["exit_code"] == 12
    run.assert_not_called()


@pytest.mark.parametrize("change", ["modify", "remove"])
def test_profile_bytes_changed_after_bootstrap_deny_before_exec(monkeypatch, tmp_path, change):
    _, profile = capture(monkeypatch, tmp_path)
    if change == "modify":
        profile.write_text('{"replacement":true}')
    else:
        profile.unlink()
    with patch.object(server.subprocess, "run") as run:
        result = asyncio.run(server.skill_install("fixture"))
    assert result["ok"] is False and result["exit_code"] == 12
    run.assert_not_called()


def test_bound_snapshot_argv_cwd_and_binary_ignore_later_environment(monkeypatch, tmp_path):
    binding, _ = capture(monkeypatch, tmp_path)
    for name in ("SKILLCTL_ENTERPRISE_PROFILE", "SKILLCTL_PROJECT_ROOT", "SKILLCTL_ARTIFACT_HOME", "SKILLCTL_BIN"):
        monkeypatch.setenv(name, "/foreign")
    with patch.object(server, "_resolve_skillctl_bin", side_effect=AssertionError("ambient binary reread")), \
            patch.object(server.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, success(), "")) as run:
        result = asyncio.run(server.skill_install("fixture", enterprise_profile=binding.profile))
    assert result["ok"] is True
    args, kwargs = run.call_args
    assert args[0] == [binding.binary, "install", "--json", "--enterprise-profile", binding.profile,
                       "--enterprise-profile-sha256", binding.digest, "--home", binding.home, "--", "fixture"]
    assert kwargs["cwd"] == binding.project
    assert "env" not in kwargs
    assert binding.digest == hashlib.sha256(Path(binding.profile).read_bytes()).hexdigest()


def test_client_cannot_enable_enterprise_without_operator_binding(monkeypatch):
    monkeypatch.setattr(server, "_ENTERPRISE_INSTALL_BINDING", server._EnterpriseInstallBinding())
    with patch.object(server.subprocess, "run") as run:
        result = asyncio.run(server.skill_install("fixture", enterprise_profile="/client/chosen"))
    assert result["ok"] is False and result["exit_code"] == 12
    run.assert_not_called()


def test_real_import_from_foreign_cwd_captures_operator_binding(tmp_path):
    profile = tmp_path / "project.json"
    profile.write_text('{"operator_fixture":true}')
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), M3C_TOKEN_STORE="file",
               M3C_TEST_KEYCHAIN="0", M3C_ER1_KEYCHAIN="off", SKILLCTL_ENTERPRISE_PROFILE=str(profile),
               SKILLCTL_PROJECT_ROOT=str(tmp_path), SKILLCTL_ARTIFACT_HOME=str(tmp_path), SKILLCTL_BIN=sys.executable)
    module = str(Path(server.__file__).parent)
    code = "import sys;sys.path.insert(0,sys.argv[1]);import server; b=server._ENTERPRISE_INSTALL_BINDING;assert b.configured and not b.error;assert b.project==sys.argv[2];print('operator-binding-captured')"
    run = subprocess.run([sys.executable, "-B", "-c", code, module, str(tmp_path.resolve())], env=env,
                         cwd=tmp_path, text=True, capture_output=True, timeout=30, check=False)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "operator-binding-captured"


def test_real_cli_enterprise_profile_and_stdio(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), M3C_TOKEN_STORE="file",
               M3C_TEST_KEYCHAIN="0", M3C_ER1_KEYCHAIN="off", M3C_MCP_TEST_PYTHON=sys.executable)
    result = subprocess.run(["go", "test", "-json", "./cmd/skillctl", "-run", "^TestInstallEnterpriseProfileMCPSubprocess$", "-count=1"],
                            cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    terminals = [event for event in events if event.get("Test") == "TestInstallEnterpriseProfileMCPSubprocess" and event.get("Action") in {"pass", "fail", "skip"}]
    assert len(terminals) == 1 and terminals[0]["Action"] == "pass", events
    assert not any(event.get("Action") in {"skip", "fail"} for event in events), events
