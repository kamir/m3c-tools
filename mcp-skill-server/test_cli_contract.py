"""Typed protocol negatives and public MCP tools against the built Go CLI."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

import server


def trust_payload(operation="verify", **changes):
    payload = {
        "schema": "m3c.skillctl.trust-result/v1", "operation": operation,
        "ok": True, "exit_code": 0, "digest": "sha256:" + "a" * 64,
        "author_identity": "id:synthetic", "registry_key_id": "fixture-key",
        "governance_level": "green", "governance_verified": False,
        "self_attested": None, "chain_summary": "advisory green (offline)",
    }
    payload.update(changes)
    return payload


def decode(payload, code=0, operation="verify"):
    return server._decode_trust_result({"exit_code": code, "stdout": json.dumps(payload), "stderr": ""}, operation)


@pytest.mark.parametrize("changes", [
    {"schema": "future"}, {"operation": "install"}, {"ok": 1},
    {"exit_code": False}, {"exit_code": 1}, {"ok": False},
    {"digest": ""}, {"digest": "sha256:bad"}, {"author_identity": ""},
    {"registry_key_id": None}, {"chain_summary": []},
    {"governance_level": "approved"}, {"governance_level": []}, {"governance_verified": 1},
    {"self_attested": "false"}, {"error": "failed"},
])
def test_malformed_success_rejected(changes):
    result = decode(trust_payload(**changes))
    assert result["ok"] is False
    assert result["error_class"] == "protocol_error"
    assert result["process_exit_code"] == 0


@pytest.mark.parametrize("field", ["self_attested", "governance_verified", "digest", "operation", "schema", "ok", "exit_code"])
def test_missing_required_field(field):
    payload = trust_payload()
    del payload[field]
    assert decode(payload)["error_class"] == "protocol_error"


@pytest.mark.parametrize("stdout", ["", "human success", "[]", "null", "{} {}", '{"ok":true,"ok":false}', 'true', '{"ignored":NaN}'])
def test_non_protocol_stdout(stdout):
    result = server._decode_trust_result({"exit_code": 0, "stdout": stdout, "stderr": ""}, "verify")
    assert result["ok"] is False
    assert result["error_class"] == "protocol_error"


def test_install_requires_path():
    assert decode(trust_payload("install"), operation="install")["error_class"] == "protocol_error"


@pytest.mark.parametrize("verified,self_attested", [(False, None), (False, False), (True, False), (True, True)])
def test_governance_fields_preserved_without_inference(verified, self_attested):
    result = decode(trust_payload(governance_verified=verified, self_attested=self_attested))
    assert result["ok"] is True
    assert result["governance_verified"] is verified
    assert result["self_attested"] is self_attested


def test_process_failure_cannot_be_overridden_by_json():
    assert decode(trust_payload(), code=13)["error_class"] == "protocol_error"
    payload = trust_payload(ok=False, exit_code=13, error="governance below minimum")
    result = decode(payload, code=13)
    assert result["ok"] is False and result["exit_code"] == 13
    assert result["error_class"] == "governance_below_min"


def test_verify_flags_precede_operand(tmp_path, monkeypatch):
    binary = tmp_path / "skillctl"
    binary.touch()
    binary.chmod(0o755)
    monkeypatch.setenv("SKILLCTL_BIN", str(binary))
    response = subprocess.CompletedProcess([], 0, json.dumps(trust_payload()), "")
    with patch("subprocess.run", return_value=response) as run:
        result = asyncio.run(server.skill_verify("fixture", registry="http://127.0.0.1:1234/api/skills", governance_min="yellow", allow_yellow=True))
    assert result["ok"] is True
    argv = run.call_args.args[0]
    assert argv[1:3] == ["verify", "--json"]
    assert argv[-1] == "fixture"
    assert argv.index("--registry") < len(argv)-1
    assert argv.index("--governance-min") < len(argv)-1


def test_real_cli_public_tools(tmp_path):
    """The Go fixture provides local signed registry responses, with no live service."""
    env = os.environ.copy()
    env.update({"HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
                "M3C_TOKEN_STORE": "file", "M3C_TEST_KEYCHAIN": "0", "M3C_ER1_KEYCHAIN": "off",
                "M3C_MCP_TEST_PYTHON": sys.executable})
    completed = subprocess.run(
        ["go", "test", "./cmd/skillctl", "-run", "^TestTrustContractMCPSubprocess$", "-count=1"],
        cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_subprocess_non_utf8_is_failure(tmp_path, monkeypatch):
    binary = tmp_path / "skillctl"
    binary.touch()
    binary.chmod(0o755)
    monkeypatch.setenv("SKILLCTL_BIN", str(binary))
    with patch("subprocess.run", side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")):
        result = asyncio.run(server.skill_verify("fixture"))
    assert result["ok"] is False and result["error_class"] == "exec_error"


@pytest.mark.parametrize("code", [16, 17, 18, 19, 20, 22, 23, 99])
def test_all_numeric_refusals_stay_fail_closed(code):
    result = decode(trust_payload(ok=False, exit_code=code, error="synthetic refusal"), code=code)
    assert result["ok"] is False and result["exit_code"] == code
    assert result["error_class"] not in (None, "protocol_error")
