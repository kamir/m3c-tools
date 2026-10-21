"""Attestation receipts must describe actual accepted CLI messages without backfill."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

import server

DIGEST = "sha256:" + "a" * 64


def receipt(**changes):
    data = {"schema": "m3c.skillctl.attestation-receipt/v1", "operation": "attest",
            "ok": True, "exit_code": 0, "attestation_id": "synthetic-receipt",
            "bundle_digest": DIGEST, "governance_level": "green", "reviewer_id": "id:fixture",
            "attested_at": "2026-10-21T11:00:00Z"}
    data.update(changes)
    return data


def decode(payload, code=0):
    return server._decode_attest_receipt({"exit_code": code, "stdout": json.dumps(payload), "stderr": ""}, DIGEST, "green", "id:fixture")


@pytest.mark.parametrize("field", list(receipt()))
def test_required_receipt_fields(field):
    payload = receipt()
    del payload[field]
    result = decode(payload)
    assert result["ok"] is False and result["error_class"] == "protocol_error"


@pytest.mark.parametrize("changes", [
    {"schema": "future"}, {"operation": "verify"}, {"ok": 1}, {"exit_code": False},
    {"exit_code": 1}, {"ok": False}, {"attestation_id": ""}, {"attestation_id": " "},
    {"attestation_id": "forged\nline"}, {"attestation_id": 1}, {"bundle_digest": "bad"},
    {"bundle_digest": "sha256:" + "b" * 64}, {"governance_level": "yellow"},
    {"reviewer_id": "id:other"}, {"attested_at": ""}, {"attested_at": None},
    {"attested_at": "2026-02-30T11:00:00Z"}, {"attested_at": "2026-10-21T11:00:00+00:00"},
    {"attested_at": "2026-10-21T11:00:00Z\n"}, {"governance_verified": True}, {"self_attested": False},
    {"error": "submission failed"},
])
def test_malformed_receipt_success_refused(changes):
    result = decode(receipt(**changes))
    assert result["ok"] is False and result["error_class"] == "protocol_error"


@pytest.mark.parametrize("raw", ["", "attestation_id: human-output", "{} {}", "null", "[]", '{"ok":true,"ok":false}', '{"x":NaN}'])
def test_strict_json_receipt(raw):
    result = server._decode_attest_receipt({"exit_code": 0, "stdout": raw, "stderr": ""}, DIGEST, "green", "id:fixture")
    assert result["ok"] is False and result["error_class"] == "protocol_error"


def test_receipt_process_exit_is_authoritative():
    assert decode(receipt(), code=1)["error_class"] == "protocol_error"
    result = decode(receipt(ok=False, exit_code=1, error="registry refused"), code=1)
    assert result["ok"] is False and result["exit_code"] == 1 and result["error_class"] == "generic_error"


def test_public_attest_rejects_missing_receipt_fields_without_backfill(tmp_path, monkeypatch):
    binary = tmp_path / "skillctl"
    binary.touch()
    binary.chmod(0o755)
    monkeypatch.setenv("SKILLCTL_BIN", str(binary))
    payload = receipt()
    del payload["attestation_id"]
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")) as run:
        result = asyncio.run(server.skill_attest(DIGEST, "green", "fixture", "id:fixture", "/synthetic-key"))
    assert result["ok"] is False and result["error_class"] == "protocol_error"
    argv = run.call_args.args[0]
    assert argv[1:3] == ["attest", "--json"] and argv[-2:] == ["--", DIGEST]


def test_real_attest_public_and_stdio(tmp_path):
    env = os.environ.copy()
    env.update({"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "M3C_TOKEN_STORE": "file",
                "M3C_ER1_KEYCHAIN": "off", "M3C_TEST_KEYCHAIN": "0", "M3C_MCP_TEST_PYTHON": sys.executable})
    result = subprocess.run(["go", "test", "./cmd/skillctl", "-run", "^TestAttestReceiptMCPSubprocess$", "-count=1"],
                            cwd=Path(__file__).resolve().parents[1], env=env, text=True, capture_output=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
