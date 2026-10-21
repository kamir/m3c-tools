"""Verify-All preserves inventory decisions through the typed public MCP tool."""
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

import server


def valid_entry():
    return {"skill": "fixture", "state": "verified", "status": "valid", "disposition": "unchanged",
            "complete": True, "exit": 0, "reason": "verified", "digest": "sha256:" + "a" * 64,
            "digest_source": "actual_bundle", "digest_verified": True, "check_scope": "online_trust_chain",
            "revocation_source": "online", "governance_verified": False, "self_attested": None,
            "checks": [{"name": name, "status": "pass"} for name in
                       ("content_binding", "trust_chain", "governance", "dependencies", "revocation")]}


def sweep():
    return {"schema": "m3c.skillctl.sweep-result/v1", "operation": "verify_all", "ok": True, "complete": True,
            "exit_code": 0, "skills_dir": "/synthetic/skills", "total": 1, "verified": 1, "invalid": 0,
            "quarantined": 0, "quarantine_candidates": 0, "unverified": 0, "skipped": 0, "entries": [valid_entry()]}


def decode(payload, code=0):
    return server._decode_sweep_result({"exit_code": code, "stdout": json.dumps(payload), "stderr": ""})


@pytest.mark.parametrize("field", list(sweep()))
def test_sweep_requires_every_top_field(field):
    payload = sweep()
    del payload[field]
    assert decode(payload)["error_class"] == "protocol_error"


@pytest.mark.parametrize("field", list(valid_entry()))
def test_sweep_requires_complete_valid_entry(field):
    payload = sweep()
    del payload["entries"][0][field]
    assert decode(payload)["error_class"] == "protocol_error"


@pytest.mark.parametrize("changes", [
    {"schema": "future"}, {"operation": "verify"}, {"ok": 1}, {"complete": 1}, {"exit_code": False},
    {"exit_code": 1}, {"ok": False}, {"complete": False}, {"total": 2}, {"total": True},
    {"verified": 2}, {"invalid": -1}, {"quarantined": 1}, {"quarantine_candidates": 1}, {"entries": None},
    {"unknown": "claim"}, {"error": "failure"}, {"skills_dir": ""},
])
def test_sweep_rejects_contradictory_summary(changes):
    payload = sweep()
    payload.update(changes)
    assert decode(payload)["error_class"] == "protocol_error"


@pytest.mark.parametrize("changes", [
    {"status": []}, {"status": {}}, {"status": "invalid"}, {"check_scope": []}, {"check_scope": "invented"}, {"check_scope": "sidecar_legacy"}, {"check_scope": "not_checked"},
    {"check_scope": "revocation_policy"}, {"check_scope": "unmanaged_policy"},
    {"complete": False}, {"complete": 1}, {"governance_verified": 1}, {"self_attested": "false"},
    {"digest_verified": False}, {"digest_verified": 1}, {"digest": "sha256:bad"}, {"digest_source": "sidecar"},
    {"skill": "\nfixture"}, {"skill": None}, {"checks": []}, {"checks": {}}, {"exit": True},
    {"quarantine_path": "/invented"}, {"action_error": "write failed"}, {"disposition": "would_quarantine"},
    {"revocation_source": "unconfirmed"}, {"unproved": True},
])
def test_sweep_rejects_contradictory_entry(changes):
    payload = sweep()
    payload["entries"][0].update(changes)
    assert decode(payload)["error_class"] == "protocol_error"


@pytest.mark.parametrize("raw", ["", "human\n{}", "null", "[]", "{} {}", '{"ok":true,"ok":false}', '{"x":NaN}'])
def test_sweep_rejects_non_protocol_stdout(raw):
    result = server._decode_sweep_result({"exit_code": 0, "stdout": raw, "stderr": ""})
    assert result["ok"] is False and result["error_class"] == "protocol_error"


def test_duplicate_names_or_checks_rejected():
    payload = sweep()
    payload["entries"].append(deepcopy(payload["entries"][0]))
    payload.update(total=2, verified=2)
    assert decode(payload)["error_class"] == "protocol_error"
    payload = sweep()
    payload["entries"][0]["checks"].append({"name": "revocation", "status": "pass"})
    assert decode(payload)["error_class"] == "protocol_error"


def test_empty_success_and_actual_governance_provenance_preserved():
    payload = sweep()
    assert decode(payload) == payload
    assert decode(payload)["entries"][0]["governance_verified"] is False
    payload.update(total=0, verified=0, entries=[])
    assert decode(payload) == payload


def test_mixed_failures_and_incomplete_entries_are_preserved():
    payload = sweep()
    invalid = valid_entry()
    invalid.update(skill="tampered", state="quarantined", status="invalid", exit=10, reason="digest mismatch",
                   digest_verified=False, disposition="would_quarantine", check_scope="online_trust_chain")
    invalid["checks"] = [{"name": check["name"], "status": "fail" if check["name"] == "trust_chain" else "not_checked"}
                         for check in invalid["checks"]]
    incomplete = valid_entry()
    incomplete.update(skill="offline", status="incomplete", complete=False, check_scope="offline_trust_chain",
                      revocation_source="unconfirmed", reason="revocation not confirmed")
    incomplete["checks"][-1]["status"] = "unconfirmed"
    payload["entries"].extend([invalid, incomplete])
    payload.update(ok=False, complete=False, exit_code=1, total=3, invalid=1, unverified=1,
                   quarantine_candidates=1, error="inventory contains failures or incomplete checks")
    assert decode(payload, code=1) == payload
    assert decode(payload, code=0)["error_class"] == "protocol_error"


def test_public_sweep_argv_and_failure_receipt(tmp_path, monkeypatch):
    binary = tmp_path / "skillctl"
    binary.touch()
    binary.chmod(0o755)
    monkeypatch.setenv("SKILLCTL_BIN", str(binary))
    payload = sweep()
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")) as run:
        result = asyncio.run(server.skill_verify_all(registry="https://registry.invalid", governance_min="yellow"))
    assert result == payload
    argv = run.call_args.args[0]
    assert argv[1:4] == ["verify", "--json", "--all"] and "--quarantine" not in argv
    assert argv[-2:] == ["--governance-min", "yellow"]
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(argv, 90)):
        result = asyncio.run(server.skill_verify_all(quarantine=True))
    assert result["ok"] is False and result["error_class"] == "exec_error"


@pytest.mark.parametrize("arguments", [
    {"budget_seconds": True}, {"budget_seconds": 0}, {"budget_seconds": 301}, {"budget_seconds": 1.5},
    {"timeout": False}, {"timeout": 60}, {"timeout": 601}, {"quarantine": "false"},
    {"registry": "https://fixture.invalid\nline"}, {"governance_min": "bogus"}, {"governance_min": []},
])
def test_invalid_sweep_input_never_executes(arguments):
    with patch("subprocess.run") as run:
        result = asyncio.run(server.skill_verify_all(**arguments))
    assert result["error_class"] == "validation_error"
    run.assert_not_called()


def test_real_sweep_public_tool_and_stdio(tmp_path):
    env = os.environ.copy()
    env.update({"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "M3C_TOKEN_STORE": "file",
                "M3C_TEST_KEYCHAIN": "0", "M3C_MCP_TEST_PYTHON": sys.executable})
    result = subprocess.run(["go", "test", "./cmd/skillctl", "-run", "^TestSweepContractMCPSubprocess$", "-count=1"],
                            cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[no tests to run]" not in result.stdout, result.stdout


@pytest.mark.parametrize("changes", [{"exit": 0}, {"state": "verified"}, {"disposition": "unchanged"}])
def test_invalid_entry_cannot_assert_success_or_omit_its_action(changes):
    payload = sweep()
    entry = payload["entries"][0]
    entry.update(status="invalid", state="quarantined", exit=10, digest_verified=False,
                 disposition="would_quarantine", reason="bundle mismatch")
    entry["checks"] = [{"name": check["name"], "status": "fail" if check["name"] == "trust_chain" else "not_checked"}
                       for check in entry["checks"]]
    entry.update(changes)
    payload.update(ok=False, complete=True, exit_code=1, verified=0, invalid=1,
                   quarantine_candidates=int(entry["disposition"] != "unchanged"), error="invalid bundle")
    assert decode(payload, code=1)["error_class"] == "protocol_error"


@pytest.mark.parametrize("changes", [{"state": "verified"}, {"exit": 1}, {"governance_verified": True},
                                     {"disposition": "would_quarantine"}, {"digest_verified": True}])
def test_skipped_entry_never_asserts_verification_or_mutation(changes):
    payload = sweep()
    entry = payload["entries"][0]
    entry.update(status="skipped", state="skipped", complete=False, digest_verified=False,
                 check_scope="unmanaged_policy", revocation_source="unconfirmed")
    entry["checks"] = [{"name": check["name"], "status": "not_checked"} for check in entry["checks"]]
    entry.update(changes)
    payload.update(ok=False, complete=False, exit_code=1, verified=0, skipped=1,
                   quarantine_candidates=int(entry["disposition"] != "unchanged"), error="unmanaged skill")
    assert decode(payload, code=1)["error_class"] == "protocol_error"
