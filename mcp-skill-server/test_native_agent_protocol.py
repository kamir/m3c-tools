"""Actual Go-shaped wire fixtures; these parser tests grant no installation."""

import base64
import json
import os
from datetime import datetime, timezone

import pytest

from native_agent_binding import NativeAgentBinding
import native_agent_protocol as protocol

DIGEST = "sha256:" + "a" * 64
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def fixture(tmp_path, operation="create", old=""):
    binding = NativeAgentBinding(intent=True, enabled=True, home=str(tmp_path))
    row = {
        "Name": "native-agent",
        "Version": "1.2.3",
        "Kind": "agent",
        "Digest": DIGEST,
        "Target": os.path.join(str(tmp_path), ".claude", "agents", "native-agent.md"),
        "Operation": operation,
        "OldDigest": old,
    }
    value = {
        "type": "native-agent-plan",
        "rows": [row],
        "token": TOKEN,
        "expires_at": "2026-10-26T21:30:00.123456789Z",
    }
    return binding, value


def result(plan):
    row = plan.public()["rows"][0]
    return {
        "type": "native-agent-installed",
        "results": [
            {
                "SkillPath": row["Target"],
                "ProvenancePath": os.path.join(
                    os.path.dirname(row["Target"]), ".provenance", row["Name"] + ".json"
                ),
                "BackupPath": "",
                "CreatedFresh": row["Operation"] == "create",
                "OverwroteOld": row["Operation"] == "overwrite",
                "OldDigest": row["OldDigest"],
            }
        ],
    }


@pytest.mark.parametrize(
    "operation,old",
    [("create", ""), ("overwrite", ""), ("overwrite", "sha256:" + "b" * 64)],
)
def test_native_agent_protocol_real_go_shapes_and_defensive_copies(
    tmp_path, operation, old
):
    binding, value = fixture(tmp_path, operation, old)
    plan = protocol.parse_plan_frame(wire(value), binding, DIGEST)
    assert plan.token == TOKEN and TOKEN not in repr(plan)
    assert plan.expires_at == value["expires_at"]
    assert plan.expires_utc == datetime(2026, 10, 26, 21, 30, 0, 123456, timezone.utc)
    copied = plan.public()
    copied["rows"][0]["Name"] = "changed"
    assert plan.public()["rows"][0]["Name"] == "native-agent"
    final = result(plan)
    assert protocol.parse_result_frame(wire(final), plan) == final


@pytest.mark.parametrize(
    "token",
    [
        None,
        True,
        "",
        TOKEN + "=",
        TOKEN + "\n",
        " " + TOKEN,
        "x" * 42,
        "x" * 44,
        "!" * 43,
        "A" * 42 + "B",
    ],
)
def test_native_agent_protocol_rejects_noncanonical_tokens(token):
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.validate_confirm_token(token)


def test_native_agent_protocol_valid_wrong_token_is_not_autofilled():
    wrong = base64.urlsafe_b64encode(b"z" * 32).decode().rstrip("=")
    assert wrong != TOKEN and protocol.validate_confirm_token(wrong) == wrong


@pytest.mark.parametrize(
    "digest",
    [None, True, "sha256:" + "A" * 64, "a" * 64, DIGEST + "\n", "sha256:" + "a" * 63],
)
def test_native_agent_protocol_digest_strict(digest):
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.validate_digest(digest)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate",
        "nan",
        "inf",
        "invalid-utf8",
        "surrogate",
        "depth",
        "tokens",
        "oversize",
        "newline",
        "crlf",
        "missing-lf",
        "extra-frame",
        "array",
        "unknown-top",
        "null-row",
        "two-rows",
        "missing-field",
        "lowercase-field",
        "foreign-kind",
        "foreign-digest",
        "invalid-version",
        "null-expiry",
        "invalid-date",
        "no-timezone",
        "bad-offset",
        "unknown-operation",
        "create-old",
        "bad-old",
        "traversal",
        "foreign-target",
        "target-dotdot",
        "name-device",
        "name-leadingdot",
        "name-control",
    ],
)
def test_native_agent_protocol_plan_rejects_malformed_or_unbound_wire(tmp_path, case):
    binding, value = fixture(tmp_path)
    row = value["rows"][0]
    if case == "unknown-top":
        value["extra"] = 1
    elif case == "null-row":
        value["rows"] = [None]
    elif case == "two-rows":
        value["rows"] *= 2
    elif case == "missing-field":
        del row["OldDigest"]
    elif case == "lowercase-field":
        row["name"] = row.pop("Name")
    elif case == "foreign-kind":
        row["Kind"] = "skill"
    elif case == "foreign-digest":
        row["Digest"] = "sha256:" + "b" * 64
    elif case == "invalid-version":
        row["Version"] = {"private": "synthetic"}
    elif case == "null-expiry":
        value["expires_at"] = None
    elif case == "invalid-date":
        value["expires_at"] = "2026-02-30T00:00:00Z"
    elif case == "no-timezone":
        value["expires_at"] = "2026-10-26T00:00:00"
    elif case == "bad-offset":
        value["expires_at"] = "2026-10-26T00:00:00+25:00"
    elif case == "unknown-operation":
        row["Operation"] = "delete"
    elif case == "create-old":
        row["OldDigest"] = DIGEST
    elif case == "bad-old":
        row.update(Operation="overwrite", OldDigest=True)
    elif case == "traversal":
        row["Name"] = "../foreign"
    elif case == "foreign-target":
        row["Target"] = os.path.join(str(tmp_path), "foreign.md")
    elif case == "target-dotdot":
        row["Target"] = os.path.join(
            str(tmp_path), ".claude", "agents", "..", "agents", "native-agent.md"
        )
    elif case == "name-device":
        row["Name"] = "COM¹.txt"
    elif case == "name-leadingdot":
        row["Name"] = ".agent"
    elif case == "name-control":
        row["Name"] = "agent\x85"
    raw = wire(value)
    if case == "duplicate":
        raw = raw.replace(b'"type":', b'"type":"wrong","type":', 1)
    elif case == "nan":
        raw = raw.replace(b'"rows":', b'"extra":NaN,"rows":')
    elif case == "inf":
        raw = raw.replace(b'"rows":', b'"extra":Infinity,"rows":')
    elif case == "invalid-utf8":
        raw = b'"\xff"\n'
    elif case == "surrogate":
        raw = b'"\\ud800"\n'
    elif case == "depth":
        raw = b"[" * 33 + b"0" + b"]" * 33 + b"\n"
    elif case == "tokens":
        raw = b"[" + b"0," * 3000 + b"0]\n"
    elif case == "oversize":
        raw = b" " * 65536 + raw
    elif case == "newline":
        raw = raw[:-1] + b"\n \n"
    elif case == "crlf":
        raw = raw[:-1] + b"\r\n"
    elif case == "missing-lf":
        raw = raw[:-1]
    elif case == "extra-frame":
        raw += raw
    elif case == "array":
        raw = b"[]\n"
    with pytest.raises(protocol.NativeAgentProtocolError) as caught:
        protocol.parse_plan_frame(raw, binding, DIGEST)
    assert str(caught.value) == protocol.NATIVE_AGENT_PROTOCOL_ERROR
    assert "synthetic" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("SkillPath", "/foreign"),
        ("ProvenancePath", "/foreign"),
        ("BackupPath", "private-path"),
        ("CreatedFresh", 1),
        ("CreatedFresh", False),
        ("OverwroteOld", True),
        ("OverwroteOld", 0),
        ("OldDigest", DIGEST),
        ("OldDigest", None),
    ],
)
def test_native_agent_protocol_results_match_retained_plan(tmp_path, field, value):
    binding, raw = fixture(tmp_path)
    plan = protocol.parse_plan_frame(wire(raw), binding, DIGEST)
    final = result(plan)
    final["results"][0][field] = value
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.parse_result_frame(wire(final), plan)


def test_native_agent_protocol_rejects_invented_result_digest_and_extra_frames(
    tmp_path,
):
    binding, raw = fixture(tmp_path)
    plan = protocol.parse_plan_frame(wire(raw), binding, DIGEST)
    final = result(plan)
    final["results"][0]["Digest"] = DIGEST
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.parse_result_frame(wire(final), plan)
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.parse_result_frame(wire(result(plan)) * 2, plan)


def test_native_agent_protocol_exact_frame_cap_and_utf8_name(tmp_path):
    binding, value = fixture(tmp_path)
    name = "日本-agent"
    value["rows"][0]["Name"] = name
    value["rows"][0]["Target"] = os.path.join(
        str(tmp_path), ".claude", "agents", name + ".md"
    )
    raw = wire(value)
    raw = raw[:-1] + b" " * (65536 - len(raw)) + b"\n"
    assert len(raw) == 65536
    plan = protocol.parse_plan_frame(raw, binding, DIGEST)
    assert plan.public()["rows"][0]["Name"] == name
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.parse_plan_frame(raw[:-1] + b" \n", binding, DIGEST)


def test_native_agent_protocol_exponent_overflow_is_not_finite_json():
    for raw in (b'{"value":1e999}', b'{"value":-1e999}'):
        with pytest.raises(protocol.NativeAgentProtocolError):
            protocol.decode_bounded_json(raw)


@pytest.mark.parametrize(
    "offset", ["+00:60", "+01:99", "-00:60", "-01:99", "+24:00", "-24:00"]
)
def test_native_agent_protocol_rejects_out_of_range_rfc3339_offset(tmp_path, offset):
    binding, value = fixture(tmp_path)
    value["expires_at"] = "2026-10-26T21:30:00" + offset
    with pytest.raises(protocol.NativeAgentProtocolError):
        protocol.parse_plan_frame(wire(value), binding, DIGEST)


@pytest.mark.parametrize("offset", ["Z", "+00:00", "-00:00", "+23:59", "-23:59"])
def test_native_agent_protocol_valid_rfc3339_offset_controls(tmp_path, offset):
    binding, value = fixture(tmp_path)
    value["expires_at"] = "2026-10-26T21:30:00" + offset
    assert (
        protocol.parse_plan_frame(wire(value), binding, DIGEST).expires_utc.tzinfo
        == timezone.utc
    )
