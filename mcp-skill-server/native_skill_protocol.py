"""Strict SKILL-session wire descriptions; Go retains all trust authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re

from native_agent_binding import NativeAgentBinding
from native_agent_protocol import (
    NativeAgentProtocolError, _EXPIRY, _RESULT_KEYS, _ROW_KEYS, _frame, _name,
    _same_path, _text, validate_confirm_token, validate_digest,
)


def _version(value) -> str:
    value = _text(value, 83)
    components = value.split(".")
    if not 1 <= len(components) <= 4 or any(
        re.fullmatch(r"0|[1-9][0-9]*", part) is None
        or int(part) > (1 << 64) - 1
        for part in components
    ):
        raise NativeAgentProtocolError()
    return value


@dataclass(frozen=True)
class NativeSkillPlan:
    token: str = field(repr=False)
    expires_at: str
    expires_utc: datetime
    _row: tuple[tuple[str, str], ...] = field(repr=False)
    _provenance: str = field(repr=False)

    def public(self) -> dict:
        return {"type": "native-skill-plan", "rows": [dict(self._row)],
                "token": self.token, "expires_at": self.expires_at}


def parse_plan_frame(raw: bytes, binding: NativeAgentBinding, digest: str) -> NativeSkillPlan:
    try:
        if (not isinstance(binding, NativeAgentBinding) or not binding.enabled
                or binding.kind != "skill"):
            raise NativeAgentProtocolError()
        validate_digest(digest)
        value = _frame(raw)
        if (set(value) != {"type", "rows", "token", "expires_at"}
                or value["type"] != "native-skill-plan"):
            raise NativeAgentProtocolError()
        rows = value["rows"]
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                or set(rows[0]) != _ROW_KEYS | {"BackupPath"}):
            raise NativeAgentProtocolError()
        row = rows[0]
        name = _name(row["Name"])
        if any(c in name for c in '<>"|?*'):
            raise NativeAgentProtocolError()
        _version(row["Version"])
        if (row["Kind"] != "skill" or row["Digest"] != digest
                or row["Operation"] not in ("create", "overwrite")):
            raise NativeAgentProtocolError()
        target = os.path.join(binding.home, ".claude", "skills", name)
        _same_path(row["Target"], target)
        if type(row["OldDigest"]) is not str or type(row["BackupPath"]) is not str:
            raise NativeAgentProtocolError()
        if row["Operation"] == "create":
            if row["OldDigest"] or row["BackupPath"]:
                raise NativeAgentProtocolError()
        else:
            validate_digest(row["OldDigest"])
            backup = row["BackupPath"]
            tx = os.path.basename(os.path.dirname(backup))
            if re.fullmatch(r"[0-9a-f]{32}", tx) is None:
                raise NativeAgentProtocolError()
            _same_path(backup, os.path.join(binding.home, ".claude", "skills",
                                          ".native-skill", "transactions", tx, "backup"))
        token = validate_confirm_token(value["token"])
        expiry = _text(value["expires_at"], 64)
        if _EXPIRY.fullmatch(expiry) is None:
            raise NativeAgentProtocolError()
        if not expiry.endswith("Z"):
            offset = expiry[-5:]
            if int(offset[:2]) > 23 or int(offset[3:]) > 59:
                raise NativeAgentProtocolError()
        parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00")).astimezone(timezone.utc)
        return NativeSkillPlan(token, expiry, parsed, tuple(row.items()),
                               os.path.join(target, ".m3c-provenance.json"))
    except (ValueError, UnicodeError, OverflowError, TypeError):
        raise NativeAgentProtocolError() from None


def parse_result_frame(raw: bytes, plan: NativeSkillPlan) -> dict:
    try:
        if not isinstance(plan, NativeSkillPlan):
            raise NativeAgentProtocolError()
        value = _frame(raw)
        if set(value) != {"type", "results"} or value["type"] != "native-skill-installed":
            raise NativeAgentProtocolError()
        results = value["results"]
        if (type(results) is not list or len(results) != 1
                or type(results[0]) is not dict or set(results[0]) != _RESULT_KEYS):
            raise NativeAgentProtocolError()
        result, row = results[0], dict(plan._row)
        _same_path(result["SkillPath"], row["Target"])
        _same_path(result["ProvenancePath"], plan._provenance)
        create = row["Operation"] == "create"
        if (result["BackupPath"] != row["BackupPath"]
                or type(result["BackupPath"]) is not str
                or type(result["CreatedFresh"]) is not bool
                or result["CreatedFresh"] is not create
                or type(result["OverwroteOld"]) is not bool
                or result["OverwroteOld"] is create
                or result["OldDigest"] != row["OldDigest"]):
            raise NativeAgentProtocolError()
        return {"type": value["type"], "results": [dict(result)]}
    except (ValueError, UnicodeError, TypeError):
        raise NativeAgentProtocolError() from None
