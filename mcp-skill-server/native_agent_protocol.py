"""Bounded wire parsing for one retained native agent CLI session.

Parsing describes Go's messages; it grants no trust or publication authority.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import os
import re
import unicodedata
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from native_agent_binding import NativeAgentBinding

NATIVE_AGENT_PROTOCOL_ERROR = "Native agent session output is invalid; close the session and inspect state before retrying."
MAX_FRAME_BYTES = 65536
MAX_JSON_DEPTH = 32
MAX_JSON_TOKENS = 4096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_EXPIRY = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_ROW_KEYS = {"Name", "Version", "Kind", "Digest", "Target", "Operation", "OldDigest"}
_RESULT_KEYS = {
    "SkillPath",
    "ProvenancePath",
    "BackupPath",
    "CreatedFresh",
    "OverwroteOld",
    "OldDigest",
}


class NativeAgentProtocolError(ValueError):
    def __init__(self):
        super().__init__(NATIVE_AGENT_PROTOCOL_ERROR)


def _reject_constant(_value):
    raise NativeAgentProtocolError()


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise NativeAgentProtocolError()
    return result


def _unique(pairs):
    result = {}
    canonical = set()
    for key, value in pairs:
        normalized = key.replace("_", "").casefold()
        if key in result or normalized in canonical:
            raise NativeAgentProtocolError()
        canonical.add(normalized)
        result[key] = value
    return result


def decode_bounded_json(raw: bytes):
    """Check lexical resource bounds before allocating a JSON object tree."""
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_FRAME_BYTES:
            raise NativeAgentProtocolError()
        text = raw.decode("utf-8", errors="strict")
        depth = tokens = 0
        i = 0
        while i < len(text):
            c = text[i]
            if c in " \t\r\n":
                i += 1
                continue
            tokens += 1
            if tokens > MAX_JSON_TOKENS:
                raise NativeAgentProtocolError()
            if c == '"':
                i += 1
                while i < len(text):
                    if text[i] == "\\":
                        i += 2
                    elif text[i] == '"':
                        i += 1
                        break
                    else:
                        i += 1
                continue
            if c in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise NativeAgentProtocolError()
            elif c in "]}":
                depth -= 1
                if depth < 0:
                    raise NativeAgentProtocolError()
            elif c not in ",:":
                while i + 1 < len(text) and text[i + 1] not in " \t\r\n,]}:":
                    i += 1
            i += 1
        if depth != 0:
            raise NativeAgentProtocolError()
        result = json.loads(
            text,
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        pending = [result]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                value.encode("utf-8", errors="strict")  # reject escaped lone surrogates
            elif isinstance(value, dict):
                pending.extend(value)
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        return result
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise NativeAgentProtocolError() from None


def validate_digest(value: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise NativeAgentProtocolError()
    return value


def validate_confirm_token(value: str) -> str:
    try:
        if type(value) is not str or _TOKEN.fullmatch(value) is None:
            raise NativeAgentProtocolError()
        raw = base64.urlsafe_b64decode(value + "=")
        if (
            len(raw) != 32
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
        ):
            raise NativeAgentProtocolError()
        return value
    except (ValueError, UnicodeError):
        raise NativeAgentProtocolError() from None


def _text(value, cap: int, *, empty: bool = False) -> str:
    if type(value) is not str:
        raise NativeAgentProtocolError()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise NativeAgentProtocolError() from None
    if (
        (not value and not empty)
        or size > cap
        or any(unicodedata.category(c) == "Cc" for c in value)
    ):
        raise NativeAgentProtocolError()
    return value


def _name(value) -> str:
    name = _text(value, 248)
    stem = name.upper().split(".", 1)[0].rstrip(" ")
    if (
        name.startswith(".")
        or any(c in name for c in "/\\:")
        or name.endswith((".", " "))
        or stem in {"CON", "PRN", "AUX", "NUL"}
        or (
            len(stem) == 4 and stem[:3] in {"COM", "LPT"} and stem[3] in "0123456789¹²³"
        )
    ):
        raise NativeAgentProtocolError()
    return name


def _frame(raw: bytes) -> dict:
    if (
        type(raw) is not bytes
        or not raw.endswith(b"\n")
        or b"\n" in raw[:-1]
        or b"\r" in raw
    ):
        raise NativeAgentProtocolError()
    value = decode_bounded_json(raw)
    if type(value) is not dict:
        raise NativeAgentProtocolError()
    return value


def _same_path(value, expected: str) -> str:
    value = _text(value, 8192)
    if not os.path.isabs(value) or os.path.normcase(
        os.path.normpath(value)
    ) != os.path.normcase(expected):
        raise NativeAgentProtocolError()
    # Do not resolve an uncreated target or follow mutable target links here.
    if os.path.normpath(value) != value:
        raise NativeAgentProtocolError()
    return value


@dataclass(frozen=True)
class NativeAgentPlan:
    token: str = field(repr=False)
    expires_at: str
    expires_utc: datetime
    _row: tuple[tuple[str, str], ...] = field(repr=False)
    _provenance: str = field(repr=False)

    def public(self) -> dict:
        return {
            "type": "native-agent-plan",
            "rows": [dict(self._row)],
            "token": self.token,
            "expires_at": self.expires_at,
        }


def parse_plan_frame(
    raw: bytes, binding: NativeAgentBinding, digest: str
) -> NativeAgentPlan:
    from native_agent_binding import NativeAgentBinding

    try:
        if (not isinstance(binding, NativeAgentBinding) or not binding.enabled
                or binding.kind != "agent"):
            raise NativeAgentProtocolError()
        validate_digest(digest)
        value = _frame(raw)
        if (
            set(value) != {"type", "rows", "token", "expires_at"}
            or value["type"] != "native-agent-plan"
        ):
            raise NativeAgentProtocolError()
        rows = value["rows"]
        if (
            type(rows) is not list
            or len(rows) != 1
            or type(rows[0]) is not dict
            or set(rows[0]) != _ROW_KEYS
        ):
            raise NativeAgentProtocolError()
        row = rows[0]
        name = _name(row["Name"])
        _text(row["Version"], 256)
        if (
            row["Kind"] != "agent"
            or row["Digest"] != digest
            or row["Operation"] not in ("create", "overwrite")
        ):
            raise NativeAgentProtocolError()
        target = os.path.join(binding.home, ".claude", "agents", name + ".md")
        _same_path(row["Target"], target)
        if type(row["OldDigest"]) is not str or (
            row["OldDigest"] and validate_digest(row["OldDigest"]) != row["OldDigest"]
        ):
            raise NativeAgentProtocolError()
        if row["Operation"] == "create" and row["OldDigest"]:
            raise NativeAgentProtocolError()
        token = validate_confirm_token(value["token"])
        expiry = _text(value["expires_at"], 64)
        if _EXPIRY.fullmatch(expiry) is None:
            raise NativeAgentProtocolError()
        if not expiry.endswith("Z"):
            offset = expiry[-5:]
            if int(offset[:2]) > 23 or int(offset[3:]) > 59:
                raise NativeAgentProtocolError()
        # Go RFC3339Nano has at most9 fractional digits; datetime retains microseconds.
        parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
        return NativeAgentPlan(
            token,
            expiry,
            parsed,
            tuple(row.items()),
            os.path.join(
                binding.home, ".claude", "agents", ".provenance", name + ".json"
            ),
        )
    except (ValueError, UnicodeError, OverflowError, TypeError):
        raise NativeAgentProtocolError() from None


def parse_result_frame(raw: bytes, plan: NativeAgentPlan) -> dict:
    try:
        if not isinstance(plan, NativeAgentPlan):
            raise NativeAgentProtocolError()
        value = _frame(raw)
        if (
            set(value) != {"type", "results"}
            or value["type"] != "native-agent-installed"
        ):
            raise NativeAgentProtocolError()
        results = value["results"]
        if (
            type(results) is not list
            or len(results) != 1
            or type(results[0]) is not dict
            or set(results[0]) != _RESULT_KEYS
        ):
            raise NativeAgentProtocolError()
        result, row = results[0], dict(plan._row)
        _same_path(result["SkillPath"], row["Target"])
        _same_path(result["ProvenancePath"], plan._provenance)
        create = row["Operation"] == "create"
        if (
            result["BackupPath"] != ""
            or type(result["BackupPath"]) is not str
            or type(result["CreatedFresh"]) is not bool
            or result["CreatedFresh"] is not create
            or type(result["OverwroteOld"]) is not bool
            or result["OverwroteOld"] is create
            or result["OldDigest"] != row["OldDigest"]
        ):
            raise NativeAgentProtocolError()
        return {"type": value["type"], "results": [dict(result)]}
    except (ValueError, UnicodeError, TypeError):
        raise NativeAgentProtocolError() from None
