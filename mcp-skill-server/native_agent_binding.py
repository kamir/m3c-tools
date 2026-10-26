"""Explicit immutable MCP startup selection; Go remains the trust authority."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import stat
import sys
import unicodedata
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

from api_connection import parse_api_base
from native_agent_protocol import decode_bounded_json, validate_digest

NATIVE_AGENT_BINDING_ERROR = "Native agent startup binding is unavailable; inspect operator configuration before retrying."
_OPT_IN = "SKILLCTL_NATIVE_AGENT_INSTALL"
_MISSING = object()
_MAX_PATH = 4096
_MAX_PROFILE = 65536
_MAX_BINARY = 256 << 20
_CHUNK = 65536
_ENV_OPTIONAL = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)


class NativeAgentBindingError(ValueError):
    def __init__(self):
        super().__init__(NATIVE_AGENT_BINDING_ERROR)


def _text(value, maximum: int, *, empty: bool = False, controls: bool = False) -> str:
    if type(value) is not str:
        raise NativeAgentBindingError()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise NativeAgentBindingError() from None
    if (
        (not value and not empty)
        or size > maximum
        or "\x00" in value
        or (not controls and any(unicodedata.category(c) == "Cc" for c in value))
    ):
        raise NativeAgentBindingError()
    return value


def _selected_env(environ: Mapping[str, str], name: str, *, windows: bool):
    if not windows:
        return environ.get(name, _MISSING)
    # Windows environment names are case-insensitive. Reject aliases rather than
    # depending on mapping iteration order (including injected test mappings).
    names = [key for key in environ if type(key) is str and key.upper() == name]
    if len(names) > 1:
        raise NativeAgentBindingError()
    return environ[names[0]] if names else _MISSING


def _path(raw) -> str:
    value = _text(raw, _MAX_PATH)
    if not os.path.isabs(value):
        raise NativeAgentBindingError()
    resolved = str(Path(value).resolve(strict=True))
    return _text(resolved, _MAX_PATH)


@dataclass(frozen=True)
class _FileObservation:
    path: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    mode: int
    sha256: str
    handle_ctime_ns: int


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
    )


def _path_handle_same(path_info, held_info):
    expected, actual = _identity(path_info), _identity(held_info)
    if sys.platform == "win32":
        # CPython's Windows path stat infers 0111 from executable extensions;
        # fstat has no filename adjustment. Normalize only this cross-API
        # difference. Path/path and handle/handle mode checks remain exact.
        # Windows path stat retains legacy creation-time ctime; fstat reports
        # change-time ctime. Compare the common explicit birthtime cross-API,
        # while retaining both raw ctimes for same-API checks and recheck.
        try:
            expected = expected[:4] + (path_info.st_birthtime_ns, expected[-1] & ~0o111)
            actual = actual[:4] + (held_info.st_birthtime_ns, actual[-1] & ~0o111)
        except AttributeError:
            raise NativeAgentBindingError() from None
    return expected == actual


def _observe(path: str, maximum: int, *, retain: bool = False):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise NativeAgentBindingError()
    # The pre-open ordinary-file check prevents an explicitly selected FIFO from
    # blocking Open. Same-file/post checks are observations, not hostile-UID safety.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    held = None
    chunks = []
    digest = hashlib.sha256()
    total = 0
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode) or not _path_handle_same(before, held):
            raise NativeAgentBindingError()
        while True:
            chunk = os.read(fd, min(_CHUNK, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise NativeAgentBindingError()
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
        after = os.fstat(fd)
        final = os.lstat(path)
        if (
            total != held.st_size
            or _identity(after) != _identity(held)
            or _identity(final) != _identity(before)
        ):
            raise NativeAgentBindingError()
    finally:
        # Close errors invalidate startup/recheck; never return bytes on uncertainty.
        os.close(fd)
    observation = _FileObservation(
        path, *_identity(before), digest.hexdigest(), held.st_ctime_ns
    )
    return observation, b"".join(chunks) if retain else None


def _keys(value, keys: set[str]):
    if type(value) is not dict or set(value) != keys:
        raise NativeAgentBindingError()
    return value


def _auth_family(document) -> str | None:
    # This is bounded configuration classification, not full Go profile validation
    # or crypto verification. In particular no referenced trust/TLS file is read.
    if (
        type(document) is not dict
        or document.get("schema") != "m3c.enterprise-project-profile/v4"
    ):
        raise NativeAgentBindingError()
    native = document.get("native")
    if type(native) is not dict:
        raise NativeAgentBindingError()
    carrier = _keys(
        native.get("carrier"), {"kind", "base_url", "context_id", "auth", "tls"}
    )
    if carrier["kind"] != "er1":
        raise NativeAgentBindingError()
    base = _text(carrier["base_url"], 8192)
    _, origin = parse_api_base(base)
    if origin[0] != "https":
        raise NativeAgentBindingError()
    context = _text(carrier["context_id"], 8192)
    if (
        context in (".", "..")
        or any(c in context for c in "/\\%?#")
        or any(c.isspace() for c in context)
    ):
        raise NativeAgentBindingError()
    tls = carrier["tls"]
    if type(tls) is not dict:
        raise NativeAgentBindingError()
    if tls.get("mode") == "system":
        _keys(tls, {"mode"})
    elif tls.get("mode") == "pinned-pem":
        _keys(tls, {"mode", "ca"})
        ca = _keys(tls["ca"], {"path", "sha256"})
        _text(ca["path"], _MAX_PATH)
        pin = _text(ca["sha256"], 64)
        if len(pin) != 64 or any(c not in "0123456789abcdefABCDEF" for c in pin):
            raise NativeAgentBindingError()
    else:
        raise NativeAgentBindingError()
    auth = carrier["auth"]
    if type(auth) is not dict:
        raise NativeAgentBindingError()
    if auth.get("mode") == "none":
        _keys(auth, {"mode"})
        return None
    _keys(auth, {"mode", "family", "origin"})
    if auth["mode"] != "external-env" or auth["family"] not in ("api-key", "bearer"):
        raise NativeAgentBindingError()
    auth_origin = _text(auth["origin"], 8192)
    canonical, selected = parse_api_base(auth_origin)
    # The physical carrier origin is explicit public metadata. Go independently
    # validates complete URL/prefix/TLS/auth semantics before the selected request.
    parsed = urlsplit(canonical)
    expected_origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if selected != origin or auth_origin != expected_origin:
        raise NativeAgentBindingError()
    return "ER1_API_KEY" if auth["family"] == "api-key" else "ER1_DEVICE_TOKEN"


def _environment(
    environ, home: str, family: str | None, *, windows: bool
) -> tuple[tuple[str, str], ...]:
    values = {"HOME": home, "USERPROFILE": home}
    for name in _ENV_OPTIONAL + ((family,) if family else ()):
        value = _selected_env(environ, name, windows=windows)
        if value is not _MISSING:
            # Inherited selected secret bytes are opaque here. Go validates them
            # after the held journal; no provider lookup, trim or fallback occurs.
            values[name] = _text(value, 8192, empty=True, controls=True)
    if (
        len(values) > 32
        or sum(len(k.encode()) + len(v.encode()) for k, v in values.items()) > 65536
    ):
        raise NativeAgentBindingError()
    return tuple(sorted(values.items()))


@dataclass(frozen=True)
class NativeAgentBinding:
    intent: bool = False
    enabled: bool = False
    error: str = ""
    profile: str = ""
    profile_sha256: str = ""
    project: str = ""
    home: str = ""
    binary: str = ""
    _env: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    _profile_observation: _FileObservation | None = field(default=None, repr=False)
    _binary_observation: _FileObservation | None = field(default=None, repr=False)

    def child_environment(self) -> dict[str, str]:
        if not self.enabled:
            raise NativeAgentBindingError()
        return dict(self._env)

    def argv(self, digest: str) -> tuple[str, ...]:
        if not self.enabled:
            raise NativeAgentBindingError()
        validate_digest(digest)
        return (
            self.binary,
            "pull",
            "--enterprise-profile",
            self.profile,
            "--enterprise-profile-sha256",
            self.profile_sha256,
            "--home",
            self.home,
            "--kind",
            "agent",
            "--digest",
            digest,
            "--install",
            "--trust-mode",
            "--native-session",
        )

    def recheck(self) -> None:
        try:
            if (
                not self.enabled
                or self._profile_observation is None
                or self._binary_observation is None
            ):
                raise NativeAgentBindingError()
            for path in (self.project, self.home):
                if _path(path) != path or not stat.S_ISDIR(os.stat(path).st_mode):
                    raise NativeAgentBindingError()
            profile, _ = _observe(self.profile, _MAX_PROFILE)
            binary, _ = _observe(self.binary, _MAX_BINARY)
            if (
                profile != self._profile_observation
                or binary != self._binary_observation
                or not os.access(self.binary, os.X_OK)
            ):
                raise NativeAgentBindingError()
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise NativeAgentBindingError() from None


def capture_native_agent_binding(
    environ: Mapping[str, str] | None = None,
) -> NativeAgentBinding:
    environ = os.environ if environ is None else environ
    windows = os.name == "nt"
    try:
        opt_in = _selected_env(environ, _OPT_IN, windows=windows)
        if opt_in is _MISSING:
            return NativeAgentBinding()
        if type(opt_in) is not str or opt_in != "1":
            raise NativeAgentBindingError()
        selected = {}
        for name in (
            "SKILLCTL_ENTERPRISE_PROFILE",
            "SKILLCTL_PROJECT_ROOT",
            "SKILLCTL_ARTIFACT_HOME",
            "SKILLCTL_BIN",
        ):
            selected[name] = _path(_selected_env(environ, name, windows=windows))
        project, home = (
            selected["SKILLCTL_PROJECT_ROOT"],
            selected["SKILLCTL_ARTIFACT_HOME"],
        )
        if not Path(project).is_dir() or not Path(home).is_dir():
            raise NativeAgentBindingError()
        profile = selected["SKILLCTL_ENTERPRISE_PROFILE"]
        observation, raw = _observe(profile, _MAX_PROFILE, retain=True)
        document = decode_bounded_json(raw)
        family = _auth_family(document)
        for name, expected in (("project_root", project), ("artifact_home", home)):
            declared = _text(document.get(name), _MAX_PATH)
            if not os.path.isabs(declared):
                declared = os.path.join(project, declared)
            if _path(declared) != expected:
                raise NativeAgentBindingError()
        binary = selected["SKILLCTL_BIN"]
        binary_observation, _ = _observe(binary, _MAX_BINARY)
        if not os.access(binary, os.X_OK):
            raise NativeAgentBindingError()
        child_env = _environment(environ, home, family, windows=windows)
        return NativeAgentBinding(
            True,
            True,
            "",
            profile,
            observation.sha256,
            project,
            home,
            binary,
            child_env,
            observation,
            binary_observation,
        )
    except (OSError, ValueError, UnicodeError, RuntimeError):
        return NativeAgentBinding(intent=True, error=NATIVE_AGENT_BINDING_ERROR)
