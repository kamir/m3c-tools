"""Pure destination checks and deferred local API-key selection."""

import ipaddress
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


INVALID_BASE = "API configuration blocked: invalid target or transport (HTTPS required unless loopback HTTP is explicitly enabled)."
INVALID_BINDING = "API configuration blocked: set M3C_API_KEY_ORIGIN to the key's independently known origin, not a newly selected target."
MISSING_KEY = "API key unavailable: set M3C_API_KEY with its independent origin pin, or explicitly assign a legacy API key. A context-only session has no API key."


def _unsafe_text(value: str) -> bool:
    return any(char.isspace() or unicodedata.category(char) == "Cc" for char in value)


def parse_api_base(raw: str, allow_loopback_http: bool = False, *, request: bool = False) -> tuple[str, tuple[str, str, int]]:
    """Preserve the URL path and compare canonical scheme/host/effective port.

    Request URLs may carry queries. Configured bases and independent origin pins
    may not. ASCII DNS names only; no DNS lookup or issuer authentication occurs.
    """
    if not isinstance(raw, str) or not raw or _unsafe_text(raw) or "\\" in raw or "#" in raw or ("?" in raw and not request):
        raise ValueError(INVALID_BASE)
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None:
            raise ValueError
        scheme = parsed.scheme.lower()
        if scheme not in ("https", "http"):
            raise ValueError
        host = host.lower()
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.removesuffix(".").split(".")):
                raise ValueError
        if addr is not None:
            if "%" in host or (addr.version == 6 and not parsed.netloc.startswith("[")):
                raise ValueError
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            host = str(addr)
        elif parsed.netloc.startswith("["):
            raise ValueError
        if scheme == "http" and (not allow_loopback_http or not (host == "localhost" or (addr is not None and addr.is_loopback))):
            raise ValueError
        port = parsed.port
        if port is None:
            if parsed.netloc.endswith(":"):
                raise ValueError
            port = 443 if scheme == "https" else 80
        if not 1 <= port <= 65535:
            raise ValueError
        # urlsplit does not reject malformed percent escapes in a path.
        if re.search(r"%(?![a-fA-F0-9]{2})", parsed.path):
            raise ValueError
        decoded_path = urllib.parse.unquote(parsed.path)
        if _unsafe_text(decoded_path) or "\\" in decoded_path:
            raise ValueError
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        path = urllib.parse.quote(parsed.path, safe="/%:@!$&'()*+,;=-._~")
        return urllib.parse.urlunsplit((scheme, authority, path, parsed.query, "")), (scheme, host, port)
    except (ValueError, UnicodeError):
        raise ValueError(INVALID_BASE) from None


@dataclass(frozen=True)
class APIConnection:
    """Local operator assignment only; no issuer or tenant authority is proven."""

    base_url: str = ""
    origin: tuple[str, str, int] | None = None
    key: str = field(default="", repr=False)
    source: str = ""
    error: str = ""
    allow_loopback_http: bool = False


def resolve_api_connection(getenv: Callable, read_session: Callable) -> APIConnection:
    """Validate the independent pin before reading environment/session secrets."""
    allow_http = getenv("M3C_ALLOW_LOOPBACK_HTTP", "") == "1"
    try:
        base, origin = parse_api_base(getenv("M3C_API_URL", "https://onboarding.guide"), allow_http)
    except ValueError:
        return APIConnection(error=INVALID_BASE, allow_loopback_http=allow_http)
    try:
        pin, pin_origin = parse_api_base(getenv("M3C_API_KEY_ORIGIN", ""), allow_http)
        if urllib.parse.urlsplit(pin).path not in ("", "/") or pin_origin != origin:
            raise ValueError
    except ValueError:
        return APIConnection(base_url=base, error=INVALID_BINDING, allow_loopback_http=allow_http)
    try:
        key = getenv("M3C_API_KEY", "")
        source = "environment-operator-assignment"
        if not key:
            source = "legacy-session-operator-assignment"
            key = read_session()
        if not isinstance(key, str) or not key.strip():
            return APIConnection(base_url=base, origin=origin, error=MISSING_KEY, allow_loopback_http=allow_http)
        key = key.strip()
        if any(char in key for char in "\r\n\x00"):
            raise ValueError
    except Exception:
        return APIConnection(base_url=base, origin=origin, error=MISSING_KEY, allow_loopback_http=allow_http)
    return APIConnection(base, origin, key, source, "", allow_http)
