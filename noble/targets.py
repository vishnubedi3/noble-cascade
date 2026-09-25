"""Target normalization.

Every comparison in the control plane happens on a *canonical* target. Raw
operator- or tool-supplied strings are never matched directly, because
substring matching is how scope engines get bypassed.
"""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
import unicodedata
import urllib.parse
from contextlib import suppress

from .errors import InvalidInput
from .models import Target, TargetKind

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_URL_SCHEMES = ("http://", "https://", "ssh://", "git://")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git": 9418}
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")
_REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*/[a-z0-9][a-z0-9._\-]*$")


def _sanitize(raw: str) -> str:
    """Reject the tricks that make string matching unsafe."""
    if not isinstance(raw, str):
        raise InvalidInput("target must be a string")
    text = raw.strip()
    if not text:
        raise InvalidInput("target is empty")
    if len(text) > 2048:
        raise InvalidInput("target exceeds 2048 characters")
    if _CONTROL_CHARS.search(text):
        raise InvalidInput("target contains control characters")
    if _ZERO_WIDTH.search(text):
        raise InvalidInput("target contains zero-width or bidi override characters")
    if "%25" in text.lower():
        raise InvalidInput("target contains double percent-encoding")
    normalized = unicodedata.normalize("NFKC", text)
    if _CONTROL_CHARS.search(normalized) or _ZERO_WIDTH.search(normalized):
        raise InvalidInput("target becomes unsafe after unicode normalization")
    return normalized


def _canonical_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        raise InvalidInput("target host is empty")
    if "\\" in host or "/" in host or "@" in host or " " in host:
        raise InvalidInput(f"target host contains illegal characters: {host!r}")
    with suppress(UnicodeError, ValueError):
        host = host.encode("idna").decode("ascii")
    # If IDNA failed, the anchored hostname/IP validation below denies it.
    if not _HOST_RE.match(host) and not _looks_like_ip(host):
        raise InvalidInput(f"target host is not a valid hostname: {host!r}")
    return host


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_path(raw_path: str) -> str:
    """Resolve a filesystem target; refuse traversal above the declared root."""
    if "\x00" in raw_path:
        raise InvalidInput("path contains a null byte")
    expanded = os.path.expanduser(raw_path)
    resolved = os.path.realpath(expanded)
    if resolved != os.path.realpath(resolved):  # pragma: no cover - defensive
        raise InvalidInput("path is not stable under resolution")
    return resolved


def normalize_target(raw: str, *, workspace_root: str | None = None) -> Target:
    """Produce a canonical :class:`Target` from an untrusted string."""
    text = _sanitize(raw)

    # 1. Explicit URL form -------------------------------------------------
    if text.lower().startswith(_URL_SCHEMES):
        if "\\" in text:
            raise InvalidInput("backslashes in target URLs are ambiguous")
        parts = urllib.parse.urlsplit(text)
        if parts.username or parts.password:
            raise InvalidInput("target URL must not embed credentials")
        if parts.query or parts.fragment:
            raise InvalidInput(
                "target URLs with query or fragment are ambiguous; use an exact endpoint"
            )
        if "%" in parts.netloc:
            raise InvalidInput("encoded hostnames are not accepted")
        host = _canonical_host(parts.hostname or "")
        scheme = parts.scheme.lower()
        try:
            port = parts.port
        except ValueError as exc:
            raise InvalidInput("target URL has an invalid port") from exc
        if port is None:
            port = _DEFAULT_PORTS.get(scheme)
        elif not 1 <= port <= 65535:
            raise InvalidInput(f"target URL has an invalid port: {port}")
        if "%" in parts.path:
            raise InvalidInput("percent-encoded URL paths are not supported")
        path = posixpath.normpath(parts.path or "/") or "/"
        host_display = f"[{host}]" if ":" in host else host
        canonical = (
            f"{scheme}://{host_display}"
            if port == _DEFAULT_PORTS.get(scheme)
            else f"{scheme}://{host_display}:{port}"
        )
        canonical = f"{canonical}{path}"
        return Target(
            raw=raw,
            kind=TargetKind.URL,
            canonical=canonical,
            host=host,
            port=port,
            path=path,
        )

    # 2. CIDR --------------------------------------------------------------
    if "/" in text and _looks_like_ip(text.split("/", 1)[0]):
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise InvalidInput(f"invalid CIDR target: {exc}") from exc
        return Target(
            raw=raw, kind=TargetKind.CIDR, canonical=str(network), host=str(network.network_address)
        )

    # 3. Bare IP -----------------------------------------------------------
    if _looks_like_ip(text):
        return Target(
            raw=raw, kind=TargetKind.IP, canonical=str(ipaddress.ip_address(text)), host=text
        )

    # 4. Repository slug ---------------------------------------------------
    lowered = text.lower()
    if (
        _REPO_RE.match(lowered)
        and not text.startswith(("/", ".", "~"))
        and "." not in text.split("/")[0]
    ):
        owner, _, name = lowered.partition("/")
        return Target(
            raw=raw, kind=TargetKind.REPOSITORY, canonical=lowered, owner=owner, name=name
        )

    # 5. Hostname (optionally with port) -----------------------------------
    if not text.startswith(("/", ".", "~")) and "/" not in text:
        host_part, sep, port_part = text.partition(":")
        if sep:
            if not port_part.isdigit() or not 1 <= int(port_part) <= 65535:
                raise InvalidInput(f"invalid port in target: {port_part!r}")
            host = _canonical_host(host_part)
            return Target(
                raw=raw,
                kind=TargetKind.HOST,
                canonical=f"{host}:{int(port_part)}",
                host=host,
                port=int(port_part),
            )
        host = _canonical_host(host_part)
        return Target(raw=raw, kind=TargetKind.HOST, canonical=host, host=host)

    # 6. Filesystem path ---------------------------------------------------
    # Require explicit path syntax; otherwise a malicious "host/path" string
    # could be misread as an allowed relative workspace path.
    if not text.startswith(("/", ".", "~")):
        raise InvalidInput("relative filesystem paths must start with './' or '../'")
    if "?" in text or "#" in text:
        raise InvalidInput("filesystem targets cannot contain URL delimiters")
    resolved = _normalize_path(text)
    if workspace_root and resolved == os.path.realpath(workspace_root):
        return Target(raw=raw, kind=TargetKind.LOCAL_WORKSPACE, canonical=resolved, path=resolved)
    return Target(raw=raw, kind=TargetKind.PATH, canonical=resolved, path=resolved)
