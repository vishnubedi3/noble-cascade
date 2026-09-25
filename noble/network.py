"""Explicit network policy.

There are no network-capable tools in the local registry. The network boundary
is a hard deny; a future adapter must implement DNS pinning, redirect checks,
and an actual egress sandbox before this module can allow a destination.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .errors import NetworkDenied


class NetworkPolicy:
    def __init__(self, enabled: bool = False) -> None:
        if enabled:
            raise NetworkDenied("network mode requires an independently verified egress sandbox")
        self.enabled = False

    def check(self, url: str, *, resolved_addresses: tuple[str, ...] = ()) -> None:
        # Parse for predictable errors, but never contact DNS or issue requests.
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise NetworkDenied("unsupported network destination")
        raise NetworkDenied("network access is disabled in this runtime")
