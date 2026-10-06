from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from authlib.common.urls import is_valid_url


def safe_uri(uri: str, *, allow_loopback: bool = False, issuer: bool = False) -> bool:
    """Application restrictions on Authlib URL validation and stdlib parsing."""
    if (
        not isinstance(uri, str)
        or "#" in uri
        or chr(92) in uri
        or any(ord(c) < 33 or ord(c) == 127 for c in uri)
    ):
        return False
    try:
        parts = urlsplit(uri)
        _ = parts.port
        if (
            not is_valid_url(uri, fragments_allowed=False)
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or (issuer and parts.query)
        ):
            return False
        if parts.scheme == "https":
            return True
        if allow_loopback and parts.scheme == "http":
            if parts.hostname == "localhost":
                return True
            return ipaddress.ip_address(parts.hostname).is_loopback
    except (ValueError, TypeError):
        return False
    return False


class ExactRedirectPolicy:
    def __init__(self, redirects: Iterable[str], *, allow_loopback: bool = False) -> None:
        self.redirects = frozenset(redirects)
        self.allow_loopback = allow_loopback
        if not self.redirects or any(
            not safe_uri(u, allow_loopback=allow_loopback) for u in self.redirects
        ):
            raise ValueError("Redirect allowlist contains an unsafe URI")

    def __call__(self, uri: str) -> bool:
        return safe_uri(uri, allow_loopback=self.allow_loopback) and uri in self.redirects


class CallableRedirectPolicy:
    def __init__(self, predicate: Callable[[str], bool], *, allow_loopback: bool = False) -> None:
        self.predicate = predicate
        self.allow_loopback = allow_loopback

    def __call__(self, uri: str) -> bool:
        return safe_uri(uri, allow_loopback=self.allow_loopback) and bool(self.predicate(uri))
