"""Optional client metadata discovery; OAuth grants continue to belong to Authlib."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass, field
from importlib.util import find_spec
from threading import RLock
from typing import Any, Protocol, cast
from urllib.parse import unquote, urlsplit

from authlib.oauth2.rfc6749 import InvalidClientError

from .models import Client
from .policies import safe_uri

logger = logging.getLogger("oauth21_asgi.metadata")


class MetadataFetchError(Exception):
    """Expected metadata/network rejection; its text must contain no request data."""


@dataclass(frozen=True)
class MetadataResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


class ClientMetadataFetcher(Protocol):
    async def fetch(self, client_id: str, *, max_bytes: int, timeout: float) -> MetadataResponse:
        """No redirects, credentials, proxies or unsafe destinations; bound bytes and time.

        Custom implementations own DNS/connect pinning, TLS and network policy.
        """
        ...


@dataclass(frozen=True)
class MetadataNetworkPolicy:
    allow_loopback: bool = False
    allowed_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if type(self.allow_loopback) is not bool or not isinstance(self.allowed_origins, frozenset):
            raise ValueError("Network policy must use a boolean and immutable origin allowlist")
        for origin in self.allowed_origins:
            if (
                not safe_uri(origin, allow_loopback=self.allow_loopback)
                or urlsplit(origin).path not in ("", "/")
                or urlsplit(origin).query
            ):
                raise ValueError("Configure safe origins without paths or queries")

    def check_address(self, address: str) -> None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise MetadataFetchError("Invalid destination address") from exc
        if self.allow_loopback and ip.is_loopback:
            return
        # Translation/transition prefixes can route a seemingly global IPv6 address
        # into private IPv4 networks. Reject them instead of guessing routing policy.
        blocked = (
            "192.0.0.0/24",
            "192.88.99.0/24",
            "64:ff9b::/96",
            "64:ff9b:1::/48",
            "2001::/23",
            "2002::/16",
            "::ffff:0:0/96",
        )
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local)
            or any(ip in ipaddress.ip_network(prefix) for prefix in blocked)
        ):
            raise MetadataFetchError("Special-use destination rejected")

    def check_url(self, client_id: str) -> None:
        if not valid_client_id(client_id, allow_loopback=self.allow_loopback):
            raise MetadataFetchError("Invalid client metadata URL")
        parts = urlsplit(client_id)
        origin = f"{parts.scheme}://{parts.netloc}"
        if self.allowed_origins and origin not in self.allowed_origins:
            raise MetadataFetchError("Metadata origin is not allowed")
        try:
            ipaddress.ip_address(parts.hostname or "")
        except ValueError:
            return
        self.check_address(parts.hostname or "")


def valid_client_id(value: str, *, allow_loopback: bool = False) -> bool:
    if not safe_uri(value, allow_loopback=allow_loopback):
        return False
    try:
        parts = urlsplit(value)
        if (
            not value.startswith(("https://", "http://") if allow_loopback else ("https://",))
            or not value.isascii()
            or parts.path in ("", "/")
            or parts.query
            or "?" in value
            or re.search(r"%(?![0-9a-fA-F]{2})", value)
            or parts.port == 0
            or "%" in parts.netloc
        ):
            return False
        decoded = unquote(parts.path, errors="strict")
        if any(segment in (".", "..") for segment in decoded.split("/")):
            return False
        # Reject encoded delimiters, double-encoding and control characters; URL
        # identity is never rewritten, even when a web server canonicalizes paths.
        return (
            not any(c in decoded for c in ("\\", "%", "?", "#"))
            and not any(ord(c) < 32 or ord(c) == 127 for c in decoded)
            and not re.search(r"%2f", parts.path, re.IGNORECASE)
        )
    except (ValueError, UnicodeError):
        return False


@dataclass(frozen=True)
class CIMDLimits:
    response_bytes: int = 16_384
    entries: int = 256
    concurrent_fetches: int = 16
    min_ttl: int = 0
    max_ttl: int = 3600
    default_ttl: int = 300
    timeout: float = 5.0

    def __post_init__(self) -> None:
        if (
            any(
                type(v) is not int or v < 1
                for v in (
                    self.response_bytes,
                    self.entries,
                    self.concurrent_fetches,
                    self.max_ttl,
                )
            )
            or type(self.min_ttl) is not int
            or self.min_ttl < 0
        ):
            raise ValueError("Invalid CIMD limits")
        if not self.min_ttl <= self.default_ttl <= self.max_ttl or not 0 < self.timeout <= 60:
            raise ValueError("Invalid CIMD TTL or timeout")


class ClientMetadataDocuments:
    """Thread-safe bounded validated cache shared across ASGI event loops.

    Construct one configuration per AuthorizationServer. Built-in transport is
    loaded only with explicit CIMD opt-in; custom fetchers do not need aiohttp.
    """

    def __init__(
        self,
        *,
        fetcher: ClientMetadataFetcher | None = None,
        network: MetadataNetworkPolicy | None = None,
        limits: CIMDLimits | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.network = network or MetadataNetworkPolicy()
        self.limits = limits or CIMDLimits()
        self.clock = clock
        if fetcher is None:
            if find_spec("aiohttp") is None:
                raise ValueError("Install oauth21-asgi[cimd] for the built-in metadata fetcher")
            from .metadata_network import AiohttpMetadataFetcher

            fetcher = AiohttpMetadataFetcher(self.network)
        self.fetcher = fetcher
        self._lock = RLock()
        self._cache: OrderedDict[str, tuple[float, Client]] = OrderedDict()
        self._pending: dict[str, Future[Client]] = {}
        self._owner: object | None = None

    def bind(self, owner: object, *, issuer: str, allow_loopback: bool) -> None:
        if self.network.allow_loopback:
            hostname = urlsplit(issuer).hostname or ""
            try:
                loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = False
            if not allow_loopback or not loopback:
                raise ValueError("CIMD loopback policy requires an explicit loopback issuer")
        with self._lock:
            if self._owner is not None and self._owner is not owner:
                raise ValueError("A CIMD cache cannot be shared between authorization servers")
            self._owner = owner

    async def resolve(self, client_id: str, validate: Callable[[dict[str, Any]], Client]) -> Client:
        try:
            self.network.check_url(client_id)
        except MetadataFetchError as exc:
            raise InvalidClientError("Client metadata is unavailable or invalid.") from exc
        with self._lock:
            cached = self._cache.get(client_id)
            if cached and cached[0] > self.clock():
                self._cache.move_to_end(client_id)
                return cached[1]
            self._cache.pop(client_id, None)
            future = self._pending.get(client_id)
            leader = future is None
            if leader:
                if len(self._pending) >= self.limits.concurrent_fetches:
                    raise InvalidClientError("Client metadata capacity reached.")
                future = Future()
                self._pending[client_id] = future
        future = cast(Future[Client], future)  # established under the lock above
        if not leader:
            return await asyncio.shield(asyncio.wrap_future(future))
        try:
            async with asyncio.timeout(self.limits.timeout):
                result = await self.fetcher.fetch(
                    client_id,
                    max_bytes=self.limits.response_bytes,
                    timeout=self.limits.timeout,
                )
            headers = {key.lower(): value for key, value in result.headers.items()}
            content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if (
                result.status != 200
                or content_type
                not in (
                    "application/json",
                    "application/oauth-client-metadata+json",
                )
                or len(result.body) > self.limits.response_bytes
                or headers.get("content-encoding", "identity") != "identity"
            ):
                raise MetadataFetchError("Unacceptable metadata response")
            data = strict_object(result.body)
            if data.get("client_id") != client_id:
                raise MetadataFetchError("Client identifier mismatch")
            client = validate(data)
            ttl = self._ttl(headers)
            with self._lock:
                if ttl > 0:
                    self._cache[client_id] = (self.clock() + ttl, client)
                    while len(self._cache) > self.limits.entries:
                        self._cache.popitem(last=False)
                future.set_result(client)
            return client
        except (
            MetadataFetchError,
            ValueError,
            UnicodeError,
            RecursionError,
            TimeoutError,
            OSError,
        ) as exc:
            if isinstance(exc, (TimeoutError, OSError)):
                logger.warning(
                    "Client metadata transport failed",
                    extra={"operation": "metadata_fetch", "exception_class": type(exc).__name__},
                )
            error = InvalidClientError("Client metadata is unavailable or invalid.")
            future.set_exception(error)
            raise error from exc
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(client_id, None)

    def _ttl(self, headers: Mapping[str, str]) -> int:
        directives = {part.strip().lower() for part in headers.get("cache-control", "").split(",")}
        if directives.intersection({"no-store", "no-cache"}):
            return 0
        age = headers.get("age", "0")
        max_age = next(
            (part[8:].strip('"') for part in directives if part.startswith("max-age=")), None
        )
        if max_age is not None and max_age.isdecimal() and age.isdecimal():
            ttl = max(0, int(max_age) - int(age))
        else:
            ttl = self.limits.default_ttl
        return min(self.limits.max_ttl, max(self.limits.min_ttl, ttl))


def strict_object(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("Non-JSON number")

    data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(data, dict):
        raise ValueError("JSON object required")
    return data
