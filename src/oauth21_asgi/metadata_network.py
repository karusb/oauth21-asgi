"""aiohttp public connector/resolver API pins vetted DNS answers to connections."""

from __future__ import annotations

import logging
import socket
import ssl

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver
from yarl import URL

from .cimd import MetadataFetchError, MetadataNetworkPolicy, MetadataResponse

logger = logging.getLogger("oauth21_asgi.metadata")


class VettedResolver(AbstractResolver):
    def __init__(self, policy: MetadataNetworkPolicy) -> None:
        self.policy = policy
        self.delegate = ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[ResolveResult]:
        answers = await self.delegate.resolve(host, port, socket.AddressFamily(family))
        if not answers:
            raise MetadataFetchError("No destination addresses")
        for answer in answers:
            self.policy.check_address(answer["host"])
        # aiohttp connects directly to these numeric addresses. It does not
        # resolve the hostname a second time; Host and TLS SNI use the original URL.
        return answers

    async def close(self) -> None:
        await self.delegate.close()


class AiohttpMetadataFetcher:
    def __init__(
        self, policy: MetadataNetworkPolicy, *, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        self.policy = policy
        if ssl_context is not None and (
            not ssl_context.check_hostname or ssl_context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError("CIMD TLS must validate certificates and hostnames")
        self.ssl_context = ssl_context or ssl.create_default_context()

    async def fetch(self, client_id: str, *, max_bytes: int, timeout: float) -> MetadataResponse:
        self.policy.check_url(client_id)
        resolver = VettedResolver(self.policy)
        connector = aiohttp.TCPConnector(
            resolver=resolver, use_dns_cache=False, ssl=self.ssl_context
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=timeout),
                auto_decompress=False,
                max_line_size=8192,
                max_field_size=8192,
            ) as session:
                async with session.get(
                    URL(client_id, encoded=True),
                    allow_redirects=False,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                ) as reply:
                    headers = {key.lower(): value for key, value in reply.headers.items()}
                    if (
                        reply.status != 200
                        or headers.get("content-encoding", "identity") != "identity"
                    ):
                        raise MetadataFetchError("Unacceptable metadata status or encoding")
                    if reply.content_length is not None and reply.content_length > max_bytes:
                        raise MetadataFetchError("Metadata exceeds size limit")
                    parts: list[bytes] = []
                    size = 0
                    async for chunk in reply.content.iter_chunked(min(max_bytes + 1, 4096)):
                        size += len(chunk)
                        if size > max_bytes:
                            raise MetadataFetchError("Metadata exceeds size limit")
                        parts.append(chunk)
                    return MetadataResponse(reply.status, headers, b"".join(parts))
        except aiohttp.ClientError as exc:
            logger.warning(
                "Client metadata transport failed",
                extra={"operation": "metadata_fetch", "exception_class": type(exc).__name__},
            )
            raise MetadataFetchError("Metadata transport failed") from exc
        finally:
            await resolver.close()
