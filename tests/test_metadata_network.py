from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from aiohttp import web
from aiohttp.resolver import ThreadedResolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oauth21_asgi.cimd import ClientMetadataDocuments, MetadataFetchError, MetadataNetworkPolicy
from oauth21_asgi.metadata_network import AiohttpMetadataFetcher, VettedResolver


def tls_contexts(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert = tmp_path / "certificate.pem"
    secret = tmp_path / "key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    secret.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, secret)
    client = ssl.create_default_context(cafile=str(cert))
    return server, client


def test_https_dns_is_vetted_once_and_host_certificate_verified(tmp_path, monkeypatch):
    server_ssl, client_ssl = tls_contexts(tmp_path)
    resolutions = []
    hosts = []

    async def resolve(self, host, port=0, family=socket.AF_INET):
        resolutions.append(host)
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    monkeypatch.setattr(ThreadedResolver, "resolve", resolve)

    async def scenario():
        async def metadata(request):
            hosts.append(request.host)
            return web.json_response({"client_id": "fixture"})

        app = web.Application()
        app.router.add_get("/client.json", metadata)
        runner = web.AppRunner(app)
        await runner.setup()
        # Public server/sockets APIs; ephemeral port chosen by the OS.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        site = web.SockSite(runner, listener, ssl_context=server_ssl)
        await site.start()
        try:
            fetcher = AiohttpMetadataFetcher(
                MetadataNetworkPolicy(allow_loopback=True), ssl_context=client_ssl
            )
            response = await fetcher.fetch(
                f"https://localhost:{port}/client.json", max_bytes=1024, timeout=2
            )
            assert response.status == 200
            assert hosts == [f"localhost:{port}"]
            assert resolutions == ["localhost"]
            # An untrusted CA must fail, never silently disable TLS verification.
            with pytest.raises(MetadataFetchError):
                await AiohttpMetadataFetcher(MetadataNetworkPolicy(allow_loopback=True)).fetch(
                    f"https://localhost:{port}/client.json", max_bytes=1024, timeout=2
                )
        finally:
            await runner.cleanup()

    asyncio.run(scenario())


def test_resolver_rejects_mixed_public_private_answers(monkeypatch):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in ("8.8.8.8", "10.0.0.1")
        ]

    monkeypatch.setattr(ThreadedResolver, "resolve", resolve)

    async def scenario():
        resolver = VettedResolver(MetadataNetworkPolicy())
        try:
            with pytest.raises(MetadataFetchError):
                await resolver.resolve("client.test", 443)
        finally:
            await resolver.close()

    asyncio.run(scenario())


def test_built_in_transport_bounds_and_never_follows_redirects():
    async def scenario():
        followed = []

        async def handler(request):
            name = request.match_info["name"]
            if name == "target":
                followed.append(name)
                return web.json_response({})
            if name == "redirect":
                return web.Response(status=302, headers={"Location": "/target"})
            if name == "encoding":
                return web.Response(body=b"compressed", headers={"Content-Encoding": "gzip"})
            if name == "chunked":
                reply = web.StreamResponse()
                await reply.prepare(request)
                await reply.write(b"x" * 1025)
                await reply.write_eof()
                return reply
            return web.Response(body=b"x" * 1025)

        app = web.Application()
        app.router.add_get("/{name}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        await web.SockSite(runner, listener).start()
        try:
            fetcher = AiohttpMetadataFetcher(MetadataNetworkPolicy(allow_loopback=True))
            for path in ("redirect", "encoding", "chunked", "large"):
                with pytest.raises(MetadataFetchError):
                    await fetcher.fetch(
                        f"http://127.0.0.1:{port}/{path}", max_bytes=1024, timeout=2
                    )
            assert not followed
        finally:
            await runner.cleanup()

    asyncio.run(scenario())


def test_default_transport_and_tls_policy():
    config = ClientMetadataDocuments()
    assert isinstance(config.fetcher, AiohttpMetadataFetcher)
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError):
        AiohttpMetadataFetcher(MetadataNetworkPolicy(), ssl_context=insecure)
