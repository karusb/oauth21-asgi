from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from conftest import CALLBACK, ISSUER, A, B, System

from oauth21_asgi import (
    CIMDLimits,
    ClientMetadataDocuments,
    ClientMode,
    ExactRedirectPolicy,
    MetadataNetworkPolicy,
    MetadataResponse,
)
from oauth21_asgi.cimd import MetadataFetchError, strict_object, valid_client_id
from oauth21_asgi.models import Client

URL = "https://client.example.test/oauth/client.json"


def document(client_id=URL, **overrides):
    # Deterministic ChatGPT-style transition fixture; no real hosted acceptance.
    result = {
        "client_id": client_id,
        "client_name": "Portable client",
        "redirect_uris": [CALLBACK, "https://chatgpt.com/connector/oauth/opaque-id"],
        "scope": "read write",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://client.example.test/keys.json",
        "logo_uri": "https://client.example.test/logo.png",
    }
    result.update(overrides)
    return result


class FixtureFetcher:
    def __init__(self, data=None, *, status=200, headers=None, raw=None):
        self.data = data if data is not None else document()
        self.status = status
        self.headers = headers or {
            "content-type": "application/json",
            "cache-control": "max-age=60",
        }
        self.raw = raw
        self.calls = []

    async def fetch(self, client_id, *, max_bytes, timeout):
        self.calls.append(client_id)
        return MetadataResponse(
            self.status,
            self.headers,
            self.raw if self.raw is not None else json.dumps(self.data).encode(),
        )


def cimd_system(mode=ClientMode.CIMD_ONLY, *, fetcher=None, **options):
    fetcher = fetcher or FixtureFetcher()
    config = ClientMetadataDocuments(fetcher=fetcher, **options)
    return System(
        client_mode=mode,
        cimd=config,
        policy=ExactRedirectPolicy({CALLBACK, "https://chatgpt.com/connector/oauth/opaque-id"}),
    ), fetcher


@pytest.mark.parametrize("mode", list(ClientMode))
def test_mode_discovery_routes_and_full_lifecycle(mode):
    if mode == ClientMode.DCR_ONLY:
        system, fetcher = System(), FixtureFetcher()
    else:
        system, fetcher = cimd_system(mode)
    metadata = system.http.get(system.oauth.discovery_path).json()
    enabled_dcr = mode != ClientMode.CIMD_ONLY
    assert ("registration_endpoint" in metadata) == enabled_dcr
    assert metadata.get("client_id_metadata_document_supported", False) == (
        mode != ClientMode.DCR_ONLY
    )
    if enabled_dcr:
        cid, token = system.tokens()
        assert system.refresh(cid, token["refresh_token"]).status_code == 200
        assert system.revoke(cid, token["access_token"]).status_code == 200
        assert not fetcher.calls
    else:
        assert system.register().status_code == 404
        assert system.exchange("opaque", "code").json()["error"] == "invalid_client"
    if mode == ClientMode.DCR_ONLY:
        assert (
            system.http.get(system.oauth.paths.authorize, params=system.parameters(URL)).status_code
            == 400
        )
        assert not fetcher.calls
    else:
        cid, token = system.tokens(URL)
        assert system.oauth.validate_access_token(token["access_token"], resource=A)
        assert system.oauth.validate_access_token(token["access_token"], resource=B) is None
        assert system.refresh(cid, token["refresh_token"], resource=B).status_code == 400
        successor = system.refresh(cid, token["refresh_token"]).json()
        assert system.revoke(cid, successor["refresh_token"]).status_code == 200
        assert system.oauth.validate_access_token(successor["access_token"], resource=A) is None
        assert fetcher.calls == [URL]  # cached for GET, consent POST, token, refresh, revocation
        assert URL not in system.storage.snapshot()["clients"]


@pytest.mark.parametrize("mode", [ClientMode.CIMD_ONLY, ClientMode.CIMD_AND_DCR])
@pytest.mark.parametrize("callback", [CALLBACK, "https://chatgpt.com/connector/oauth/opaque-id"])
def test_chatgpt_public_method_intersection(mode, callback):
    system, _ = cimd_system(mode)
    result = system.authorize(URL, redirect_uri=callback)
    from urllib.parse import parse_qs, urlsplit

    values = parse_qs(urlsplit(result.headers["location"]).query)
    assert values["iss"] == [ISSUER]
    token = system.exchange(URL, values["code"][0], redirect_uri=callback)
    assert token.status_code == 200
    assert system.storage.snapshot()["clients"] == {}
    assert system.oauth.engine.resolved_client.get() is None


@pytest.mark.parametrize("mode", [ClientMode.CIMD_ONLY, ClientMode.CIMD_AND_DCR])
def test_bad_cimd_never_downgrades_to_stored_dcr(mode):
    fetcher = FixtureFetcher(document(client_id="https://other.example.test/client.json"))
    system, _ = cimd_system(mode, fetcher=fetcher)
    with system.storage.transaction() as unit:
        unit.put_client(Client(URL, (CALLBACK,), "read write", ("authorization_code",)))
    before = system.storage.snapshot()
    for path, data in (
        (
            system.oauth.paths.token,
            {"client_id": URL, "grant_type": "authorization_code", "code": "bad"},
        ),
        (system.oauth.paths.revoke, {"client_id": URL, "token": "unknown"}),
    ):
        result = system.http.post(path, data=data)
        assert result.json()["error"] == "invalid_client"
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(URL)).status_code
        == 400
    )
    assert system.storage.snapshot() == before
    assert fetcher.calls == [URL, URL, URL]  # errors are not cached


@pytest.mark.parametrize(
    "override",
    [
        {"redirect_uris": []},
        {"redirect_uris": ["https://evil.test/cb"]},
        {"redirect_uris": [CALLBACK, CALLBACK]},
        {"scope": "admin"},
        {"scope": "read read"},
        {"response_types": ["token"]},
        {"grant_types": ["client_credentials"]},
        {"token_endpoint_auth_methods_supported": ["private_key_jwt"]},
        {"token_endpoint_auth_methods_supported": "none"},
        {"token_endpoint_auth_methods_supported": ["none", "none"]},
        {"token_endpoint_auth_methods_supported": ["none", 1]},
        {"token_endpoint_auth_methods_supported": ["none", "client_secret_basic"]},
        {"client_secret": "not-allowed"},
        {"client_secret_expires_at": 0},
        {"jwks": {"keys": []}},
        {"client_name": {}},
        {"client_id": URL + "/other"},
    ],
)
def test_cimd_metadata_rejections(override):
    system, _ = cimd_system(fetcher=FixtureFetcher(document(**override)))
    result = system.http.get(system.oauth.paths.authorize, params=system.parameters(URL))
    assert result.status_code == 400, result.text
    assert result.json()["error"] == "invalid_client"
    assert system.storage.snapshot()["clients"] == {}


@pytest.mark.parametrize(
    "raw", [b"[]", b"null", b"{", b'{"client_id":1,"client_id":2}', b'{"x":NaN}', b"\xff"]
)
def test_strict_metadata_json(raw):
    with pytest.raises((ValueError, UnicodeError)):
        strict_object(raw)
    system, _ = cimd_system(fetcher=FixtureFetcher(raw=raw))
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(URL)).status_code
        == 400
    )


@pytest.mark.parametrize(
    "status,headers,raw",
    [
        (
            301,
            {"content-type": "application/json", "location": "https://public.test/client.json"},
            None,
        ),
        (302, {"content-type": "application/json", "location": "http://127.0.0.1/private"}, None),
        (307, {"content-type": "application/json", "location": URL}, None),
        (404, {"content-type": "application/json"}, None),
        (200, {"content-type": "text/html"}, None),
        (200, {"content-type": "application/json"}, b"x" * 16_385),
    ],
)
def test_responses_and_redirects_rejected(status, headers, raw):
    system, fetcher = cimd_system(fetcher=FixtureFetcher(status=status, headers=headers, raw=raw))
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(URL)).status_code
        == 400
    )
    assert fetcher.calls == [URL]


@pytest.mark.parametrize(
    "uri",
    [
        "http://client.test/client.json",
        "https://client.test",
        "https://client.test/",
        "https://user@client.test/client.json",
        "https://client.test/a#",
        "https://client.test/a?x=1",
        "https://client.test:bad/a",
        "https://client.test:65536/a",
        "https://client.test:0/a",
        "https://client.test/%",
        "https://client.test/%zz",
        "https://client.test/../a",
        "https://client.test/%2e%2e/a",
        "https://client.test/a%2fb",
        "https://client.test/%252f",
        "https://client.test/%00",
        "https://client.test/%ff",
        "https://client.test/a\\b",
        "https://[fe80::1%25eth0]/client.json",
        "https://clïent.test/a",
    ],
)
def test_invalid_url_never_fetched(uri):
    assert not valid_client_id(uri)
    system, fetcher = cimd_system()
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(uri)).status_code
        == 400
    )
    assert fetcher.calls == []


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 -- rejected SSRF address, not a listener
        "224.0.0.1",
        "255.255.255.255",
        "100.64.0.1",
        "192.0.0.9",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "4000::1",
        "8000::1",
        "fec0::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
        "not-an-address",
    ],
)
def test_special_use_networks_rejected(address):
    with pytest.raises(MetadataFetchError):
        MetadataNetworkPolicy().check_address(address)


def test_global_addresses_and_origin_policy():
    policy = MetadataNetworkPolicy(allowed_origins=frozenset({"https://client.example.test"}))
    policy.check_address("8.8.8.8")
    policy.check_address("2606:4700:4700::1111")
    policy.check_url(URL)
    with pytest.raises(MetadataFetchError):
        policy.check_url("https://other.test/client.json")
    with pytest.raises(MetadataFetchError):
        MetadataNetworkPolicy().check_url("https://127.0.0.1/client.json")


def test_startup_configuration_and_no_cache_bypass_after_mode_change():
    with pytest.raises(ValueError):
        System(client_mode=ClientMode.CIMD_ONLY)
    with pytest.raises(ValueError):
        System(
            client_mode=ClientMode.DCR_ONLY, cimd=ClientMetadataDocuments(fetcher=FixtureFetcher())
        )
    with pytest.raises(ValueError):
        System(client_mode="unknown")
    with pytest.raises(ValueError):
        cimd_system(network=MetadataNetworkPolicy(allow_loopback=True))
    combined, fetcher = cimd_system(ClientMode.CIMD_AND_DCR)
    cid, dcr_token = combined.tokens()
    _, cimd_token = combined.tokens(URL)
    storage = combined.storage
    only, _ = cimd_system()
    # Recreate with the same storage; switching modes never destroys registrations.
    only = System(
        storage=storage,
        client_mode=ClientMode.CIMD_ONLY,
        cimd=only.oauth.cimd.__class__(fetcher=FixtureFetcher()),
        policy=ExactRedirectPolicy({CALLBACK, "https://chatgpt.com/connector/oauth/opaque-id"}),
    )
    assert only.refresh(cid, dcr_token["refresh_token"]).status_code == 400
    assert only.oauth.validate_access_token(dcr_token["access_token"], resource=A) is None
    assert cid in storage.snapshot()["clients"]
    assert only.refresh(URL, cimd_token["refresh_token"]).status_code == 200
    restored = System(storage=storage)
    assert restored.refresh(cid, dcr_token["refresh_token"]).status_code == 200
    assert (
        restored.http.get(
            restored.oauth.paths.authorize, params=restored.parameters(URL)
        ).status_code
        == 400
    )
    assert fetcher.calls == [URL]
    back, _ = cimd_system(ClientMode.CIMD_AND_DCR)
    back = System(
        storage=storage,
        client_mode=ClientMode.CIMD_AND_DCR,
        cimd=ClientMetadataDocuments(fetcher=FixtureFetcher()),
    )
    assert back.register().status_code == 201


def test_cache_ttl_bounds_eviction_and_no_store():
    now = [0.0]
    config = ClientMetadataDocuments(
        fetcher=FixtureFetcher(),
        clock=lambda: now[0],
        limits=CIMDLimits(entries=1, min_ttl=5, max_ttl=10, default_ttl=5),
    )

    def parse(data):
        return Client(data["client_id"], (CALLBACK,), "read", ("authorization_code",))

    asyncio.run(config.resolve(URL, parse))
    asyncio.run(config.resolve(URL, parse))
    assert len(config.fetcher.calls) == 1
    now[0] = 10
    asyncio.run(config.resolve(URL, parse))
    assert len(config.fetcher.calls) == 2
    other = URL + "/second"
    config.fetcher.data = document(client_id=other)
    asyncio.run(config.resolve(other, parse))
    config.fetcher.data = document()
    asyncio.run(config.resolve(URL, parse))
    assert len(config.fetcher.calls) == 4
    config.fetcher.headers["cache-control"] = "no-store"
    now[0] = 30
    asyncio.run(config.resolve(URL, parse))
    asyncio.run(config.resolve(URL, parse))
    assert len(config.fetcher.calls) == 6
    assert config._ttl({"cache-control": "max-age=5", "age": "4"}) == 5


def test_concurrent_cache_miss_single_fetch_and_context_isolation():
    class SlowFetcher(FixtureFetcher):
        async def fetch(self, *args, **kwargs):
            await asyncio.sleep(0.1)
            return await super().fetch(*args, **kwargs)

    system, fetcher = cimd_system(fetcher=SlowFetcher())
    barrier = Barrier(4)

    def authorize():
        barrier.wait(timeout=10)
        return system.http.get(system.oauth.paths.authorize, params=system.parameters(URL))

    with ThreadPoolExecutor(4) as pool:
        results = [job.result() for job in [pool.submit(authorize) for _ in range(4)]]
    assert all(result.status_code == 200 for result in results)
    assert fetcher.calls == [URL]
    assert all(
        result.json()["context"]["client_origin"] == "https://client.example.test"
        for result in results
    )
    assert system.oauth.engine.resolved_client.get() is None


def test_sanitized_diagnostics_and_authlib_other_debug_survives(caplog):
    from test_security import FaultStorage

    caplog.set_level(logging.DEBUG)
    store = FaultStorage()
    system = System(storage=store)
    cid = system.client()
    code = system.code(cid)
    store.fail = True
    failure = system.exchange(cid, code)
    incident = failure.headers["x-oauth-incident-id"]
    record = next(r for r in caplog.records if r.name == "oauth21_asgi.errors")
    assert record.incident_id == incident
    assert record.endpoint == "token"
    assert record.exception_class == "RuntimeError"
    assert "Do not disclose" not in caplog.text
    assert code not in caplog.text
    assert record.exc_info is None
    logging.getLogger("authlib.oauth2.rfc6749.grants.authorization_code").debug(
        "Unrelated diagnostic"
    )
    assert "Unrelated diagnostic" in caplog.text
    caplog.clear()
    store.fail = False
    system.exchange(cid, "invalid")
    assert not [r for r in caplog.records if r.name == "oauth21_asgi.errors"]


def test_metadata_scope_change_cannot_widen_exchange_or_refresh():
    fetcher = FixtureFetcher(
        headers={"content-type": "application/json", "cache-control": "no-store"}
    )
    system, _ = cimd_system(fetcher=fetcher)
    code = system.code(URL)
    fetcher.data["scope"] = "read"
    rejected = system.exchange(URL, code)
    assert rejected.status_code == 400
    assert rejected.json()["error"] == "invalid_scope"
    # A metadata mismatch must preserve the previously authorized code.
    fetcher.data["scope"] = "read write"
    issued = system.exchange(URL, code)
    assert issued.status_code == 200
    token = issued.json()
    fetcher.data["scope"] = "read"
    assert system.refresh(URL, token["refresh_token"]).json()["error"] == "invalid_scope"
    narrowed = system.refresh(URL, token["refresh_token"], scope="read")
    assert narrowed.status_code == 200
    assert narrowed.json()["scope"] == "read"


def test_cache_inflight_capacity_failure_retry_and_timeout():
    from authlib.oauth2.rfc6749 import InvalidClientError

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()

        class WaitingFetcher(FixtureFetcher):
            async def fetch(self, *args, **kwargs):
                started.set()
                await release.wait()
                return await super().fetch(*args, **kwargs)

        fetcher = WaitingFetcher(raw=b'{"broken": true}')
        config = ClientMetadataDocuments(fetcher=fetcher, limits=CIMDLimits(concurrent_fetches=1))

        def parse(data):
            return Client(data["client_id"], (CALLBACK,), "read", ("authorization_code",))

        leader = asyncio.create_task(config.resolve(URL, parse))
        await started.wait()
        follower = asyncio.create_task(config.resolve(URL, parse))
        await asyncio.sleep(0)
        with pytest.raises(InvalidClientError):
            await config.resolve(URL + "/other", parse)
        release.set()
        results = await asyncio.gather(leader, follower, return_exceptions=True)
        assert all(isinstance(result, InvalidClientError) for result in results)
        assert fetcher.calls == [URL]
        fetcher.raw = None
        assert (await config.resolve(URL, parse)).client_id == URL
        assert fetcher.calls == [URL, URL]
        # A fetch timeout releases capacity and does not install valid cached state.
        release.clear()
        timeout_config = ClientMetadataDocuments(fetcher=fetcher, limits=CIMDLimits(timeout=0.01))
        with pytest.raises(InvalidClientError):
            await timeout_config.resolve(URL, parse)
        release.set()
        assert (await timeout_config.resolve(URL, parse)).client_id == URL

    asyncio.run(scenario())
