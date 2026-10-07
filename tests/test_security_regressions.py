"""Regression coverage for consent, input bounds and client-source validation."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.oauth2.rfc6749 import InvalidRequestError
from conftest import CALLBACK, A, System
from starlette.requests import Request
from test_cimd import URL, FixtureFetcher, cimd_system, document

from oauth21_asgi import (
    CIMDLimits,
    ClientMetadataDocuments,
    ClientMode,
    ExactRedirectPolicy,
    Limits,
)


def test_consent_freezes_omitted_scope_before_metadata_expands():
    fetcher = FixtureFetcher(
        data=document(scope="read", redirect_uris=[CALLBACK]),
        headers={"content-type": "application/json", "cache-control": "no-store"},
    )
    system, _ = cimd_system(fetcher=fetcher)
    parameters = system.parameters(URL)
    parameters.pop("scope")
    first = system.http.get(system.oauth.paths.authorize, params=parameters)
    assert first.status_code == 200
    assert first.json()["context"]["scopes"] == ["read"]
    fetcher.data["scope"] = "read write"
    completed = system.http.post(
        system.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    assert completed.status_code == 302
    code = parse_qs(urlsplit(completed.headers["location"]).query)["code"][0]
    reply = system.exchange(URL, code)
    assert reply.status_code == 200
    assert reply.json()["scope"] == "read"


def test_consent_freezes_default_redirect_before_metadata_changes():
    other_callback = "https://client.example.test/other-callback"
    fetcher = FixtureFetcher(
        data=document(redirect_uris=[CALLBACK]),
        headers={"content-type": "application/json", "cache-control": "no-store"},
    )
    # Both destinations are host-allowed; the user only saw the first one.
    system = System(
        client_mode=ClientMode.CIMD_ONLY,
        cimd=ClientMetadataDocuments(fetcher=fetcher),
        policy=ExactRedirectPolicy({CALLBACK, other_callback}),
    )
    parameters = system.parameters(URL)
    parameters.pop("redirect_uri")
    first = system.http.get(system.oauth.paths.authorize, params=parameters)
    assert first.status_code == 200
    assert first.json()["context"]["redirect_uri"] == CALLBACK
    fetcher.data["redirect_uris"] = [other_callback]
    completed = system.http.post(
        system.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    assert completed.status_code == 400
    assert "location" not in completed.headers
    assert not system.storage.snapshot()["codes"]


def test_non_ascii_consent_token_is_expected_rejection(caplog):
    system = System()
    caplog.set_level(logging.ERROR, logger="oauth21_asgi.errors")
    system.http.cookies.set("oauth21_consent", "ascii-cookie")
    reply = system.http.post(
        system.oauth.paths.authorize, data={"consent_token": "\u00e9", "decision": "allow"}
    )
    assert reply.status_code == 400
    assert not [record for record in caplog.records if record.name == "oauth21_asgi.errors"]


def test_oversized_query_is_rejected_before_url_or_parameter_parsing():
    system = System(limits=replace(Limits(), query_bytes=8))

    class UnparsedRequest(Request):
        @property
        def url(self):
            raise AssertionError("Oversized query must not construct a URL")

        @property
        def query_params(self):
            raise AssertionError("Oversized query must not parse parameters")

    request = UnparsedRequest({"type": "http", "query_string": b"a=" + b"x" * 100})
    with pytest.raises(InvalidRequestError) as failure:
        system.oauth.check_transport(request)
    assert failure.value.status_code == 413


@pytest.mark.parametrize(
    "cache_control",
    [
        'no-cache="redirect_uris", max-age=3600',
        "max-age=0, max-age=3600",
        "max-age=invalid",
    ],
)
def test_ambiguous_cache_directives_never_reuse_metadata(cache_control):
    fetcher = FixtureFetcher(
        headers={"content-type": "application/json", "cache-control": cache_control}
    )
    system, _ = cimd_system(fetcher=fetcher)
    for _ in range(2):
        assert (
            system.http.get(system.oauth.paths.authorize, params=system.parameters(URL)).status_code
            == 200
        )
    assert fetcher.calls == [URL, URL]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_registration_rejects_non_json_numbers(constant):
    system = System()
    raw = json.dumps({"redirect_uris": [CALLBACK]})[:-1] + ', "extension": ' + constant + "}"
    reply = system.http.post(
        system.oauth.paths.register, content=raw, headers={"content-type": "application/json"}
    )
    assert reply.status_code == 400
    assert not system.storage.snapshot()["clients"]


def test_access_validation_rejects_orphaned_registered_client():
    system = System()
    cid, token = system.tokens()
    snapshot = system.storage.snapshot()
    snapshot["clients"].pop(cid)
    from oauth21_asgi import MemoryStorage

    orphaned = System(storage=MemoryStorage.from_snapshot(snapshot))
    assert orphaned.oauth.validate_access_token(token["access_token"], resource=A) is None


@pytest.mark.parametrize("value", [True, 0.5, float("nan")])
def test_cimd_default_ttl_requires_integer(value):
    with pytest.raises(ValueError):
        CIMDLimits(default_ttl=value)


def test_cimd_timeout_requires_real_number_not_boolean():
    with pytest.raises(ValueError):
        CIMDLimits(timeout=True)


def test_following_cache_request_survives_follower_cancellation():
    async def scenario():
        ready, release = asyncio.Event(), asyncio.Event()

        class WaitingFetcher(FixtureFetcher):
            async def fetch(self, *args, **kwargs):
                ready.set()
                await release.wait()
                return await super().fetch(*args, **kwargs)

        system, _ = cimd_system(fetcher=WaitingFetcher())
        config: ClientMetadataDocuments = system.oauth.cimd
        leader = asyncio.create_task(config.resolve(URL, system.oauth.engine.cimd_client))
        await ready.wait()
        follower = asyncio.create_task(config.resolve(URL, system.oauth.engine.cimd_client))
        await asyncio.sleep(0)
        follower.cancel()
        with pytest.raises(asyncio.CancelledError):
            await follower
        release.set()
        assert (await leader).client_id == URL
        assert (await config.resolve(URL, system.oauth.engine.cimd_client)).client_id == URL

    asyncio.run(scenario())


def test_slow_request_body_has_a_total_deadline():
    system = System(limits=replace(Limits(), body_timeout=1))

    async def receive():
        await asyncio.sleep(2)
        return {"type": "http.request", "body": b"small-body", "more_body": False}

    request = Request({"type": "http"}, receive)
    with pytest.raises(InvalidRequestError) as failure:
        asyncio.run(system.oauth.body(request))
    assert failure.value.status_code == 408


def test_dcr_consent_freezes_default_scope():
    system = System()
    cid = system.client(scope="read")
    parameters = system.parameters(cid)
    parameters.pop("scope")
    first = system.http.get(system.oauth.paths.authorize, params=parameters)
    assert first.json()["context"]["scopes"] == ["read"]
    with system.storage.transaction() as unit:
        unit.put_client(replace(unit.get_client(cid), scope="read write"))
    completed = system.http.post(
        system.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    code = parse_qs(urlsplit(completed.headers["location"]).query)["code"][0]
    assert system.exchange(cid, code).json()["scope"] == "read"


def test_legacy_pending_without_resolved_defaults_requires_new_consent():
    system = System()
    cid = system.client()
    first = system.http.get(system.oauth.paths.authorize, params=system.parameters(cid))
    with system.storage.transaction() as unit:
        pending = unit.pending()[0]
        legacy = dict(pending.parameters)
        legacy.pop("scope")
        unit.put_pending(replace(pending, parameters=legacy))
    reply = system.http.post(
        system.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    assert reply.status_code == 400
    assert "location" not in reply.headers
    assert not system.storage.snapshot()["codes"]


def test_combined_mode_rejects_unknown_stored_client_source():
    from oauth21_asgi import MemoryStorage

    system, _ = cimd_system(ClientMode.CIMD_AND_DCR)
    _, token = system.tokens()
    snapshot = system.storage.snapshot()
    for grant in snapshot["grants"].values():
        grant["client_source"] = "unknown"
    reloaded = System(
        storage=MemoryStorage.from_snapshot(snapshot),
        client_mode=ClientMode.CIMD_AND_DCR,
        cimd=ClientMetadataDocuments(fetcher=FixtureFetcher()),
    )
    assert reloaded.oauth.validate_access_token(token["access_token"], resource=A) is None


def test_default_registered_scope_must_still_fit_reconfigured_server():
    system = System()
    cid = system.client()
    reconfigured = System(storage=system.storage, scopes={"read"})
    parameters = reconfigured.parameters(cid)
    parameters.pop("scope")
    reply = reconfigured.http.get(reconfigured.oauth.paths.authorize, params=parameters)
    assert reply.status_code == 302
    assert parse_qs(urlsplit(reply.headers["location"]).query)["error"] == ["invalid_scope"]
    assert not system.storage.snapshot()["pending"]


def test_host_content_security_policy_is_preserved_with_frame_protection():
    system = System()
    original = system.oauth.consent.render
    host_policy = "default-src 'none'; form-action 'self'; frame-ancestors 'self'"

    async def render(request, context, consent_token):
        result = await original(request, context, consent_token)
        result.headers["Content-Security-Policy"] = host_policy
        return result

    system.oauth.consent.render = render
    reply = system.http.get(system.oauth.paths.authorize, params=system.parameters(system.client()))
    assert reply.status_code == 200
    assert reply.headers.get_list("content-security-policy") == [
        host_policy,
        "frame-ancestors 'none'",
    ]


def test_unexpected_discovery_failure_is_sanitized(caplog):
    system = System()
    caplog.set_level(logging.ERROR, logger="oauth21_asgi.errors")

    def failure(request):
        raise RuntimeError("synthetic-private-detail")

    system.oauth.check_transport = failure
    reply = system.http.get(system.oauth.discovery_path)
    assert reply.status_code == 503
    assert reply.json() == {"error": "temporarily_unavailable"}
    assert "synthetic-private-detail" not in caplog.text
    assert "synthetic-private-detail" not in reply.text
    record = next(record for record in caplog.records if record.name == "oauth21_asgi.errors")
    assert record.endpoint == "discovery"
    assert record.exc_info is None
