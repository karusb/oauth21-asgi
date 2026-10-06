from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import replace

import pytest
from authlib.oauth2.rfc6749 import AuthorizationServer as AuthlibServer
from authlib.oauth2.rfc6749 import InvalidRequestError, OAuth2Error
from authlib.oauth2.rfc6749.authenticate_client import ClientAuthentication
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7591 import ClientMetadataClaims, ClientRegistrationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9207 import IssuerParameter
from conftest import CALLBACK, ISSUER, A, System

from oauth21_asgi import CallableRedirectPolicy, ExactRedirectPolicy, Limits, MemoryStorage, Paths
from oauth21_asgi.http import FormRequest
from oauth21_asgi.models import Client
from oauth21_asgi.policies import safe_uri


def test_actual_authlib_implementations_used(monkeypatch):
    calls = Counter()
    targets = [
        (AuthorizationCodeGrant, "validate_token_request"),
        (AuthorizationCodeGrant, "create_token_response"),
        (RefreshTokenGrant, "validate_token_request"),
        (RefreshTokenGrant, "create_token_response"),
        (CodeChallenge, "validate_code_verifier"),
        (ClientRegistrationEndpoint, "create_registration_response"),
        (ClientMetadataClaims, "validate"),
        (ClientAuthentication, "authenticate"),
        (RevocationEndpoint, "create_endpoint_response"),
        (IssuerParameter, "add_issuer_parameter"),
        (OAuth2Error, "__call__"),
    ]
    for cls, method in targets:
        original = getattr(cls, method)
        label = f"{cls.__name__}.{method}"

        def traced(*args, _original=original, _label=label, **kwargs):
            calls[_label] += 1
            return _original(*args, **kwargs)

        # Test-only spies on public methods; each invokes the real implementation.
        monkeypatch.setattr(cls, method, traced)
    s = System()
    assert isinstance(s.oauth.engine, AuthlibServer)
    cid, token = s.tokens()
    assert s.refresh(cid, token["refresh_token"]).status_code == 200
    assert s.revoke(cid, "unknown").status_code == 200
    s.exchange(cid, "invalid-code")
    assert set(calls) == {f"{cls.__name__}.{name}" for cls, name in targets}
    assert all(calls.values())


class FaultStorage:
    def __init__(self):
        self.inner = MemoryStorage()
        self.fail = False

    @contextmanager
    def transaction(self):
        with self.inner.transaction() as unit:
            yield unit
            if self.fail:
                raise RuntimeError("Do not disclose storage details or credentials")

    def snapshot(self):
        return self.inner.snapshot()


def test_persistence_failure_rolls_back_code_and_refresh():
    storage = FaultStorage()
    s = System(storage=storage)
    cid = s.client()
    code = s.code(cid)
    before = storage.snapshot()
    storage.fail = True
    result = s.exchange(cid, code)
    assert result.status_code == 503
    assert result.json() == {"error": "temporarily_unavailable"}
    assert storage.snapshot() == before
    storage.fail = False
    token = s.exchange(cid, code).json()
    before = storage.snapshot()
    storage.fail = True
    assert s.refresh(cid, token["refresh_token"]).status_code == 503
    assert storage.snapshot() == before
    storage.fail = False
    assert s.oauth.validate_access_token(token["access_token"], resource=A)
    assert s.refresh(cid, token["refresh_token"]).status_code == 200


def test_registration_consent_and_authorization_write_failures():
    store = FaultStorage()
    s = System(storage=store)
    store.fail = True
    assert s.register().status_code == 503
    assert store.snapshot()["clients"] == {}
    store.fail = False
    cid = s.client()
    store.fail = True
    assert s.http.get(s.oauth.paths.authorize, params=s.parameters(cid)).status_code == 503
    assert store.snapshot()["pending"] == {}
    store.fail = False
    first = s.http.get(s.oauth.paths.authorize, params=s.parameters(cid))
    before = store.snapshot()
    # Fail commit only when issuance reaches storage (not on the preceding load transaction).
    original = s.oauth.consent.decide

    async def fail_on_issue(request, context):
        decision = await original(request, context)
        store.fail = True
        return decision

    s.oauth.consent.decide = fail_on_issue
    result = s.http.post(
        s.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    assert result.status_code == 503 and "location" not in result.headers
    assert store.snapshot() == before


@pytest.mark.parametrize(
    "uri",
    [
        "ftp://example.test/a",
        "https://u:p@example.test/a",
        "https://example.test/a#x",
        "https://example.test:bad/a",
        "https://example.test/a\n",
        "",
        "https:///a",
        "http://attacker.test/a",
        "http://127.0.0.1:80@evil.test/a",
        "http://localhost.evil.test/a",
    ],
)
def test_redirect_policy_rejects_unsafe_uris(uri):
    assert not safe_uri(uri)
    assert not CallableRedirectPolicy(lambda _: True)(uri)
    with pytest.raises(ValueError):
        ExactRedirectPolicy({uri})


def test_loopback_is_explicit_and_policy_is_exact():
    for uri in ("http://127.0.0.1:8000/cb", "http://[::1]:8000/cb", "http://localhost:8000/cb"):
        assert not safe_uri(uri)
        assert ExactRedirectPolicy({uri}, allow_loopback=True)(uri)
    policy = CallableRedirectPolicy(lambda uri: uri == CALLBACK)
    assert policy(CALLBACK)
    assert not policy(CALLBACK + "/other")
    assert not safe_uri("http://evil.test/cb", allow_loopback=True)
    assert not safe_uri("https://example.test?x=1", issuer=True)
    assert not safe_uri("https://example.test:99999/cb")


@pytest.mark.parametrize(
    "settings",
    [
        {"issuer": "http://evil.test"},
        {"scopes": []},
        {"scopes": {"openid"}},
        {"scopes": {"read write"}},
        {"resources": []},
        {"resources": {"http://evil.test"}},
    ],
)
def test_configuration_fail_closed(settings):
    from conftest import FakeConsent, FakeIdentity

    from oauth21_asgi import AuthorizationServer

    values = dict(
        issuer=ISSUER,
        scopes={"read"},
        resources={A},
        storage=MemoryStorage(),
        identity=FakeIdentity(),
        consent=FakeConsent(),
        redirect_policy=ExactRedirectPolicy({CALLBACK}),
    )
    values.update(settings)
    with pytest.raises(ValueError):
        AuthorizationServer(**values)


def test_invalid_limits_paths_and_snapshots():
    for kwargs in ({"code_ttl": 601}, {"body_bytes": 0}, {"access_ttl": -1}):
        with pytest.raises(ValueError):
            Limits(**kwargs)
    for kwargs in ({"token": "/oauth/revoke"}, {"token": "//evil.test"}, {"token": "/bad?query"}):
        with pytest.raises(ValueError):
            Paths(**kwargs)
    with pytest.raises(ValueError):
        MemoryStorage.from_snapshot({"schema": 2})


def test_transport_origin_query_and_encoding(system):
    assert (
        system.http.get(system.oauth.discovery_path, headers={"host": "evil.test"}).status_code
        == 400
    )
    assert (
        system.http.get(system.oauth.paths.authorize + "?refresh_token=secret").status_code == 400
    )
    assert system.http.post(system.oauth.paths.register + "?x=1", json={}).status_code == 400
    assert (
        system.http.post(
            system.oauth.paths.token,
            content=bytes([255]),
            headers={"content-type": "application/x-www-form-urlencoded"},
        ).status_code
        == 400
    )
    assert (
        system.http.post(system.oauth.paths.revoke, data={"client_id": "missing"}).status_code
        == 400
    )
    assert (
        system.http.post(system.oauth.paths.token, data={"grant_type": "password"}).json()["error"]
        == "unsupported_grant_type"
    )


def test_registration_hook_blocks_without_oauth_authentication():
    seen = []

    def hook(request):
        seen.append(request.client.host)
        raise InvalidRequestError("Rate limit", status_code=429)

    s = System(hook=hook)
    assert s.register().status_code == 429
    assert seen == ["testclient"]
    assert s.storage.snapshot()["clients"] == {}


@pytest.mark.parametrize(
    "limit,operation",
    [("pending_consents", "pending"), ("authorization_codes", "code"), ("token_families", "token")],
)
def test_capacity_limits(limit, operation):
    s = System(limits=replace(Limits(), **{limit: 1}))
    cid = s.client()
    if operation == "pending":
        assert s.http.get(s.oauth.paths.authorize, params=s.parameters(cid)).status_code == 200
        assert s.http.get(s.oauth.paths.authorize, params=s.parameters(cid)).status_code == 400
    elif operation == "code":
        s.code(cid)
        result = s.authorize(cid)
        assert result.status_code == 302
        assert "error=" in result.headers["location"]
    else:
        s.tokens(cid)
        result = s.exchange(cid, s.code(cid))
        assert result.status_code == 400


def test_access_expiry_refresh_and_invalid_validation(system):
    cid, token = system.tokens()
    assert system.oauth.validate_access_token(token["access_token"], resource="invalid") is None
    assert system.oauth.validate_access_token("x" * 17000, resource=A) is None
    system.now += system.oauth.limits.access_ttl
    assert system.oauth.validate_access_token(token["access_token"], resource=A) is None
    assert system.refresh(cid, token["refresh_token"]).status_code == 200


def test_client_code_only_and_multiple_redirects():
    from conftest import VERIFIER

    s = System(policy=ExactRedirectPolicy({CALLBACK, CALLBACK + "/second"}))
    cid = s.client(
        grant_types=["authorization_code"], redirect_uris=[CALLBACK, CALLBACK + "/second"]
    )
    cid2, token = s.tokens(cid)
    assert cid2 == cid and "refresh_token" not in token
    assert s.refresh(cid, "unknown").status_code == 400
    values = s.parameters(cid)
    del values["redirect_uri"]
    assert s.http.get(s.oauth.paths.authorize, params=values).status_code == 400
    code = s.code(cid)
    assert s.exchange("", code).status_code == 400
    assert s.exchange(cid, code, code_verifier=VERIFIER).status_code == 200


def test_consent_version_changed_and_get_never_issues(system):
    cid = system.client()
    first = system.http.get(system.oauth.paths.authorize, params=system.parameters(cid))
    assert system.storage.snapshot()["codes"] == {}
    system.identity.subject = replace(system.identity.subject, authorization_version="changed")
    assert (
        system.http.post(
            system.oauth.paths.authorize,
            data={"consent_token": first.json()["consent_token"], "decision": "allow"},
        ).status_code
        == 400
    )


def test_client_methods_and_request_public_adapter():
    client = Client("id", (CALLBACK,), "read", ("authorization_code",))
    assert client.get_client_id() == "id"
    assert client.get_default_redirect_uri() == CALLBACK
    assert client.get_allowed_scope(None) == "read"
    assert not client.check_client_secret("any")
    assert client.check_endpoint_auth_method("none", "revocation")
    assert FormRequest("GET", ISSUER, [("key", "value")], {}).args == {"key": "value"}


def test_refresh_scope_duplicate_and_empty(system):
    cid, token = system.tokens()
    for scope in ("read read", ""):
        assert system.refresh(cid, token["refresh_token"], scope=scope).status_code == 400
    assert system.refresh(cid, token["refresh_token"]).status_code == 200


@pytest.mark.parametrize("when", ["before-decision", "after-decision"])
def test_post_callback_errors_also_have_exact_issuer(system, when):
    from urllib.parse import parse_qs, urlsplit

    cid = system.client()
    first = system.http.get(system.oauth.paths.authorize, params=system.parameters(cid))

    def narrow():
        with system.storage.transaction() as unit:
            unit.put_client(replace(unit.get_client(cid), scope="read"))

    if when == "before-decision":
        narrow()
    else:
        original = system.oauth.consent.decide

        async def decide(request, context):
            decision = await original(request, context)
            narrow()
            return decision

        system.oauth.consent.decide = decide
    callback = system.http.post(
        system.oauth.paths.authorize,
        data={"consent_token": first.json()["consent_token"], "decision": "allow"},
    )
    assert callback.status_code == 302
    values = parse_qs(urlsplit(callback.headers["location"]).query)
    assert values["error"] == ["invalid_scope"]
    assert values["iss"] == [ISSUER]
    assert values["state"] == [system.parameters(cid)["state"]]


def test_reject_fragment_delimiter_and_browser_backslash():
    assert not safe_uri("https://example.test/#")
    assert not safe_uri("https://example.test/" + chr(92) + "evil")


@pytest.mark.parametrize(
    "scope", ["read read", "read" + chr(9) + "write", "read  write", " read", "read "]
)
def test_scope_profile_rejects_ambiguous_whitespace(system, scope):
    assert system.register(scope=scope).status_code == 400
    cid = system.client()
    result = system.http.get(
        system.oauth.paths.authorize, params=system.parameters(cid, scope=scope)
    )
    assert result.status_code == 302 and "invalid_scope" in result.headers["location"]
    cid, token = system.tokens(cid)
    assert system.refresh(cid, token["refresh_token"], scope=scope).status_code == 400
