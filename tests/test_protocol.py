from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import CALLBACK, ISSUER, VERIFIER, A, B, System

from oauth21_asgi import Limits, MemoryStorage, Paths


def query(result):
    return parse_qs(urlsplit(result.headers["location"]).query)


@pytest.mark.parametrize("issuer", [ISSUER, ISSUER.rstrip("/")])
@pytest.mark.parametrize("resource,other", [(A, B), (B, A)])
@pytest.mark.parametrize(
    "callback_uri", [CALLBACK, "https://chatgpt.com/connector/oauth/opaque-id"]
)
def test_chatgpt_compatible_protocol(issuer, resource, other, callback_uri):
    from oauth21_asgi import ExactRedirectPolicy

    s = System(issuer=issuer, policy=ExactRedirectPolicy({callback_uri}))
    metadata = s.http.get(s.oauth.discovery_path).json()
    assert metadata["issuer"] == issuer
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["authorization_response_iss_parameter_supported"] is True
    registration = s.register(redirect_uris=[callback_uri])
    assert registration.status_code == 201
    assert registration.json()["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in registration.json()
    cid = registration.json()["client_id"]
    callback = s.authorize(cid, resource=resource, redirect_uri=callback_uri)
    values = query(callback)
    assert values["iss"] == [issuer]
    assert values["state"] == [s.parameters(cid)["state"]]
    token = s.exchange(cid, values["code"][0], resource=resource, redirect_uri=callback_uri).json()
    assert s.oauth.validate_access_token(token["access_token"], resource=resource, scopes={"read"})
    assert s.oauth.validate_access_token(token["access_token"], resource=other) is None
    rotated = s.refresh(cid, token["refresh_token"], resource=resource)
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != token["refresh_token"]
    assert s.revoke(cid, rotated.json()["refresh_token"]).status_code == 200
    assert s.oauth.validate_access_token(rotated.json()["access_token"], resource=resource) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_endpoint_auth_method": "client_secret_basic"},
        {"token_endpoint_auth_method": "client_secret_post"},
        {"token_endpoint_auth_method": None},
        {"grant_types": ["client_credentials"]},
        {"grant_types": ["authorization_code", "password"]},
        {"grant_types": []},
        {"response_types": ["token"]},
        {"redirect_uris": []},
        {"redirect_uris": CALLBACK},
        {"redirect_uris": [CALLBACK, CALLBACK]},
        {"redirect_uris": ["https://evil.test/cb"]},
        {"redirect_uris": ["http://localhost:80@attacker.test/cb"]},
        {"redirect_uris": [CALLBACK + "#fragment"]},
        {"redirect_uris": [42]},
        {"scope": "openid"},
        {"scope": ["read"]},
        {"scope": "admin"},
        {"contacts": "mail@example.test"},
        {"client_name": {}},
        {"jwks": {}},
    ],
)
def test_dcr_metadata_rejected(system, overrides):
    result = system.register(**overrides)
    assert result.status_code == 400, result.text
    assert result.json()["error"] == "invalid_client_metadata"


def test_dcr_defaults_and_limits():
    s = System(limits=replace(Limits(), registered_clients=1, redirects_per_client=1))
    first = s.http.post(s.oauth.paths.register, json={"redirect_uris": [CALLBACK]})
    assert first.status_code == 201
    assert first.json()["token_endpoint_auth_method"] == "none"
    assert s.register().status_code == 400
    s.now += s.oauth.limits.client_ttl + 1
    assert s.register().status_code == 201


@pytest.mark.parametrize(
    "data", [b"{", b"[]", b"null", b'{"redirect_uris":[],"redirect_uris":[]}', bytes([255])]
)
def test_dcr_malformed_json(system, data):
    assert (
        system.http.post(
            system.oauth.paths.register, content=data, headers={"content-type": "application/json"}
        ).status_code
        == 400
    )


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"scope": "admin"}, "invalid_scope"),
        ({"scope": "read read"}, "invalid_scope"),
        ({"resource": B + "/wrong"}, "invalid_target"),
        ({"resource": ""}, "invalid_target"),
        ({"code_challenge": ""}, "invalid_request"),
        ({"code_challenge": "x"}, "invalid_request"),
        ({"code_challenge": "x" * 44}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge_method": ""}, "invalid_request"),
        ({"response_type": "token"}, "unsupported_response_type"),
    ],
)
def test_safe_authorization_errors_include_issuer(system, overrides, error):
    cid = system.client()
    result = system.http.get(
        system.oauth.paths.authorize, params=system.parameters(cid, **overrides)
    )
    assert result.status_code == 302, result.text
    assert query(result)["error"] == [error]
    assert query(result)["iss"] == [ISSUER]
    assert query(result)["state"] == [system.parameters(cid)["state"]]


@pytest.mark.parametrize(
    "overrides",
    [
        {"client_id": "unknown"},
        {"redirect_uri": "https://evil.test/callback"},
        {"redirect_uri": CALLBACK + "/"},
        {"redirect_uri": CALLBACK + "?inject=1"},
    ],
)
def test_unsafe_redirect_never_used(system, overrides):
    values = system.parameters(system.client())
    values.update(overrides)
    result = system.http.get(system.oauth.paths.authorize, params=values)
    assert result.status_code == 400
    assert "location" not in result.headers


def test_allow_deny_and_authentication(system):
    cid = system.client()
    result = system.authorize(cid, decision="deny")
    assert result.status_code == 302
    assert query(result)["error"] == ["access_denied"]
    assert query(result)["iss"] == [ISSUER]
    assert query(result)["state"] == [system.parameters(cid)["state"]]
    system.identity.signed_in = False
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(cid)).status_code
        == 401
    )
    system.identity.signed_in = True
    system.identity.subject = replace(system.identity.subject, active=False)
    assert (
        system.http.get(system.oauth.paths.authorize, params=system.parameters(cid)).status_code
        == 400
    )


@pytest.mark.parametrize(
    "field", ["resource", "scope", "client_id", "redirect_uri", "code_challenge_method"]
)
def test_authorization_duplicate_parameters(system, field):
    values = list(system.parameters(system.client()).items())
    values.append((field, dict(values)[field]))
    result = system.http.get(system.oauth.paths.authorize, params=values)
    assert result.status_code in (400, 302)
    if result.status_code == 302:
        assert query(result)["error"] == (
            ["invalid_target"] if field == "resource" else ["invalid_request"]
        )
        assert query(result)["iss"] == [ISSUER]


@pytest.mark.parametrize(
    "overrides",
    [
        {"code_verifier": "w" * 64},
        {"code_verifier": "short"},
        {"code_verifier": ""},
        {"code_verifier": VERIFIER + "\n"},
        {"redirect_uri": CALLBACK + "/"},
        {"resource": B},
        {"resource": ""},
    ],
)
def test_code_mismatch_does_not_consume(system, overrides):
    cid = system.client()
    code = system.code(cid)
    assert system.exchange(cid, code, **overrides).status_code == 400
    assert system.exchange(cid, code).status_code == 200
    assert system.exchange(cid, code).status_code == 400


def test_code_wrong_client_and_expiry(system):
    cid = system.client()
    code = system.code(cid)
    assert system.exchange(system.client(), code).status_code == 400
    assert system.exchange(cid, code).status_code == 200
    expired = system.code(cid)
    system.now += system.oauth.limits.code_ttl
    assert system.exchange(cid, expired).status_code == 400


def test_concurrent_code_exchange(system):
    cid = system.client()
    code = system.code(cid)
    barrier = Barrier(2)

    def exchange():
        barrier.wait(timeout=10)
        return system.exchange(cid, code).status_code

    with ThreadPoolExecutor(2) as pool:
        jobs = [pool.submit(exchange), pool.submit(exchange)]
        assert sorted(j.result() for j in jobs) == [200, 400]
    assert len(system.storage.snapshot()["grants"]) == 1


def test_refresh_narrows_and_does_not_escalate(system):
    cid, first = system.tokens()
    assert system.refresh(cid, first["refresh_token"], scope="admin").status_code == 400
    second = system.refresh(cid, first["refresh_token"], scope="read")
    assert second.status_code == 200, second.text
    assert second.json()["scope"] == "read"
    assert system.oauth.validate_access_token(first["access_token"], resource=A) is None
    assert (
        system.oauth.validate_access_token(
            second.json()["access_token"], resource=A, scopes={"write"}
        )
        is None
    )
    assert (
        system.refresh(cid, second.json()["refresh_token"], scope="read write").status_code == 400
    )


@pytest.mark.parametrize("kind", ["wrong-client", "wrong-resource"])
def test_bad_refresh_binding_does_not_poison_family(system, kind):
    cid, token = system.tokens()
    rotated = system.refresh(cid, token["refresh_token"]).json()
    kwargs = {"resource": B} if kind == "wrong-resource" else {}
    other = system.client() if kind == "wrong-client" else cid
    assert system.refresh(other, token["refresh_token"], **kwargs).status_code == 400
    assert system.oauth.validate_access_token(rotated["access_token"], resource=A)
    assert system.refresh(cid, rotated["refresh_token"]).status_code == 200


def test_refresh_replay_revokes_family(system):
    cid, token = system.tokens()
    rotated = system.refresh(cid, token["refresh_token"]).json()
    assert system.refresh(cid, token["refresh_token"]).status_code == 400
    assert system.oauth.validate_access_token(rotated["access_token"], resource=A) is None
    assert system.refresh(cid, rotated["refresh_token"]).status_code == 400


def test_parallel_refresh_does_not_fork(system):
    cid, token = system.tokens()
    barrier = Barrier(2)

    def refresh():
        barrier.wait(timeout=10)
        return system.refresh(cid, token["refresh_token"])

    with ThreadPoolExecutor(2) as pool:
        jobs = [pool.submit(refresh), pool.submit(refresh)]
        results = [j.result() for j in jobs]
    assert sorted(r.status_code for r in results) == [200, 400]
    winner = next(r.json() for r in results if r.status_code == 200)
    assert system.oauth.validate_access_token(winner["access_token"], resource=A) is None
    assert len(system.storage.snapshot()["grants"]) == 1


def test_absolute_lifetime_and_rotation_bound():
    s = System(limits=replace(Limits(), grant_ttl=50, access_ttl=20, refresh_rotations=2))
    cid, token = s.tokens()
    s.now += 40
    rotated = s.refresh(cid, token["refresh_token"])
    assert rotated.status_code == 200
    assert rotated.json()["expires_in"] == 10
    s.now += 10
    assert s.refresh(cid, rotated.json()["refresh_token"]).status_code == 400
    assert s.oauth.validate_access_token(rotated.json()["access_token"], resource=A) is None
    cid, token = s.tokens()
    for _ in range(2):
        token = s.refresh(cid, token["refresh_token"]).json()
    assert s.refresh(cid, token["refresh_token"]).status_code == 400
    assert s.oauth.validate_access_token(token["access_token"], resource=A) is None
    assert max(len(g["used_refresh"]) for g in s.storage.snapshot()["grants"].values()) == 2


@pytest.mark.parametrize("attribute", ["authorization_version", "active", "subject_id"])
def test_subject_binding_invalidates_code_access_refresh(system, attribute):
    cid, token = system.tokens()
    code = system.code(cid)
    replacement = {
        "authorization_version": "incarnation-2:version-1",
        "active": False,
        "subject_id": "bob",
    }
    system.identity.subject = replace(
        system.identity.subject, **{attribute: replacement[attribute]}
    )
    assert system.exchange(cid, code).status_code == 400
    assert system.oauth.validate_access_token(token["access_token"], resource=A) is None
    assert system.refresh(cid, token["refresh_token"]).status_code == 400


@pytest.mark.parametrize("field", ["access_token", "refresh_token"])
def test_revocation_and_unknown(system, field):
    cid, token = system.tokens()
    assert system.revoke(cid, token[field], token_type_hint="access_token").status_code == 200
    assert system.revoke(cid, "unknown").status_code == 200
    assert system.oauth.validate_access_token(token["access_token"], resource=A) is None
    assert system.refresh(cid, token["refresh_token"]).status_code == 400


def test_revoke_wrong_client(system):
    cid, token = system.tokens()
    assert system.revoke(system.client(), token["access_token"]).status_code == 400
    assert system.oauth.validate_access_token(token["access_token"], resource=A)
    assert system.revoke(cid, token["access_token"], token_type_hint="jwt").status_code == 401


def test_storage_reload_no_plaintext_and_logs(system, caplog):
    caplog.set_level(logging.DEBUG)
    cid = system.client()
    code = system.code(cid)
    token = system.exchange(cid, code).json()
    rotated = system.refresh(cid, token["refresh_token"]).json()
    snapshot = json.dumps(system.storage.snapshot())
    for secret in (
        code,
        *[token[k] for k in ("access_token", "refresh_token")],
        *[rotated[k] for k in ("access_token", "refresh_token")],
    ):
        assert secret not in snapshot
        assert secret not in caplog.text
    restored = System(storage=MemoryStorage.from_snapshot(json.loads(snapshot)))
    assert restored.oauth.validate_access_token(rotated["access_token"], resource=A)
    assert restored.refresh(cid, rotated["refresh_token"]).status_code == 200


def test_method_content_type_body_and_cache(system):
    for path in (system.oauth.paths.register, system.oauth.paths.token, system.oauth.paths.revoke):
        assert system.http.get(path).status_code == 405
        assert (
            system.http.post(path, content="{}", headers={"content-type": "text/plain"}).status_code
            == 415
        )
        media = (
            "application/json"
            if path == system.oauth.paths.register
            else "application/x-www-form-urlencoded"
        )
        result = system.http.post(
            path,
            content="x" * (system.oauth.limits.body_bytes + 1),
            headers={"content-type": media},
        )
        assert result.status_code == 413
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["pragma"] == "no-cache"
    cid, token = system.tokens()
    assert token["token_type"] == "Bearer"
    assert system.http.post(system.oauth.paths.token, json={}).status_code == 415
    result = system.http.post(
        system.oauth.paths.token,
        content="client_id=a&client_id=b",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert result.status_code == 400
    assert (
        system.http.post(
            system.oauth.paths.token + "?access_token=secret", data={"client_id": cid}
        ).status_code
        == 400
    )
    assert system.http.get(system.oauth.paths.authorize + "?x=" + "a" * 9000).status_code == 413


def test_client_authentication_none_only(system):
    cid = system.client()
    code = system.code(cid)
    for kwargs in ({"client_secret": ""}, {"client_secret": "secret"}):
        assert system.exchange(cid, code, **kwargs).json()["error"] == "invalid_client"
    data = {
        "grant_type": "authorization_code",
        "client_id": cid,
        "code": code,
        "resource": A,
        "code_verifier": VERIFIER,
        "redirect_uri": CALLBACK,
    }
    assert (
        system.http.post(
            system.oauth.paths.token, data=data, headers={"authorization": "Basic abc"}
        ).status_code
        == 400
    )
    assert system.exchange(cid, code).status_code == 200


def test_host_revoke_prune_and_paths(system):
    cid, token = system.tokens()
    system.code(cid)
    assert system.oauth.revoke_subject("nobody") == 0
    assert system.oauth.revoke_subject("alice") == 1
    assert system.oauth.validate_access_token(token["access_token"], resource=A) is None
    system.now += system.oauth.limits.grant_ttl + system.oauth.limits.client_ttl
    system.oauth.prune()
    assert all(not system.storage.snapshot()[g] for g in ("clients", "codes", "pending", "grants"))
    s = System(paths=Paths(token="/custom/token"))
    assert (
        s.http.get(s.oauth.discovery_path).json()["token_endpoint"]
        == "https://video.example.test/custom/token"
    )
    with pytest.raises(ValueError):
        s.oauth.mount(s.app)


def test_consent_csrf_expiry_subject_and_reuse(system):
    cid = system.client()
    first = system.http.get(system.oauth.paths.authorize, params=system.parameters(cid))
    data = {"consent_token": first.json()["consent_token"], "decision": "allow"}
    assert (
        system.http.post(
            system.oauth.paths.authorize, data=data, headers={"origin": "https://evil.test"}
        ).status_code
        == 400
    )
    assert (
        system.http.post(
            system.oauth.paths.authorize, data=data, headers={"sec-fetch-site": "cross-site"}
        ).status_code
        == 400
    )
    assert (
        system.http.post(
            system.oauth.paths.authorize, data={**data, "consent_token": "wrong"}
        ).status_code
        == 400
    )
    assert system.http.post(system.oauth.paths.authorize, data=data).status_code == 302
    assert system.http.post(system.oauth.paths.authorize, data=data).status_code == 400
    first = system.http.get(system.oauth.paths.authorize, params=system.parameters(cid))
    data["consent_token"] = first.json()["consent_token"]
    system.now += system.oauth.limits.consent_ttl + 1
    assert system.http.post(system.oauth.paths.authorize, data=data).status_code == 400
