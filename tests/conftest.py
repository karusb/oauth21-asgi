from __future__ import annotations

from dataclasses import asdict
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import FastAPI
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from oauth21_asgi import (
    AuthorizationServer,
    Decision,
    ExactRedirectPolicy,
    Limits,
    MemoryStorage,
    Subject,
)

ISSUER = "https://video.example.test/"
A = "https://video.example.test/mcp"
B = "https://video.example.test/studio/mcp"
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "v" * 64


class FakeIdentity:
    def __init__(self):
        self.subject = Subject("alice", "incarnation-1:version-1")
        self.signed_in = True

    async def authenticate(self, request):
        return self.subject if self.signed_in else JSONResponse({"login": True}, status_code=401)

    def get_subject(self, subject_id):
        return self.subject if subject_id == self.subject.subject_id else None


class FakeConsent:
    async def render(self, request, context, consent_token):
        return JSONResponse({"context": asdict(context), "consent_token": consent_token})

    async def decide(self, request, context):
        form = await request.form()
        return Decision(form.get("decision", "deny"))


class System:
    def __init__(
        self, *, limits=None, storage=None, issuer=ISSUER, paths=None, hook=None, policy=None
    ):
        self.now = 2_000_000_000.0
        self.identity = FakeIdentity()
        self.storage = storage or MemoryStorage()
        options = {} if paths is None else {"paths": paths}
        self.oauth = AuthorizationServer(
            issuer=issuer,
            scopes={"read", "write"},
            resources={A, B},
            storage=self.storage,
            identity=self.identity,
            consent=FakeConsent(),
            redirect_policy=policy or ExactRedirectPolicy({CALLBACK}),
            limits=limits or Limits(),
            clock=lambda: self.now,
            registration_hook=hook,
            **options,
        )
        self.app = FastAPI()
        self.oauth.mount(self.app)
        self.http = TestClient(self.app, base_url=issuer, follow_redirects=False)

    def register(self, **overrides):
        data = {
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "read write",
        }
        data.update(overrides)
        return self.http.post(self.oauth.paths.register, json=data)

    def client(self, **overrides):
        result = self.register(**overrides)
        assert result.status_code == 201, result.text
        return result.json()["client_id"]

    def parameters(self, client_id, **overrides):
        result = {
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "response_type": "code",
            "scope": "read write",
            "resource": A,
            "state": "state with + / unicode α",
            "code_challenge": create_s256_code_challenge(VERIFIER),
            "code_challenge_method": "S256",
        }
        result.update(overrides)
        return result

    def authorize(self, client_id, decision="allow", **overrides):
        first = self.http.get(
            self.oauth.paths.authorize, params=self.parameters(client_id, **overrides)
        )
        assert first.status_code == 200, first.text
        return self.http.post(
            self.oauth.paths.authorize,
            data={"consent_token": first.json()["consent_token"], "decision": decision},
        )

    def code(self, client_id, **overrides):
        result = self.authorize(client_id, **overrides)
        assert result.status_code == 302, result.text
        return parse_qs(urlsplit(result.headers["location"]).query)["code"][0]

    def exchange(self, client_id, code, **overrides):
        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": VERIFIER,
            "resource": A,
        }
        data.update(overrides)
        return self.http.post(self.oauth.paths.token, data=data)

    def tokens(self, client_id=None, **overrides):
        client_id = client_id or self.client()
        result = self.exchange(
            client_id, self.code(client_id, **overrides), resource=overrides.get("resource", A)
        )
        assert result.status_code == 200, result.text
        return client_id, result.json()

    def refresh(self, client_id, refresh_token, **overrides):
        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "resource": A,
        }
        data.update(overrides)
        return self.http.post(self.oauth.paths.token, data=data)

    def revoke(self, client_id, token, **overrides):
        return self.http.post(
            self.oauth.paths.revoke, data={"client_id": client_id, "token": token, **overrides}
        )


@pytest.fixture
def system():
    return System()
