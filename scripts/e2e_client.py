"""Independent OAuth client process: no oauth21_asgi/Authlib imports."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import secrets
import ssl
from contextlib import closing
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx

issuer = os.environ["E2E_ISSUER"]
mode = os.environ["E2E_MODE"]
ca = os.environ.get("E2E_CA")
verify = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
http = httpx.Client(
    base_url=issuer, verify=verify, trust_env=False, follow_redirects=False, timeout=10
)
metadata = http.get("/.well-known/oauth-authorization-server").json()
assert metadata["issuer"] == issuer
assert ("registration_endpoint" in metadata) == (mode != "cimd")
assert metadata.get("client_id_metadata_document_supported", False) == (mode != "dcr")
callback = "https://client.example.test/callback"
client_url = issuer + "/client.json"
resource = issuer + ("/mcp" if os.environ.get("E2E_MCP") == "1" else "/api")


async def mcp_call(access_token):
    from e2e_mcp_client import call_tool

    await call_tool(issuer, access_token)


def flow(client_id):
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": client_id,
        "redirect_uri": callback,
        "response_type": "code",
        "scope": "read",
        "resource": resource,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    first = http.get("/oauth/authorize", params=params)
    if first.status_code == 303:
        login = http.get("/login")
        assert http.post("/login", data={"csrf": "\u00e9"}).status_code == 400
        login = http.get("/login")
        csrf = login.text.split('name="csrf" value="')[1].split('"')[0]
        assert http.post("/login", data={"csrf": csrf}).status_code == 303
        first = http.get("/oauth/authorize", params=params)
    assert first.status_code == 200, first.text
    ticket = first.text.split('name="consent_token" value="')[1].split('"')[0]
    authorized = http.post("/oauth/authorize", data={"consent_token": ticket, "decision": "allow"})
    assert authorized.status_code == 302, authorized.text
    values = parse_qs(urlsplit(authorized.headers["location"]).query)
    assert values["state"] == [state]
    assert values["iss"] == [issuer]
    exchange = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": values["code"][0],
        "code_verifier": verifier,
        "redirect_uri": callback,
        "resource": resource,
    }
    assert (
        http.post("/oauth/token", data={**exchange, "resource": resource + "/wrong"}).status_code
        == 400
    )
    token_reply = http.post("/oauth/token", data=exchange)
    assert token_reply.status_code == 200, token_reply.text
    token = token_reply.json()
    assert http.post("/oauth/token", data=exchange).status_code == 400
    headers = {"Authorization": "Bearer " + token["access_token"]}
    assert http.get("/api", headers=headers).status_code == 200
    assert http.get("/other", headers=headers).status_code == 401
    if os.environ.get("E2E_MCP") == "1":
        asyncio.run(mcp_call(token["access_token"]))
    refresh = http.post(
        "/oauth/token",
        data={
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": token["refresh_token"],
            "resource": resource,
        },
    )
    assert refresh.status_code == 200, refresh.text
    successor = refresh.json()
    assert http.get("/api", headers=headers).status_code == 401
    assert (
        http.get(
            "/api", headers={"Authorization": "Bearer " + successor["access_token"]}
        ).status_code
        == 200
    )
    assert (
        http.post(
            "/oauth/revoke", data={"client_id": client_id, "token": successor["refresh_token"]}
        ).status_code
        == 200
    )
    assert (
        http.get(
            "/api", headers={"Authorization": "Bearer " + successor["access_token"]}
        ).status_code
        == 401
    )


with closing(http):
    if mode != "dcr":
        before = http.get("/stats").json()
        flow(client_url)
        after = http.get("/stats").json()
        assert after["registration"] == before["registration"] == 0
        assert after["clients"] == 0
        assert after["fetch"] == after["document"] == 1
        rejection = http.get(
            "/oauth/authorize",
            params={"client_id": issuer + "/invalid.json", "response_type": "code"},
        )
        assert rejection.status_code == 400
        assert http.get("/stats").json()["registration"] == 0
    if mode != "cimd":
        before = http.get("/stats").json()
        registered = http.post(
            "/oauth/register",
            json={
                "redirect_uris": [callback],
                "scope": "read write",
                "token_endpoint_auth_method": "none",
            },
        )
        assert registered.status_code == 201, registered.text
        flow(registered.json()["client_id"])
        assert http.get("/stats").json()["fetch"] == before["fetch"]
    else:
        assert http.post("/oauth/register", json={}).status_code == 404
        assert (
            http.post(
                "/oauth/token",
                data={
                    "client_id": "opaque",
                    "grant_type": "refresh_token",
                    "refresh_token": "invalid",
                    "resource": resource,
                },
            ).status_code
            == 400
        )
    if mode == "dcr":
        assert (
            http.get(
                "/oauth/authorize", params={"client_id": client_url, "response_type": "code"}
            ).status_code
            == 400
        )
        assert http.get("/stats").json()["fetch"] == 0
    if os.environ.get("E2E_INTERNAL"):
        # Direct traffic uses an explicitly untrusted source IP. The proxy's
        # trusted loopback connection is the only source allowed to set scheme.
        with httpx.Client(
            transport=httpx.HTTPTransport(local_address="127.0.0.2"), trust_env=False
        ) as direct:
            origin = urlsplit(issuer).netloc
            rejected = direct.get(
                os.environ["E2E_INTERNAL"] + "/.well-known/oauth-authorization-server",
                headers={
                    "Host": origin,
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-For": "127.0.0.1",
                },
            )
            assert rejected.status_code == 400
print(
    f"Installed wheel E2E passed: {mode}, {'HTTPS/proxy' if ca else 'TCP'}, {'MCP interoperability' if os.environ.get('E2E_MCP') else 'OAuth lifecycle'}"
)
