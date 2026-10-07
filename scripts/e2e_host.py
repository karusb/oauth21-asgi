"""Ephemeral installed-wheel host. All counters/routes are test instrumentation."""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from fastapi import Request
from fastapi_app import create_app
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

import oauth21_asgi
from oauth21_asgi import ClientMetadataDocuments, ClientMode, MetadataNetworkPolicy
from oauth21_asgi.metadata_network import AiohttpMetadataFetcher

assert "/src/" not in str(Path(oauth21_asgi.__file__).resolve()).replace("\\", "/")
issuer = os.environ["E2E_ISSUER"]
mode = ClientMode(os.environ["E2E_MODE"])
counts = {"registration": 0, "fetch": 0, "document": 0}
client_url = issuer + "/client.json"
policy = MetadataNetworkPolicy(allow_loopback=True)


class CountedFetcher:
    def __init__(self):
        ca = os.environ.get("E2E_CA")
        context = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.inner = AiohttpMetadataFetcher(policy, ssl_context=context)

    async def fetch(self, client_id, *, max_bytes, timeout):
        counts["fetch"] += 1
        return await self.inner.fetch(client_id, max_bytes=max_bytes, timeout=timeout)


app = create_app(
    issuer=issuer,
    client_mode=mode,
    resources={issuer + "/api", issuer + "/other", issuer + "/mcp", issuer + "/other-mcp"},
    cimd=ClientMetadataDocuments(fetcher=CountedFetcher(), network=policy)
    if mode != ClientMode.DCR_ONLY
    else None,
)
oauth = app.state.oauth


def registration(request):
    counts["registration"] += 1


oauth.registration_hook = registration


@app.get("/client.json")
async def metadata_document():
    counts["document"] += 1
    return JSONResponse(
        {
            "client_id": client_url,
            "client_name": "TCP client",
            "redirect_uris": ["https://client.example.test/callback"],
            "scope": "read write",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "token_endpoint_auth_method": "private_key_jwt",
        },
        headers={"Cache-Control": "max-age=60"},
    )


@app.get("/invalid.json")
async def invalid_document():
    counts["document"] += 1
    return JSONResponse({"client_id": "https://wrong.example.test/client.json"})


@app.get("/stats")
async def stats():
    # Fixture only; never mount operational storage inspection in production.
    return {
        **counts,
        "clients": len(oauth.engine.transaction(lambda: oauth.engine.uow.get().clients())),
    }


@app.get("/api")
async def resource(request: Request):
    credential = request.headers.get("authorization", "").removeprefix("Bearer ")
    principal = await run_in_threadpool(
        oauth.validate_access_token,
        credential,
        resource=issuer + ("/mcp" if os.environ.get("E2E_MCP") == "1" else "/api"),
        scopes={"read"},
    )
    return JSONResponse({"allowed": bool(principal)}, status_code=200 if principal else 401)


@app.get("/other")
async def other_resource(request: Request):
    credential = request.headers.get("authorization", "").removeprefix("Bearer ")
    principal = await run_in_threadpool(
        oauth.validate_access_token, credential, resource=issuer + "/other", scopes={"read"}
    )
    return JSONResponse({"allowed": bool(principal)}, status_code=200 if principal else 401)


if os.environ.get("E2E_MCP") == "1":
    from e2e_mcp import mount_mcp

    mount_mcp(app, oauth, issuer)
