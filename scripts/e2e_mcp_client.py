"""Official SDK client process; knows nothing about the authorization library."""

import os
import ssl

import httpx2 as httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def call_tool(issuer, token):
    ca = os.environ.get("E2E_CA")
    context = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    async with httpx.AsyncClient(
        verify=context, trust_env=False, headers={"Authorization": "Bearer " + token}
    ) as client:
        metadata = await client.get(issuer + "/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == issuer + "/mcp"
        assert metadata.json()["authorization_servers"] == [issuer]
        async with (
            streamable_http_client(issuer + "/mcp", http_client=client) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool("echo", {"message": "interop-ok"})
            assert not result.is_error
            assert any(getattr(item, "text", "") == "interop-ok" for item in result.content)
        rejected = await client.post(
            issuer + "/other-mcp/",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert rejected.status_code == 401
    async with httpx.AsyncClient(verify=context, trust_env=False) as anonymous:
        challenge = await anonymous.post(issuer + "/mcp", json={})
        assert challenge.status_code == 401
        assert "resource_metadata=" in challenge.headers["www-authenticate"]
