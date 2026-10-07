"""Official MCP SDK 2.3.0 resource-server interop fixture; no runtime dependency."""

from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.concurrency import run_in_threadpool


def mount_mcp(app, oauth, issuer):
    class Verifier:
        def __init__(self, resource):
            self.resource = resource

        async def verify_token(self, token):
            principal = await run_in_threadpool(
                oauth.validate_access_token, token, resource=self.resource, scopes={"read"}
            )
            if not principal:
                return None
            return AccessToken(
                token=token,
                client_id=principal.client_id,
                scopes=list(principal.scopes),
                expires_at=int(principal.expires_at),
                resource=principal.resource,
                subject=principal.subject.subject_id,
            )

    def resource_app(resource, route):
        server = MCPServer(
            "Ephemeral interop",
            token_verifier=Verifier(resource),
            auth=AuthSettings(
                issuer_url=issuer,
                resource_server_url=resource,
                validate_token_resource=True,
                required_scopes=["read"],
            ),
        )

        @server.tool()
        def echo(message: str) -> str:
            return message

        return server.streamable_http_app(
            streamable_http_path=route,
            json_response=True,
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                allowed_hosts=[urlsplit(issuer).netloc], allowed_origins=[issuer]
            ),
        )

    main = resource_app(issuer + "/mcp", "/mcp")
    other = resource_app(issuer + "/other-mcp", "/")
    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with (
            original(application),
            main.router.lifespan_context(main),
            other.router.lifespan_context(other),
        ):
            yield

    app.router.lifespan_context = lifespan
    app.mount("/other-mcp", other)
    app.mount("/", main)
