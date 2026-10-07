"""Development-only host identity/consent example. Never deploy the demo login."""

from __future__ import annotations

import html
import os
import secrets
from collections.abc import Iterable
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, RedirectResponse

from oauth21_asgi import (
    AuthorizationContext,
    AuthorizationServer,
    ClientMetadataDocuments,
    ClientMode,
    Decision,
    ExactRedirectPolicy,
    MemoryStorage,
    Subject,
)


class DemoIdentity:
    def __init__(self) -> None:
        self.subject = Subject("demo-account", "demo-incarnation:1")

    async def authenticate(self, request: Request):
        if request.session.get("subject") == self.subject.subject_id:
            return self.subject
        request.session["return_to"] = str(request.url)
        return RedirectResponse("/login", status_code=303)

    def get_subject(self, subject_id: str) -> Subject | None:
        return self.subject if subject_id == self.subject.subject_id else None


class DemoConsent:
    async def render(
        self, request: Request, context: AuthorizationContext, consent_token: str
    ) -> HTMLResponse:
        # Registered branding is untrusted. Escape all displayed values; never fetch logos.
        text = f"{context.client_name} ({context.client_origin or 'registered client'}) requests {', '.join(context.scopes)} for {context.resource}"
        return HTMLResponse(
            "<h1>Allow application access?</h1><p>" + html.escape(text) + "</p>"
            '<form method="post" action="/oauth/authorize">'
            '<input type="hidden" name="consent_token" value="' + html.escape(consent_token) + '">'
            '<button name="decision" value="allow">Allow</button>'
            '<button name="decision" value="deny">Deny</button></form>'
        )

    async def decide(self, request: Request, context: AuthorizationContext) -> Decision:
        form = await request.form()
        return Decision.ALLOW if form.get("decision") == "allow" else Decision.DENY


def create_app(
    *,
    issuer: str = "https://video.example.test/",
    callback: str = "https://client.example.test/callback",
    client_mode: ClientMode = ClientMode.DCR_ONLY,
    cimd: ClientMetadataDocuments | None = None,
    resources: Iterable[str] | None = None,
) -> FastAPI:
    """Demo host only. The default HTTPS issuer also supports in-process TestClient tests."""
    app = FastAPI()
    identity = DemoIdentity()
    # Ephemeral key is intentional for a local example. A real host owns durable login sessions.
    app.add_middleware(
        SessionMiddleware,
        secret_key=secrets.token_urlsafe(32),
        https_only=issuer.startswith("https:"),
        same_site="lax",
    )
    oauth = AuthorizationServer(
        issuer=issuer,
        scopes={"read", "write"},
        resources=resources if resources is not None else {issuer.rstrip("/") + "/api"},
        storage=MemoryStorage(),
        identity=identity,
        consent=DemoConsent(),
        redirect_policy=ExactRedirectPolicy({callback}),
        client_mode=client_mode,
        cimd=cimd,
        allow_loopback=urlsplit(issuer).hostname in {"localhost", "127.0.0.1", "::1"},
    )
    oauth.mount(app)
    app.state.oauth = oauth

    @app.get("/login")
    async def login(request: Request):
        challenge = secrets.token_urlsafe(32)
        request.session["login_csrf"] = challenge
        return HTMLResponse(
            "<h1>Development identity</h1><p>This is not production authentication.</p>"
            '<form method="post"><input type="hidden" name="csrf" value="' + challenge + '">'
            "<button>Use demo account</button></form>"
        )

    @app.post("/login")
    async def complete_login(request: Request):
        form = await request.form()
        csrf = request.session.pop("login_csrf", "")
        submitted = str(form.get("csrf", ""))
        if not csrf or not submitted.isascii() or not secrets.compare_digest(submitted, csrf):
            return HTMLResponse("Invalid login request", status_code=400)
        request.session["subject"] = identity.subject.subject_id
        return RedirectResponse(request.session.pop("return_to", "/"), status_code=303)

    return app


# Explicit local loopback development entry point: uvicorn examples.fastapi_app:app
app = create_app(issuer=os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:8000"))
