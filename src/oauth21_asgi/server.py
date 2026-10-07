from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Callable, Iterable
from contextvars import Token
from dataclasses import replace
from typing import Any, TypeVar, cast
from urllib.parse import urlsplit, urlunsplit

from authlib.oauth2.rfc6749 import InvalidClientError, InvalidRequestError, OAuth2Error
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from .cimd import ClientMetadataDocuments, strict_object
from .engine import Engine
from .extensions import current_subject
from .http import FormRequest, OAuthResponse, RegistrationRequest, response
from .interfaces import Consent, Identity, RedirectPolicy, RegistrationHook, Storage
from .models import (
    AuthorizationContext,
    Client,
    ClientMode,
    Decision,
    Limits,
    Paths,
    PendingConsent,
    Principal,
    Subject,
)
from .policies import safe_uri
from .storage import digest

T = TypeVar("T")
logger = logging.getLogger("oauth21_asgi.errors")


class AuthorizationServer:
    """Embed the Authlib public-client authorization server in a Starlette/FastAPI app."""

    def __init__(
        self,
        *,
        issuer: str,
        scopes: Iterable[str],
        resources: Iterable[str],
        storage: Storage,
        identity: Identity,
        consent: Consent,
        redirect_policy: RedirectPolicy,
        limits: Limits | None = None,
        paths: Paths | None = None,
        registration_hook: RegistrationHook | None = None,
        clock: Callable[[], float] = time.time,
        allow_loopback: bool = False,
        client_mode: ClientMode = ClientMode.DCR_ONLY,
        cimd: ClientMetadataDocuments | None = None,
    ) -> None:
        limits, paths = limits or Limits(), paths or Paths()
        if not safe_uri(issuer, allow_loopback=allow_loopback, issuer=True):
            raise ValueError("Issuer requires HTTPS; development loopback requires explicit opt-in")
        self.issuer, self.limits, self.paths, self.clock = issuer, limits, paths, clock
        self.identity, self.consent, self.registration_hook = identity, consent, registration_hook
        try:
            self.client_mode = ClientMode(client_mode)
        except ValueError as exc:
            raise ValueError("Unknown client mode") from exc
        if (self.client_mode == ClientMode.DCR_ONLY) != (cimd is None):
            raise ValueError("CIMD configuration must match the explicit client mode")
        self.cimd = cimd
        if cimd is not None:
            cimd.bind(self, issuer=issuer, allow_loopback=allow_loopback)
        self.resources = frozenset(resources)
        scope_set = frozenset(scopes)
        if not self.resources or any(
            not safe_uri(r, allow_loopback=allow_loopback) for r in self.resources
        ):
            raise ValueError("Configure at least one safe, exact resource URI")
        if not scope_set or any(
            not s
            or s in {"openid", "profile", "email"}
            or any(ord(c) < 33 or ord(c) > 126 or c in '"' or c == chr(92) for c in s)
            for s in scope_set
        ):
            raise ValueError("Configure non-OIDC OAuth scope tokens")
        parts = urlsplit(issuer)
        self.origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        self.secure_cookie = parts.scheme == "https"
        self.metadata = AuthorizationServerMetadata(
            {
                "issuer": issuer,
                "authorization_endpoint": self.origin + paths.authorize,
                "token_endpoint": self.origin + paths.token,
                "registration_endpoint": self.origin + paths.register,
                "revocation_endpoint": self.origin + paths.revoke,
                "scopes_supported": sorted(scope_set),
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "revocation_endpoint_auth_methods_supported": ["none"],
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": True,
            }
        )
        if self.client_mode == ClientMode.CIMD_ONLY:
            self.metadata.pop("registration_endpoint", None)
        if self.client_mode != ClientMode.DCR_ONLY:
            self.metadata["client_id_metadata_document_supported"] = True
        self.metadata.validate()
        self.engine = Engine(
            identity=identity,
            storage=storage,
            limits=limits,
            clock=clock,
            metadata=self.metadata,
            resources=self.resources,
            redirect_policy=redirect_policy,
            client_mode=self.client_mode,
        )
        self.discovery_path = paths.metadata
        if paths.metadata == Paths().metadata and parts.path not in ("", "/"):
            self.discovery_path += parts.path.rstrip("/")

    def mount(self, app: Starlette) -> None:
        routes = [
            Route(self.discovery_path, self.discovery, methods=["GET"]),
            Route(self.paths.authorize, self.authorize, methods=["GET", "POST"]),
            Route(self.paths.token, self.token, methods=["POST"]),
            Route(self.paths.revoke, self.revoke, methods=["POST"]),
        ]
        if self.client_mode != ClientMode.CIMD_ONLY:
            routes.append(Route(self.paths.register, self.register, methods=["POST"]))
        if len({r.path for r in routes}) != len(routes):
            raise ValueError("OAuth discovery path collides with an endpoint")
        existing = {getattr(r, "path", None) for r in app.router.routes}
        if any(r.path in existing for r in routes):
            raise ValueError("OAuth route collides with an existing host route")
        app.router.routes.extend(routes)

    def check_transport(self, request: Request) -> None:
        if len(request.scope.get("query_string", b"")) > self.limits.query_bytes:
            raise InvalidRequestError("Query too large.", status_code=413)
        parts = urlsplit(str(request.url))
        if urlunsplit((parts.scheme, parts.netloc, "", "", "")) != self.origin:
            raise InvalidRequestError("Request origin does not match the configured issuer.")
        if {
            "access_token",
            "refresh_token",
            "client_secret",
            "code_verifier",
            "password",
            "code",
        }.intersection(request.query_params):
            raise InvalidRequestError("Credentials must not appear in the request URL.")

    async def body(self, request: Request) -> bytes:
        parts: list[bytes] = []
        length = 0
        try:
            async with asyncio.timeout(self.limits.body_timeout):
                async for part in request.stream():
                    length += len(part)
                    if length > self.limits.body_bytes:
                        raise InvalidRequestError("Body too large.", status_code=413)
                    parts.append(part)
        except TimeoutError as error:
            raise InvalidRequestError("Request body timed out.", status_code=408) from error
        return b"".join(parts)

    async def form(self, request: Request) -> tuple[Request, list[tuple[str, str]]]:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
        if content_type != "application/x-www-form-urlencoded":
            raise InvalidRequestError("Use application/x-www-form-urlencoded.", status_code=415)
        raw = await self.body(request)
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InvalidRequestError("Form must be UTF-8.") from error

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": raw, "more_body": False}

        prepared = Request(request.scope, receive)
        values = await prepared.form()
        pairs = [(k, str(v)) for k, v in values.multi_items()]
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise InvalidRequestError("Repeated form parameters are not supported.")
        if request.query_params:
            raise InvalidRequestError("POST OAuth credentials must be in the form body.")
        return prepared, pairs

    def error(self, error: OAuth2Error, *, callback: bool = False) -> OAuthResponse:
        result = self.engine.handle_error_response(None, error)
        if callback:
            self.engine.issuer_parameter.add_issuer_parameter(self.engine, result)
        return cast(OAuthResponse, result)

    async def invoke(self, callback: Callable[[], T]) -> T:
        return await run_in_threadpool(self.engine.transaction, callback)

    async def resolve_client(self, pairs: Iterable[tuple[str, str]]) -> Token[Client | None]:
        values = [value for key, value in pairs if key == "client_id"]
        if len(values) > 1:
            raise InvalidRequestError("Repeated client IDs are not supported.")
        client: Client | None = None
        if values and self.cimd is not None and ":" in values[0]:
            client = await self.cimd.resolve(values[0], self.engine.cimd_client)
        return self.engine.resolved_client.set(client)

    def unavailable(self, endpoint: str, error: Exception) -> OAuthResponse:
        # No exception text/traceback, URL, request headers, cookies or bodies.
        # The locally generated ID is safe even when client correlation headers
        # deliberately contain credential values.
        incident = secrets.token_hex(8)
        logger.error(
            "OAuth operation failed",
            extra={
                "endpoint": endpoint,
                "operation": "oauth_request",
                "exception_class": type(error).__name__,
                "incident_id": incident,
            },
        )
        result = response(503, {"error": "temporarily_unavailable"}, [])
        result.headers["X-OAuth-Incident-ID"] = incident
        return result

    async def discovery(self, request: Request) -> Response:
        try:
            self.check_transport(request)
            return response(200, dict(self.metadata), [])
        except OAuth2Error as error:
            return self.error(error)
        except Exception as error:
            return self.unavailable("discovery", error)

    async def register(self, request: Request) -> Response:
        try:
            self.check_transport(request)
            if request.query_params:
                raise InvalidRequestError("Registration uses a JSON body.")
            if (
                request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise InvalidRequestError("Use application/json.", status_code=415)
            raw = await self.body(request)

            try:
                data = strict_object(raw)
            except (UnicodeDecodeError, ValueError, RecursionError) as error:
                raise InvalidRequestError("A valid JSON object is required.") from error
            if self.registration_hook:
                await run_in_threadpool(self.registration_hook, request)
            adapted = RegistrationRequest(str(request.url), data, request.headers)
            return await self.invoke(
                lambda: self.engine.create_endpoint_response("client_registration", adapted)
            )
        except OAuth2Error as error:
            return self.error(error)
        except Exception as error:
            return self.unavailable("register", error)

    async def token(self, request: Request) -> Response:
        return await self.credential_endpoint(request, None)

    async def revoke(self, request: Request) -> Response:
        return await self.credential_endpoint(request, "revocation")

    async def credential_endpoint(self, request: Request, endpoint: str | None) -> Response:
        marker: Token[Client | None] | None = None
        try:
            self.check_transport(request)
            prepared, pairs = await self.form(request)
            if "authorization" in request.headers or "client_secret" in dict(pairs):
                raise InvalidClientError("Only public-client authentication is supported.")
            adapted = FormRequest("POST", str(request.url), pairs, prepared.headers)
            marker = await self.resolve_client(pairs)
            callback = (
                (lambda: self.engine.create_endpoint_response(endpoint, adapted))
                if endpoint
                else (lambda: self.engine.create_token_response(adapted))
            )
            return await self.invoke(callback)
        except OAuth2Error as error:
            return self.error(error)
        except Exception as error:
            return self.unavailable(endpoint or "token", error)
        finally:
            if marker is not None:
                self.engine.resolved_client.reset(marker)

    def context(self, grant: Any, subject: Subject) -> AuthorizationContext:
        req = grant.request
        return AuthorizationContext(
            req.client.client_id,
            req.client.client_name or req.client.client_id,
            grant.redirect_uri,
            tuple(req.scope.split()),
            self.engine.resource_binding.resource(req),
            req.payload.state,
            subject,
            req.client.metadata_origin,
        )

    async def authorize(self, request: Request) -> Response:
        marker: Token[Client | None] | None = None
        try:
            self.check_transport(request)
            if request.method == "POST":
                return await self.confirm(request)
            adapted = FormRequest(
                "GET", str(request.url), request.query_params.multi_items(), request.headers
            )
            marker = await self.resolve_client(request.query_params.multi_items())

            def validate() -> Any:
                try:
                    return self.engine.get_consent_grant(adapted)
                except OAuth2Error as error:
                    return self.error(error, callback=True)

            grant = await self.invoke(validate)
            if isinstance(grant, Response):
                return grant
            subject = await self.identity.authenticate(request)
            if isinstance(subject, Response):
                return subject
            if not subject.active:
                raise InvalidRequestError("An active subject is required.")
            context = self.context(grant, subject)
            consent_token = secrets.token_urlsafe(32)
            parameters = dict(adapted.payload.data)
            # Bind the ticket to what was rendered, not mutable client defaults.
            parameters.update(redirect_uri=context.redirect_uri, scope=" ".join(context.scopes))

            def save() -> None:
                current_subject(self.identity, subject)
                unit = self.engine.uow.get()
                if len(unit.pending()) >= self.limits.pending_consents:
                    raise InvalidRequestError("Consent capacity reached.")
                unit.put_pending(
                    PendingConsent(
                        digest(consent_token),
                        subject,
                        parameters,
                        self.clock() + self.limits.consent_ttl,
                    )
                )
                self.engine.touch_client(context.client_id)

            await self.invoke(save)
            result = await self.consent.render(request, context, consent_token)
            result.set_cookie(
                "oauth21_consent",
                consent_token,
                max_age=self.limits.consent_ttl,
                path=self.paths.authorize,
                secure=self.secure_cookie,
                httponly=True,
                samesite="lax",
            )
            result.headers["Cache-Control"] = "no-store"
            result.headers["Referrer-Policy"] = "no-referrer"
            # Multiple enforced policies intersect; never discard the host's CSP.
            result.headers.append("Content-Security-Policy", "frame-ancestors 'none'")
            return result
        except OAuth2Error as error:
            return self.error(error, callback=True)
        except Exception as error:
            return self.unavailable("authorize", error)
        finally:
            if marker is not None:
                self.engine.resolved_client.reset(marker)

    async def confirm(self, request: Request) -> Response:
        prepared, pairs = await self.form(request)
        token = dict(pairs).get("consent_token", "")
        cookie = request.cookies.get("oauth21_consent", "")
        origin = request.headers.get("origin")
        if (
            not token
            or not cookie
            or len(token) != 43
            or len(cookie) != 43
            or not token.isascii()
            or not cookie.isascii()
            or not secrets.compare_digest(token, cookie)
            or (origin is not None and origin != self.origin)
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            raise InvalidRequestError("Invalid consent binding.")
        subject = await self.identity.authenticate(prepared)
        if isinstance(subject, Response):
            return subject

        def saved_parameters() -> dict[str, str]:
            pending = self.engine.uow.get().get_pending(digest(token))
            if not pending or pending.expires_at <= self.clock() or pending.subject != subject:
                raise InvalidRequestError("Consent expired or subject changed.")
            if not pending.parameters.get("scope") or not pending.parameters.get("redirect_uri"):
                raise InvalidRequestError("Restart authorization to confirm explicit consent.")
            return dict(pending.parameters)

        parameters = await self.invoke(saved_parameters)
        marker = await self.resolve_client(parameters.items())
        try:
            return await self.complete_consent(prepared, subject, token)
        finally:
            self.engine.resolved_client.reset(marker)

    async def complete_consent(self, prepared: Request, subject: Subject, token: str) -> Response:

        def load() -> Any:
            pending = self.engine.uow.get().get_pending(digest(token))
            if not pending or pending.expires_at <= self.clock() or pending.subject != subject:
                raise InvalidRequestError("Consent expired or subject changed.")
            current_subject(self.identity, subject)
            adapted = FormRequest(
                "GET",
                self.origin + self.paths.authorize,
                pending.parameters.items(),
                prepared.headers,
            )
            grant = self.engine.get_consent_grant(adapted, end_user=subject)
            return self.context(grant, subject)

        context = await self.invoke(load)
        decision = await self.consent.decide(prepared, context)
        if decision not in (Decision.ALLOW, Decision.DENY):
            raise InvalidRequestError("Explicit allow or deny is required.")

        def complete() -> Response:
            unit = self.engine.uow.get()
            pending = unit.get_pending(digest(token))
            if not pending or pending.expires_at <= self.clock() or pending.subject != subject:
                raise InvalidRequestError("Consent already consumed.")
            current_subject(self.identity, subject)
            adapted = FormRequest(
                "GET",
                self.origin + self.paths.authorize,
                pending.parameters.items(),
                prepared.headers,
            )
            try:
                grant = self.engine.get_consent_grant(adapted, end_user=subject)
            except OAuth2Error as error:
                return self.error(error, callback=True)
            unit.delete_pending(pending.digest)
            return cast(
                Response,
                self.engine.create_authorization_response(
                    adapted, grant_user=subject if decision == Decision.ALLOW else None, grant=grant
                ),
            )

        result = await self.invoke(complete)
        result.delete_cookie(
            "oauth21_consent",
            path=self.paths.authorize,
            secure=self.secure_cookie,
            httponly=True,
            samesite="lax",
        )
        return result

    def validate_access_token(
        self, token: str, *, resource: str, scopes: Iterable[str] = ()
    ) -> Principal | None:
        """Synchronous host Resource Server boundary; call in a worker for async hosts."""
        if len(token) > self.limits.body_bytes or resource not in self.resources:
            return None

        def validate() -> Principal | None:
            unit = self.engine.uow.get()
            grant = unit.find_token(digest(token), "access_token")
            if (
                not grant
                or grant.revoked
                or grant.client_source not in ("dcr", "cimd")
                or grant.resource != resource
                or grant.access_expires_at <= self.clock()
                or grant.expires_at <= self.clock()
                or not set(scopes).issubset(grant.scope.split())
                or not set(grant.scope.split()).issubset(self.metadata["scopes_supported"])
                or (self.client_mode == ClientMode.CIMD_ONLY and grant.client_source != "cimd")
                or (self.client_mode == ClientMode.DCR_ONLY and grant.client_source != "dcr")
                or (
                    grant.client_source == "dcr"
                    and self.engine.query_client(grant.client_id) is None
                )
            ):
                return None
            try:
                subject = current_subject(self.identity, grant.subject)
            except OAuth2Error:
                unit.put_grant(replace(grant, revoked=True))
                return None
            self.engine.touch_client(grant.client_id)
            return Principal(
                subject,
                grant.client_id,
                resource,
                frozenset(grant.scope.split()),
                grant.access_expires_at,
                grant.family_id,
            )

        return self.engine.transaction(validate)

    def revoke_subject(self, subject_id: str) -> int:
        def revoke() -> int:
            unit = self.engine.uow.get()
            matches = [
                g for g in unit.grants() if g.subject.subject_id == subject_id and not g.revoked
            ]
            for grant in matches:
                unit.put_grant(replace(grant, revoked=True))
            for code in unit.codes():
                if code.subject.subject_id == subject_id:
                    unit.delete_code(code.digest)
            for pending in unit.pending():
                if pending.subject.subject_id == subject_id:
                    unit.delete_pending(pending.digest)
            return len(matches)

        return self.engine.transaction(revoke)

    def prune(self) -> None:
        self.engine.transaction(lambda: None)
