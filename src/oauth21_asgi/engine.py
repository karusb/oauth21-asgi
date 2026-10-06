from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import replace
from typing import Any, TypeVar

from authlib.oauth2.rfc6749 import AuthorizationServer as AuthlibServer
from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, InvalidScopeError
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7591 import ClientMetadataClaims, ClientRegistrationEndpoint
from authlib.oauth2.rfc7591.errors import InvalidClientMetadataError
from joserfc.errors import InvalidClaimError

from .extensions import ExactIssuer, MandatoryS256, ResourceBinding, current_subject
from .http import FormRequest, OAuthResponse, RegistrationRequest, response
from .interfaces import Identity, RedirectPolicy, Storage, UnitOfWork
from .models import Client, Code, Grant, Limits
from .storage import digest

T = TypeVar("T")


class NoCredentialDebug(logging.Filter):
    """Authlib 1.8 grant DEBUG messages contain complete issued token dictionaries."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


class PublicCodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def generate_authorization_code(self) -> str:
        return secrets.token_urlsafe(32)

    def save_authorization_code(self, code: str, request: Any) -> None:
        engine = self.server
        if len(engine.uow.get().codes()) >= engine.limits.authorization_codes:
            raise InvalidRequestError(
                "Authorization capacity reached. Try again later.", redirect_uri=self.redirect_uri
            )
        engine.uow.get().put_code(
            Code(
                digest(code),
                request.client.client_id,
                request.user,
                self.redirect_uri,
                request.scope,
                engine.resource_binding.resource(request),
                request.payload.data["code_challenge"],
                engine.clock() + engine.limits.code_ttl,
            )
        )

    def query_authorization_code(self, code: str, client: Client) -> Code | None:
        value = self.server.uow.get().get_code(digest(code))
        if value and value.client_id == client.client_id and value.expires_at > self.server.clock():
            return value
        return None

    def delete_authorization_code(self, authorization_code: Code) -> None:
        self.server.uow.get().delete_code(authorization_code.digest)

    def authenticate_user(self, authorization_code: Code) -> Any:
        return current_subject(self.server.identity, authorization_code.subject)


class PublicRefreshGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def validate_token_request(self) -> None:
        super().validate_token_request()
        self.server.validate_requested_scope(self.request.payload.scope)

    def authenticate_refresh_token(self, refresh_token: str) -> Grant | None:
        engine = self.server
        fingerprint = digest(refresh_token)
        grant = engine.uow.get().find_token(fingerprint, "refresh_token")
        if not grant or not grant.check_client(self.request.client):
            return None
        # Check binding BEFORE replay revocation: a different client/resource cannot poison a family.
        engine.resource_binding.resource(self.request, grant.resource)
        if grant.revoked or grant.expires_at <= engine.clock():
            return None
        if any(secrets.compare_digest(fingerprint, old) for old in grant.used_refresh):
            engine.uow.get().put_grant(replace(grant, revoked=True))
            return None
        if not secrets.compare_digest(fingerprint, grant.refresh_digest or ""):
            return None
        if len(grant.used_refresh) >= engine.limits.refresh_rotations:
            engine.uow.get().put_grant(replace(grant, revoked=True))
            return None
        return grant

    def authenticate_user(self, refresh_token: Grant) -> Any:
        return current_subject(self.server.identity, refresh_token.subject)

    def issue_token(self, user: Any, refresh_token: Grant) -> dict[str, Any]:
        token = super().issue_token(user, refresh_token)
        remaining = int(refresh_token.expires_at - self.server.clock())
        if remaining < 1:
            raise InvalidGrantError()
        token["expires_in"] = min(token["expires_in"], remaining)
        return token

    def revoke_old_credential(self, refresh_token: Grant) -> None:
        # save_token atomically installs the successor and its replay tombstone.
        pass


class PublicRevocation(RevocationEndpoint):
    CLIENT_AUTH_METHODS = ["none"]

    def query_token(self, token: str, token_type_hint: str | None) -> Grant | None:
        fingerprint = digest(token)
        kinds = [token_type_hint] if token_type_hint else []
        kinds += [k for k in ("access_token", "refresh_token") if k not in kinds]
        for kind in kinds:
            grant = self.server.uow.get().find_token(fingerprint, kind)
            if grant:
                return grant
        return None

    def revoke_token(self, token: Grant, request: Any) -> None:
        self.server.uow.get().put_grant(replace(token, revoked=True))


class OpenRegistration(ClientRegistrationEndpoint):
    def authenticate_token(self, request: Any) -> bool:
        return True

    def get_server_metadata(self) -> dict[str, Any]:
        return self.server.metadata

    def generate_client_info(self, request: Any) -> dict[str, Any]:
        return {
            "client_id": secrets.token_urlsafe(24),
            "client_id_issued_at": int(self.server.clock()),
        }

    def save_client(
        self, client_info: dict[str, Any], client_metadata: dict[str, Any], request: Any
    ) -> Client:
        engine = self.server
        if len(engine.uow.get().clients()) >= engine.limits.registered_clients:
            raise InvalidClientMetadataError("Registration capacity reached.")
        client = Client(
            client_info["client_id"],
            tuple(client_metadata["redirect_uris"]),
            client_metadata["scope"],
            tuple(client_metadata["grant_types"]),
            tuple(client_metadata["response_types"]),
            client_metadata.get("client_name", ""),
            engine.clock(),
        )
        engine.uow.get().put_client(client)
        return client


class Engine(AuthlibServer):
    def __init__(
        self,
        *,
        identity: Identity,
        storage: Storage,
        limits: Limits,
        clock: Callable[[], float],
        metadata: dict[str, Any],
        resources: frozenset[str],
        redirect_policy: RedirectPolicy,
    ) -> None:
        super().__init__(scopes_supported=metadata["scopes_supported"])
        self.identity, self.storage, self.limits, self.clock = identity, storage, limits, clock
        self.metadata = metadata
        self.uow: ContextVar[UnitOfWork] = ContextVar("oauth21_unit_of_work")
        self.resource_binding = ResourceBinding(resources)
        self.issuer_parameter = ExactIssuer(metadata["issuer"])
        for module in ("authorization_code", "refresh_token"):
            logger = logging.getLogger("authlib.oauth2.rfc6749.grants." + module)
            if not any(isinstance(f, NoCredentialDebug) for f in logger.filters):
                logger.addFilter(NoCredentialDebug())
        self.register_grant(PublicCodeGrant, [MandatoryS256(), self.resource_binding])
        self.register_grant(PublicRefreshGrant)
        self.register_extension(self.issuer_parameter)
        self.register_endpoint(PublicRevocation)
        profile_scopes = " ".join(metadata["scopes_supported"])

        class ProfileMetadata(ClientMetadataClaims):
            def validate(self, now: Any = None, leeway: int = 0) -> None:
                self.setdefault("token_endpoint_auth_method", "none")
                self.setdefault("grant_types", ["authorization_code", "refresh_token"])
                self.setdefault("response_types", ["code"])
                self.setdefault("scope", profile_scopes)
                for name in ("redirect_uris", "grant_types", "response_types", "contacts"):
                    if name in self and (
                        not isinstance(self[name], list)
                        or not all(isinstance(v, str) for v in self[name])
                        or len(set(self[name])) != len(self[name])
                    ):
                        raise InvalidClaimError(name)
                for name in self.REGISTERED_CLAIMS:
                    if name not in (
                        "redirect_uris",
                        "grant_types",
                        "response_types",
                        "contacts",
                        "jwks",
                    ):
                        if name in self and not isinstance(self[name], str):
                            raise InvalidClaimError(name)
                uris = self.get("redirect_uris", [])
                if (
                    not uris
                    or len(uris) > limits.redirects_per_client
                    or len(set(uris)) != len(uris)
                    or any(not redirect_policy(uri) for uri in uris)
                ):
                    raise InvalidClaimError("redirect_uris")
                if any(name in self for name in ("jwks", "jwks_uri", "client_secret")):
                    raise InvalidClaimError("token_endpoint_auth_method")
                scope = self["scope"]
                if (
                    not scope
                    or scope != " ".join(scope.split())
                    or len(scope.split()) != len(set(scope.split()))
                ):
                    raise InvalidClaimError("scope")
                super().validate(now, leeway)
                if "authorization_code" not in self["grant_types"] or self["response_types"] != [
                    "code"
                ]:
                    raise InvalidClaimError("grant_types")

        self.register_endpoint(OpenRegistration(self, claims_classes=[ProfileMetadata]))
        self.register_token_generator(
            "default",
            BearerTokenGenerator(
                access_token_generator=lambda **kwargs: secrets.token_urlsafe(32),
                refresh_token_generator=lambda **kwargs: secrets.token_urlsafe(32),
                expires_generator=min(limits.access_ttl, limits.grant_ttl),
            ),
        )

    def transaction(self, callback: Callable[[], T]) -> T:
        with self.storage.transaction() as unit:
            marker = self.uow.set(unit)
            try:
                unit.prune(self.clock(), self.limits.client_ttl)
                return callback()
            finally:
                self.uow.reset(marker)

    def query_client(self, client_id: str) -> Client | None:
        return self.uow.get().get_client(client_id)

    def create_oauth2_request(self, request: FormRequest) -> FormRequest:
        return request

    def create_json_request(self, request: RegistrationRequest) -> RegistrationRequest:
        return request

    def handle_response(
        self, status: int, body: Any, headers: list[tuple[str, str]]
    ) -> OAuthResponse:
        return response(status, body, headers)

    def send_signal(self, name: str, *args: Any, **kwargs: Any) -> None:
        pass

    def validate_requested_scope(self, scope: str | None) -> None:
        super().validate_requested_scope(scope)
        if scope is not None and (
            not scope
            or scope != " ".join(scope.split())
            or len(scope.split()) != len(set(scope.split()))
        ):
            raise InvalidScopeError()

    def save_token(self, token: dict[str, Any], request: Any) -> None:
        unit, now = self.uow.get(), self.clock()
        old: Grant | None = request.refresh_token
        if old:
            if old.refresh_digest is None:
                raise InvalidGrantError()
            grant = replace(
                old,
                scope=token.get("scope", ""),
                access_digest=digest(token["access_token"]),
                access_expires_at=now + token["expires_in"],
                refresh_digest=digest(token["refresh_token"]),
                used_refresh=(*old.used_refresh, old.refresh_digest),
            )
        else:
            if len(unit.grants()) >= self.limits.token_families:
                raise InvalidRequestError("Token capacity reached. Try again later.")
            code = request.authorization_code
            grant = Grant(
                secrets.token_urlsafe(24),
                request.client.client_id,
                request.user,
                code.resource,
                token.get("scope", ""),
                now,
                now + self.limits.grant_ttl,
                now + token["expires_in"],
                digest(token["access_token"]),
                digest(token["refresh_token"]) if "refresh_token" in token else None,
            )
        unit.put_grant(grant)
