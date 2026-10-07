from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import replace
from typing import Any, TypeVar, cast

from authlib.oauth2.rfc6749 import AuthorizationServer as AuthlibServer
from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, InvalidScopeError
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7591 import ClientMetadataClaims, ClientRegistrationEndpoint
from authlib.oauth2.rfc7591.errors import InvalidClientMetadataError
from joserfc.errors import InvalidClaimError

from .cimd import MetadataFetchError
from .extensions import ExactIssuer, MandatoryS256, ResourceBinding, current_subject
from .http import FormRequest, OAuthResponse, RegistrationRequest, response
from .interfaces import Identity, RedirectPolicy, Storage, UnitOfWork
from .models import Client, ClientMode, Code, Grant, Limits, Subject, TokenKind
from .storage import digest

T = TypeVar("T")


class NoCredentialDebug(logging.Filter):
    """Authlib 1.8 grant DEBUG messages contain complete issued token dictionaries."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Only the verified Authlib 1.8 token-dictionary event is suppressed.
        # Do not format the record: formatting would itself expose credentials.
        return record.msg != "Issue token %r to %r"


class PublicCodeGrant(AuthorizationCodeGrant):  # type: ignore[misc] # untyped Authlib base
    server: Engine
    request: FormRequest
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def generate_authorization_code(self) -> str:
        return secrets.token_urlsafe(32)

    def save_authorization_code(self, code: str, request: FormRequest) -> None:
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
                client_source="cimd" if request.client.metadata_origin is not None else "dcr",
            )
        )
        engine.touch_client(request.client.client_id)

    def query_authorization_code(self, code: str, client: Client) -> Code | None:
        value = self.server.uow.get().get_code(digest(code))
        if (
            value
            and value.client_id == client.client_id
            and value.expires_at > self.server.clock()
            and value.client_source == ("cimd" if client.metadata_origin is not None else "dcr")
        ):
            return value
        return None

    def delete_authorization_code(self, authorization_code: Code) -> None:
        self.server.uow.get().delete_code(authorization_code.digest)

    def authenticate_user(self, authorization_code: Code) -> Subject:
        return current_subject(self.server.identity, authorization_code.subject)


class PublicRefreshGrant(RefreshTokenGrant):  # type: ignore[misc] # untyped Authlib base
    server: Engine
    request: FormRequest
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def validate_token_request(self) -> None:
        super().validate_token_request()
        old = self.request.refresh_token
        if old is None:
            raise InvalidGrantError()
        scope = self.request.payload.data.get("scope", old.scope)
        self.server.validate_requested_scope(scope)
        if self.request.client.get_allowed_scope(scope) is None:
            raise InvalidScopeError()

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

    def authenticate_user(self, refresh_token: Grant) -> Subject:
        return current_subject(self.server.identity, refresh_token.subject)

    def issue_token(self, user: Subject, refresh_token: Grant) -> dict[str, Any]:
        token = cast(dict[str, Any], super().issue_token(user, refresh_token))
        remaining = int(refresh_token.expires_at - self.server.clock())
        if remaining < 1:
            raise InvalidGrantError()
        token["expires_in"] = min(token["expires_in"], remaining)
        return token

    def revoke_old_credential(self, refresh_token: Grant) -> None:
        # save_token atomically installs the successor and its replay tombstone.
        pass


class PublicRevocation(RevocationEndpoint):  # type: ignore[misc] # untyped Authlib base
    server: Engine
    CLIENT_AUTH_METHODS = ["none"]

    def query_token(self, token: str, token_type_hint: str | None) -> Grant | None:
        fingerprint = digest(token)
        kinds: list[TokenKind] = []
        if token_type_hint in ("access_token", "refresh_token"):
            kinds.append(cast(TokenKind, token_type_hint))
        kinds += [k for k in ("access_token", "refresh_token") if k not in kinds]
        for kind in kinds:
            grant = self.server.uow.get().find_token(fingerprint, kind)
            if grant:
                return grant
        return None

    def revoke_token(self, token: Grant, request: FormRequest) -> None:
        self.server.uow.get().put_grant(replace(token, revoked=True))
        self.server.touch_client(token.client_id)


class OpenRegistration(ClientRegistrationEndpoint):  # type: ignore[misc] # untyped Authlib base
    server: Engine

    def authenticate_token(self, request: RegistrationRequest) -> bool:
        return True

    def get_server_metadata(self) -> dict[str, Any]:
        return self.server.metadata

    def generate_client_info(self, request: RegistrationRequest) -> dict[str, Any]:
        return {
            "client_id": secrets.token_urlsafe(24),
            "client_id_issued_at": int(self.server.clock()),
        }

    def save_client(
        self,
        client_info: dict[str, Any],
        client_metadata: dict[str, Any],
        request: RegistrationRequest,
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


class Engine(AuthlibServer):  # type: ignore[misc] # untyped Authlib server base
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
        client_mode: ClientMode = ClientMode.DCR_ONLY,
    ) -> None:
        super().__init__(scopes_supported=metadata["scopes_supported"])
        self.identity, self.storage, self.limits, self.clock = identity, storage, limits, clock
        self.metadata = metadata
        self.client_mode = client_mode
        self.resolved_client: ContextVar[Client | None] = ContextVar("oauth21_client", default=None)
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

        class ProfileMetadata(ClientMetadataClaims):  # type: ignore[misc] # untyped Authlib claims
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

        if client_mode != ClientMode.CIMD_ONLY:
            self.register_endpoint(OpenRegistration(self, claims_classes=[ProfileMetadata]))
        self.client_claims = ProfileMetadata
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
        if self.client_mode != ClientMode.DCR_ONLY and ":" in client_id:
            client = self.resolved_client.get()
            return client if client and client.client_id == client_id else None
        if self.client_mode == ClientMode.CIMD_ONLY:
            return None
        return self.uow.get().get_client(client_id)

    def cimd_client(self, document: dict[str, Any]) -> Client:
        data = dict(document)
        if any(name in data for name in ("client_secret", "client_secret_expires_at")):
            raise MetadataFetchError("Shared credentials are not permitted")
        jwks = data.pop("jwks", None)
        if jwks is not None:
            # No key verification is implemented. Reject embedded keys rather
            # than inadvertently accepting private or symmetric key material.
            raise MetadataFetchError("Embedded keys are outside this public-client profile")
        data.pop("jwks_uri", None)  # Public branding/key references are never fetched.
        methods = data.pop("token_endpoint_auth_methods_supported", None)
        if methods is not None:
            if (
                not isinstance(methods, list)
                or not methods
                or not all(isinstance(value, str) for value in methods)
                or len(set(methods)) != len(methods)
                or "none" not in methods
            ):
                raise MetadataFetchError("No supported client authentication method")
            if any(method.startswith("client_secret_") for method in methods):
                raise MetadataFetchError("Shared-secret authentication is not permitted")
            data["token_endpoint_auth_method"] = PublicCodeGrant.TOKEN_ENDPOINT_AUTH_METHODS[0]
        elif data.get("token_endpoint_auth_method", "none") != "none":
            raise MetadataFetchError("No supported client authentication method")
        for name, allowed, required in (
            ("grant_types", ("authorization_code", "refresh_token"), "authorization_code"),
            ("response_types", ("code",), "code"),
        ):
            values = data.get(name, list(allowed))
            if (
                not isinstance(values, list)
                or not all(isinstance(v, str) for v in values)
                or (len(set(values)) != len(values) or required not in values)
            ):
                raise MetadataFetchError("Incompatible client capabilities")
            data[name] = [v for v in values if v in allowed]
        try:
            options = self.client_claims.get_claims_options(self.metadata)
            claims = self.client_claims(data, {}, options, self.metadata)
            claims.validate()
        except InvalidClaimError as exc:
            raise MetadataFetchError("Invalid client metadata") from exc
        from urllib.parse import urlsplit

        parts = urlsplit(data["client_id"])
        return Client(
            data["client_id"],
            tuple(claims["redirect_uris"]),
            claims["scope"],
            tuple(claims["grant_types"]),
            tuple(claims["response_types"]),
            claims.get("client_name", ""),
            metadata_origin=f"{parts.scheme}://{parts.netloc}",
        )

    def touch_client(self, client_id: str) -> None:
        if self.client_mode == ClientMode.CIMD_ONLY or (
            self.client_mode != ClientMode.DCR_ONLY and ":" in client_id
        ):
            return
        unit = self.uow.get()
        client = unit.get_client(client_id)
        if client:
            unit.put_client(replace(client, last_used_at=self.clock()))

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

    def save_token(self, token: dict[str, Any], request: FormRequest) -> None:
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
                client_source="cimd" if request.client.metadata_origin is not None else "dcr",
            )
        unit.put_grant(grant)
        self.touch_client(request.client.client_id)
