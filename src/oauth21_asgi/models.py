from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, ClientMixin, TokenMixin


@dataclass(frozen=True)
class Subject:
    subject_id: str
    authorization_version: str
    active: bool = True


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Client(ClientMixin):
    client_id: str
    redirect_uris: tuple[str, ...]
    scope: str
    grant_types: tuple[str, ...]
    response_types: tuple[str, ...] = ("code",)
    client_name: str = ""
    issued_at: float = 0

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> str | None:
        return self.redirect_uris[0] if len(self.redirect_uris) == 1 else None

    def get_allowed_scope(self, scope: str | None) -> str | None:
        if scope is None:
            return self.scope
        return scope if set(scope.split()).issubset(self.scope.split()) else None

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret: str) -> bool:
        return False

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        return method == "none"

    def check_response_type(self, response_type: str) -> bool:
        return response_type in self.response_types

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.grant_types


@dataclass(frozen=True)
class Code(AuthorizationCodeMixin):
    digest: str
    client_id: str
    subject: Subject
    redirect_uri: str
    scope: str
    resource: str
    code_challenge: str
    expires_at: float
    code_challenge_method: str = "S256"

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scope(self) -> str:
        return self.scope


@dataclass(frozen=True)
class Grant(TokenMixin):
    family_id: str
    client_id: str
    subject: Subject
    resource: str
    scope: str
    created_at: float
    expires_at: float
    access_expires_at: float
    access_digest: str
    refresh_digest: str | None = None
    used_refresh: tuple[str, ...] = ()
    revoked: bool = False

    def check_client(self, client: Client) -> bool:
        return self.client_id == client.client_id

    def get_scope(self) -> str:
        return self.scope


@dataclass(frozen=True)
class PendingConsent:
    digest: str
    subject: Subject
    parameters: dict[str, str] = field(repr=False)
    expires_at: float = 0


@dataclass(frozen=True)
class AuthorizationContext:
    client_id: str
    client_name: str
    redirect_uri: str
    scopes: tuple[str, ...]
    resource: str
    state: str | None
    subject: Subject


@dataclass(frozen=True)
class Principal:
    subject: Subject
    client_id: str
    resource: str
    scopes: frozenset[str]
    expires_at: float
    family_id: str


@dataclass(frozen=True)
class Limits:
    body_bytes: int = 16_384
    query_bytes: int = 8_192
    redirects_per_client: int = 8
    registered_clients: int = 1_000
    pending_consents: int = 256
    authorization_codes: int = 1_024
    token_families: int = 4_096
    refresh_rotations: int = 256
    code_ttl: int = 120
    consent_ttl: int = 600
    access_ttl: int = 900
    grant_ttl: int = 30 * 24 * 3600
    client_ttl: int = 90 * 24 * 3600

    def __post_init__(self) -> None:
        if any(type(v) is not int or v < 1 for v in vars(self).values()):
            raise ValueError("Limits must be positive integers")
        if self.code_ttl > 600:
            raise ValueError("Authorization codes must expire within 600 seconds")


@dataclass(frozen=True)
class Paths:
    metadata: str = "/.well-known/oauth-authorization-server"
    register: str = "/oauth/register"
    authorize: str = "/oauth/authorize"
    token: str = "/oauth/token"  # noqa: S105 - endpoint path
    revoke: str = "/oauth/revoke"

    def __post_init__(self) -> None:
        values = list(vars(self).values())
        if len(set(values)) != len(values) or any(
            not p.startswith("/") or p.startswith("//") or "?" in p or "#" in p for p in values
        ):
            raise ValueError("Endpoint paths must be distinct absolute paths")
