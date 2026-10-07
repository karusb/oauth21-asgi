from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, OAuth2Error
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9207 import IssuerParameter

from .http import FormRequest
from .interfaces import Identity
from .models import Subject

if TYPE_CHECKING:
    from .engine import Engine


class GrantHooks(Protocol):
    request: FormRequest
    server: Engine

    def register_hook(self, name: str, callback: Callable[..., None]) -> None: ...


class InvalidTargetError(OAuth2Error):  # type: ignore[misc] # untyped Authlib error base
    error = "invalid_target"
    description = "A single configured resource is required and must match the grant."


class MandatoryS256(CodeChallenge):  # type: ignore[misc] # untyped Authlib hook base
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant: GrantHooks, redirect_uri: str) -> None:
        super().validate_code_challenge(grant, redirect_uri)
        values = grant.request.payload.data
        if values.get("code_challenge_method") != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", values.get("code_challenge", "")
        ):
            raise InvalidRequestError("PKCE requires an explicit S256 challenge.")

    def validate_code_verifier(self, grant: GrantHooks, result: Any) -> None:
        verifier = grant.request.form.get("code_verifier", "")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise InvalidRequestError("A well-formed PKCE verifier is required.")
        super().validate_code_verifier(grant, result)


class ResourceBinding:
    """RFC 8707 single-resource profile through Authlib's public grant hooks."""

    def __init__(self, resources: frozenset[str]) -> None:
        self.resources = resources

    def __call__(self, grant: GrantHooks) -> None:
        grant.register_hook("after_validate_authorization_request_payload", self.authorization)
        grant.register_hook("after_validate_token_request", self.exchange)

    def resource(self, request: FormRequest, expected: str | None = None) -> str:
        values = request.payload.datalist.get("resource", [])
        if len(values) != 1 or values[0] not in self.resources:
            raise InvalidTargetError()
        if expected is not None and values[0] != expected:
            raise InvalidTargetError()
        return values[0]

    def authorization(self, grant: GrantHooks, redirect_uri: str) -> None:
        self.resource(grant.request)
        grant.server.validate_requested_scope(grant.request.scope)
        if any(len(v) != 1 for v in grant.request.payload.datalist.values()):
            raise InvalidRequestError("Repeated authorization parameters are not supported.")

    def exchange(self, grant: GrantHooks, result: Any) -> None:
        self.resource(grant.request, grant.request.authorization_code.resource)
        scope = grant.request.authorization_code.scope
        grant.server.validate_requested_scope(scope)
        if grant.request.client.get_allowed_scope(scope) is None:
            from authlib.oauth2.rfc6749 import InvalidScopeError

            raise InvalidScopeError()


class ExactIssuer(IssuerParameter):  # type: ignore[misc] # untyped Authlib extension base
    def __init__(self, issuer: str) -> None:
        self.issuer = issuer

    def get_issuer(self) -> str:
        return self.issuer


def current_subject(identity: Identity, old: Subject) -> Subject:
    subject = identity.get_subject(old.subject_id)
    if (
        subject is None
        or not subject.active
        or subject.authorization_version != old.authorization_version
    ):
        raise InvalidGrantError("The authorization is no longer valid.")
    return subject
