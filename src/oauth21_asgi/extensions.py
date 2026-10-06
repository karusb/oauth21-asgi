from __future__ import annotations

import re
from typing import Any

from authlib.oauth2.rfc6749 import InvalidGrantError, InvalidRequestError, OAuth2Error
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9207 import IssuerParameter


class InvalidTargetError(OAuth2Error):
    error = "invalid_target"
    description = "A single configured resource is required and must match the grant."


class MandatoryS256(CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant: Any, redirect_uri: str) -> None:
        super().validate_code_challenge(grant, redirect_uri)
        values = grant.request.payload.data
        if values.get("code_challenge_method") != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", values.get("code_challenge", "")
        ):
            raise InvalidRequestError("PKCE requires an explicit S256 challenge.")

    def validate_code_verifier(self, grant: Any, result: Any) -> None:
        verifier = grant.request.form.get("code_verifier", "")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise InvalidRequestError("A well-formed PKCE verifier is required.")
        super().validate_code_verifier(grant, result)


class ResourceBinding:
    """RFC 8707 single-resource profile through Authlib's public grant hooks."""

    def __init__(self, resources: frozenset[str]) -> None:
        self.resources = resources

    def __call__(self, grant: Any) -> None:
        grant.register_hook("after_validate_authorization_request_payload", self.authorization)
        grant.register_hook("after_validate_token_request", self.exchange)

    def resource(self, request: Any, expected: str | None = None) -> str:
        values = request.payload.datalist.get("resource", [])
        if len(values) != 1 or values[0] not in self.resources:
            raise InvalidTargetError()
        if expected is not None and values[0] != expected:
            raise InvalidTargetError()
        return values[0]

    def authorization(self, grant: Any, redirect_uri: str) -> None:
        self.resource(grant.request)
        if any(len(v) != 1 for v in grant.request.payload.datalist.values()):
            raise InvalidRequestError("Repeated authorization parameters are not supported.")

    def exchange(self, grant: Any, result: Any) -> None:
        self.resource(grant.request, grant.request.authorization_code.resource)


class ExactIssuer(IssuerParameter):
    def __init__(self, issuer: str) -> None:
        self.issuer = issuer

    def get_issuer(self) -> str:
        return self.issuer


def current_subject(identity: Any, old: Any) -> Any:
    subject = identity.get_subject(old.subject_id)
    if (
        subject is None
        or not subject.active
        or subject.authorization_version != old.authorization_version
    ):
        raise InvalidGrantError("The authorization is no longer valid.")
    return subject
