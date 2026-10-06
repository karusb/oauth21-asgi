from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from authlib.oauth2.rfc6749 import JsonRequest, OAuth2Payload, OAuth2Request
from authlib.oauth2.rfc6749.requests import JsonPayload
from starlette.responses import JSONResponse, Response


class Payload(OAuth2Payload):
    def __init__(self, pairs: Iterable[tuple[str, str]]) -> None:
        self._data: dict[str, str] = {}
        self._datalist: defaultdict[str, list[str]] = defaultdict(list)
        for key, value in pairs:
            self._data[key] = value
            self._datalist[key].append(value)

    @property
    def data(self) -> dict[str, str]:
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list[str]]:
        return self._datalist


class FormRequest(OAuth2Request):
    def __init__(
        self, method: str, uri: str, pairs: Iterable[tuple[str, str]], headers: Any
    ) -> None:
        super().__init__(method, uri, headers=headers)
        self.payload = Payload(pairs)

    @property
    def form(self) -> dict[str, str]:
        return self.payload.data

    @property
    def args(self) -> dict[str, str]:
        return self.payload.data


class JSONPayload(JsonPayload):
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @property
    def data(self) -> dict[str, Any]:
        return self._data


class RegistrationRequest(JsonRequest):
    def __init__(self, uri: str, data: dict[str, Any], headers: Any) -> None:
        super().__init__("POST", uri, headers=headers)
        self.payload = JSONPayload(data)


class OAuthResponse(Response):
    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @location.setter
    def location(self, value: str) -> None:
        self.headers["location"] = value


class OAuthJSONResponse(JSONResponse, OAuthResponse):
    pass


def response(status: int, body: Any, headers: list[tuple[str, str]]) -> OAuthResponse:
    cls = OAuthJSONResponse if isinstance(body, (dict, list)) else OAuthResponse
    result = cls(body, status_code=status, headers=dict(headers))
    result.headers["Cache-Control"] = "no-store"
    result.headers["Pragma"] = "no-cache"
    result.headers["Referrer-Policy"] = "no-referrer"
    result.headers["X-Content-Type-Options"] = "nosniff"
    return result
