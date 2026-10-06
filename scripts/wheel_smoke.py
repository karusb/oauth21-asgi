"""Run with the wheel installed, outside the source tree. No OpenAI requests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from authlib.oauth2.rfc7636 import create_s256_code_challenge
from starlette.testclient import TestClient

import oauth21_asgi

root = Path(sys.argv[1]).resolve()
assert "/src/" not in str(Path(oauth21_asgi.__file__).resolve()).replace("\\", "/")
spec = importlib.util.spec_from_file_location("demo_host", root / "examples" / "fastapi_app.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
app = module.create_app()
http = TestClient(app, base_url="https://video.example.test", follow_redirects=False)
metadata = http.get("/.well-known/oauth-authorization-server").json()
assert metadata["issuer"] == "https://video.example.test/"
registration = http.post(
    "/oauth/register",
    json={
        "redirect_uris": ["https://client.example.test/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
    },
)
assert registration.status_code == 201, registration.text
cid = registration.json()["client_id"]
verifier = "v" * 64
params = {
    "client_id": cid,
    "response_type": "code",
    "redirect_uri": "https://client.example.test/callback",
    "resource": "https://video.example.test/api",
    "scope": "read",
    "state": "wheel-smoke",
    "code_challenge": create_s256_code_challenge(verifier),
    "code_challenge_method": "S256",
}
auth = http.get("/oauth/authorize", params=params)
assert auth.status_code == 303
login = http.get("/login")
csrf = login.text.split('name="csrf" value="')[1].split('"')[0]
assert http.post("/login", data={"csrf": csrf}).status_code == 303
consent = http.get("/oauth/authorize", params=params)
assert consent.status_code == 200
secret = consent.text.split('name="consent_token" value="')[1].split('"')[0]
callback = http.post("/oauth/authorize", data={"consent_token": secret, "decision": "allow"})
assert callback.status_code == 302, callback.text
values = parse_qs(urlsplit(callback.headers["location"]).query)
assert values["iss"] == [metadata["issuer"]]
token = http.post(
    "/oauth/token",
    data={
        "grant_type": "authorization_code",
        "client_id": cid,
        "code": values["code"][0],
        "redirect_uri": params["redirect_uri"],
        "resource": params["resource"],
        "code_verifier": verifier,
    },
)
assert token.status_code == 200, token.text
assert app.state.oauth.validate_access_token(
    token.json()["access_token"], resource=params["resource"]
)
print(
    "Installed wheel: import, FastAPI startup, discovery, DCR, login, consent, iss and token passed"
)
