# oauth21-asgi

An **ASGI/FastAPI Authorization Server integration built on Authlib** for public clients, mandatory PKCE S256, Dynamic Client Registration and resource-bound opaque tokens.

Python 3.11–3.14. The host application provides authentication, consent and persistent storage. OAuth protocol handling stays in Authlib.

## Features

- Authorization Code with public-client authentication (`none`) and mandatory PKCE S256.
- Dynamic Client Registration (RFC 7591), authorization server discovery (RFC 8414), callback issuer identification (RFC 9207) and token revocation (RFC 7009).
- Exact resource binding (RFC 8707), configurable scopes and callback policies.
- Single-use authorization codes, rotating refresh tokens, replay-family revocation and absolute grant lifetimes.
- Opaque credentials digested at rest, account-version invalidation and transactional storage contracts.
- Explicit consent protected by a browser-bound, one-use ticket.
- Bounded requests, duplicate-parameter rejection and non-cacheable OAuth responses.

This is a focused public-client profile. It does not include OIDC, JWT access tokens, confidential clients, passwords, social login, CIMD or token introspection. It is not an OAuth certification.

## Installation

Install a published release with FastAPI support:

```sh
python -m pip install 'oauth21-asgi[fastapi]'
```

For development, install from the checkout:

```sh
python -m pip install -e '.[dev,example]'
```

FastAPI is optional; Starlette hosts can install the base package. Authlib, Starlette and python-multipart are the required runtime dependencies. No database driver or MCP SDK is required.

## Mount in your application

Supply your application's storage, identity and consent adapters:

```python
from fastapi import FastAPI

from oauth21_asgi import AuthorizationServer, ExactRedirectPolicy

app = FastAPI()
oauth = AuthorizationServer(
    issuer="https://auth.example.com/",
    scopes={"read", "write"},
    resources={"https://api.example.com/documents", "https://api.example.com/images"},
    storage=storage,
    identity=identity,
    consent=consent,
    redirect_policy=ExactRedirectPolicy({"https://client.example.com/callback"}),
)
oauth.mount(app)
```

`Identity.authenticate(request)` is async and returns an authenticated `Subject` or a host login/error response. `Identity.get_subject(subject_id)` is synchronous and performs a fresh authoritative lookup. A subject includes its stable ID, active state and `authorization_version`; change the version after reset, disable or account recreation.

`Consent.render(request, context, consent_token)` returns your consent page. The validated context includes client identity, scopes, exact resource/redirect, state and subject. Escape displayed metadata. Include `consent_token` in a POST form to the authorization route. `Consent.decide(request, context)` returns `Decision.ALLOW` or `Decision.DENY`. GET never grants access.

Production storage implements `Storage.transaction()` and the `UnitOfWork` contract. **MemoryStorage is development/single-process only.** Read the [storage contract](docs/storage.md) before implementing a durable adapter.

A complete development host is provided in [examples/fastapi_app.py](examples/fastapi_app.py):

```sh
python -m uvicorn examples.fastapi_app:app --host 127.0.0.1 --port 8000
```

The example login is demonstration-only. HTTP loopback is explicitly enabled there; public issuers require HTTPS.

## Public-client flow

Discover `/.well-known/oauth-authorization-server`, then POST JSON to `/oauth/register`:

```json
{
  "client_name": "Example application",
  "redirect_uris": ["https://client.example.com/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "read write"
}
```

The registration response contains a random client ID and no client secret. This profile defaults omitted auth method to `none`, grants to code/refresh and scope to configured scopes. Registration is public; use `registration_hook` and host middleware for rate control.

Authorize at `/oauth/authorize` with `response_type=code`, client ID, exact registered redirect, scope, fresh state, **one** allowlisted resource, a valid S256 challenge and explicit `code_challenge_method=S256`. After login and consent, the client checks callback state and exact `iss` against discovery.

Exchange using POST form encoding at `/oauth/token`: `grant_type=authorization_code`, client ID, code, verifier, the same redirect and resource. Verifiers must contain 43–128 permitted characters. Authlib performs PKCE hashing/comparison. Wrong verifier/client/redirect/resource does not consume the code; success does so atomically.

Refresh uses `grant_type=refresh_token`, client ID, refresh token, the same resource and optional narrowed scope. Each rotation replaces both credentials. A correctly bound predecessor replay revokes its whole family, including the successor. Serialize refresh requests; concurrent replay invalidates the one issued successor. Grant lifetime never slides indefinitely.

Revoke at `/oauth/revoke` with client ID, token and optional `token_type_hint`. Access or refresh revocation invalidates the family; unknown tokens return success. Credentials belong in form bodies, not URL queries or Authorization headers for this public-only profile.

## Resource Server integration

```python
principal = oauth.validate_access_token(
    bearer_token,
    resource="https://api.example.com/documents",
    scopes={"read"},
)
```

`None` means reject the credential. `Principal` exposes subject, client, scopes, exact resource, expiry and family ID. Validation rechecks authoritative identity/version. Async hosts should call this synchronous operation through `run_in_threadpool`.

`oauth.revoke_subject(subject_id)` invalidates grants, codes and pending consents. `oauth.prune()` runs storage cleanup. Keep these administrative operations behind host authorization.

MCP hosts can use this package as their Authorization Server while the official MCP SDK owns protected-resource discovery, challenges, tool metadata and request authentication. The protocol suite includes a ChatGPT-compatible DCR/PKCE flow with both documented callback forms; this is a compatibility test, not hosted-client certification.

## Configuration and security

`Limits` configures body/query sizes, client/code/consent/family capacities, refresh rotation bounds and TTLs. `Paths` configures all endpoint routes. Issuers with path components use RFC 8414 discovery path insertion. Route collisions fail explicitly. `oauth.engine` exposes the real Authlib server for supported public extensions.

`ExactRedirectPolicy` requires safe HTTPS and exact membership. `CallableRedirectPolicy` checks URI safety before applying your predicate. Loopback callbacks require explicit opt-in. No metadata URL is fetched.

Codes/access/refresh credentials are random 256-bit secrets with SHA-256 digests at rest. Clients and resource audiences match exactly. Storage failures fail closed. Authlib's token-bearing DEBUG grant logs are filtered; infrastructure must independently redact request bodies, credentials and callback queries. See [SECURITY.md](SECURITY.md), [architecture](docs/architecture.md) and [storage](docs/storage.md).

## Development and releases

```sh
python -m pytest --cov --cov-report=term-missing
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m bandit -q -r src
python -m pip_audit
python -m build
python -m twine check --strict dist/*
python scripts/check_distribution.py dist
```

CI runs all supported interpreters and checks the wheel installed outside the source tree. Conventional Commits drive Release Please; `_version.py` is the authoritative package version. See [CONTRIBUTING.md](CONTRIBUTING.md) and [release setup](docs/releases.md).

## License

[BSD-3-Clause](LICENSE). Authlib and Starlette are BSD-3-Clause; python-multipart is Apache-2.0. These remain separately licensed dependencies, installed from their own distributions. No upstream source is vendored or relicensed here. Redistributing dependencies requires retaining their applicable license and copyright notices.

Upstream terms: [Authlib](https://github.com/authlib/authlib/blob/v1.8.0/LICENSE), [Starlette](https://github.com/Kludex/starlette/blob/1.7.0/LICENSE.md), [python-multipart](https://github.com/Kludex/python-multipart/blob/0.0.32/LICENSE.txt).
