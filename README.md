# oauth21-asgi

**OAuth for your ASGI app, powered by Authlib.**

![Python 3.11–3.14](https://img.shields.io/badge/python-3.11–3.14-3776AB?logo=python&logoColor=white)
![ASGI / FastAPI](https://img.shields.io/badge/ASGI-FastAPI-009688)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

Add an Authorization Server for public clients with mandatory PKCE S256, Dynamic Client Registration and resource-bound opaque tokens. Your application owns login, consent and storage; Authlib handles the OAuth protocol.

[Quick start](#quick-start) · [App integration](#mount-in-your-application) · [Client flow](#public-client-flow) · [Resource servers](#resource-server-integration) · [Documentation](#documentation)

## Features

| Capability | What you get |
| --- | --- |
| Authorization | Authorization Code, public-client authentication (`none`) and mandatory PKCE S256 |
| Discovery & registration | Dynamic Client Registration (RFC 7591), server discovery (RFC 8414) and callback issuer identification (RFC 9207) |
| Resource binding | Exact audiences (RFC 8707), configurable scopes and redirect policies |
| Token lifecycle | Single-use codes, rotating refresh tokens, replay-family revocation, absolute grant lifetimes and revocation (RFC 7009) |
| Host integration | Transactional storage contracts, account-version invalidation and browser-bound, one-use consent tickets |
| Request protection | Bounded requests, duplicate-parameter rejection, non-cacheable OAuth responses and credential digests at rest |

**Scope:** a focused public-client profile, without OIDC, JWT access tokens, confidential clients, password grants, social login, CIMD or token introspection. This project is not an OAuth certification.

## Quick start

**Requires Python 3.11–3.14.** Install with FastAPI support:

```sh
python -m pip install 'oauth21-asgi[fastapi]'
```

To try the included demo, run these commands from a checkout:

```sh
python -m pip install -e '.[dev,example]'
python -m uvicorn examples.fastapi_app:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login) to try the demo login. See [the complete example](examples/fastapi_app.py) for identity, consent and resource-server wiring.

> The demo login and `MemoryStorage` are for development only. The example explicitly enables HTTP loopback; public issuers require HTTPS.

For Starlette, install `oauth21-asgi` without the FastAPI extra. Runtime dependencies are Authlib, Starlette and python-multipart; no database driver or MCP SDK is required.

## Mount in your application

Supply your application's storage, identity and consent adapters. In this snippet, `storage`, `identity` and `consent` are your implementations of the contracts below:

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

### The three host adapters

- **Identity:** async `authenticate(request)` returns a `Subject` or your login/error response. Synchronous `get_subject(subject_id)` performs a fresh authoritative lookup. A subject carries its stable ID, active state and `authorization_version`; change that version after reset, disable or account recreation.
- **Consent:** `render(request, context, consent_token)` returns your consent page. Escape displayed metadata and include `consent_token` in a POST form to the authorization route. The validated context contains client identity, scopes, exact resource/redirect, state and subject. `decide(request, context)` returns `Decision.ALLOW` or `Decision.DENY`; GET never grants access.
- **Storage:** implement `Storage.transaction()` and `UnitOfWork` for durable, transactional persistence. Read the [storage contract](docs/storage.md) before building an adapter. **`MemoryStorage` is development/single-process only.**

## Public-client flow

Default routes follow this flow:

**Discover → Register → Authorize + consent → Exchange → Refresh or revoke**

### 1. Discover and register

Read `/.well-known/oauth-authorization-server`, then POST JSON to `/oauth/register`:

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

### 2. Authorize

Send the user to `/oauth/authorize` with `response_type=code`, client ID, exact registered redirect, scope, fresh state, **one** allowlisted resource, a valid S256 challenge and explicit `code_challenge_method=S256`. After login and consent, check callback state and exact `iss` against discovery.

### 3. Exchange the code

Exchange using POST form encoding at `/oauth/token`: `grant_type=authorization_code`, client ID, code, verifier, the same redirect and resource. Verifiers must contain 43–128 permitted characters. Authlib performs PKCE hashing/comparison. Wrong verifier/client/redirect/resource does not consume the code; success does so atomically.

### 4. Refresh or revoke

Refresh at `/oauth/token` with `grant_type=refresh_token`, client ID, refresh token, the same resource and optional narrowed scope. Each rotation replaces both credentials; grant lifetime never slides indefinitely.

> **Serialize refresh requests.** A correctly bound predecessor replay revokes its entire token family, including the successor. Concurrent replay therefore invalidates the newly issued credentials.

Revoke at `/oauth/revoke` with client ID, token and optional `token_type_hint`. Access or refresh revocation invalidates the family; unknown tokens return success. Credentials belong in form bodies, not URL queries or Authorization headers for this public-only profile.

## Resource server integration

Validate a bearer token against the exact resource and required scopes:

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

Install `.[dev,example]` from the checkout, then run:

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

## Documentation

| Guide | When to read it |
| --- | --- |
| [Architecture](docs/architecture.md) | Understand the Authlib integration and host boundaries |
| [Storage contract](docs/storage.md) | Implement a production storage adapter |
| [Security](SECURITY.md) | Review security expectations and report vulnerabilities |
| [Contributing](CONTRIBUTING.md) | Set up development and contribute changes |
| [Releases](docs/releases.md) | Configure publishing and release automation |

## License

[BSD-3-Clause](LICENSE). Authlib and Starlette are BSD-3-Clause; python-multipart is Apache-2.0. These remain separately licensed dependencies, installed from their own distributions. No upstream source is vendored or relicensed here. Redistributing dependencies requires retaining their applicable license and copyright notices.

Upstream terms: [Authlib](https://github.com/authlib/authlib/blob/v1.8.0/LICENSE), [Starlette](https://github.com/Kludex/starlette/blob/1.7.0/LICENSE.md), [python-multipart](https://github.com/Kludex/python-multipart/blob/0.0.32/LICENSE.txt).
