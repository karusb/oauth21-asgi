# IETF standards coverage

This guide describes the shipped public-client profile, reviewed on **2026-10-08**. Authlib supplies protocol machinery; this package enables specific grants and extensions and adds ASGI, host and storage integration. An RFC appearing in Authlib does not mean this library enables all of it. Coverage below is an implementation assessment, not certification or an exhaustive requirement-by-requirement conformance report.

## Implemented RFC behavior

| Specification | Implemented behavior | Scope and missing parts |
| --- | --- | --- |
| [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html), §§4.1, 5, 6 | Authorization Code, form-encoded token exchange, token/error responses, scope checks and refresh with optional scope narrowing. Codes are short-lived, client/redirect-bound and single-use. | Public clients (`none`) only; no implicit, password, client-credentials or assertion grants. Code replay is rejected but does not revoke tokens previously issued from that code; see below. |
| [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html) | Opaque bearer-token issuance and `validate_access_token()` checks for expiry, audience, scope, subject and revocation. | Partial: the host must extract `Authorization: Bearer`, enforce resource access and emit RFC 6750 HTTP errors/`WWW-Authenticate` challenges. No general Resource Server middleware is included. |
| [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636.html), §§4–5 | Mandatory explicit S256 challenge; verifier character/length checks and Authlib hashing/comparison at exchange. | `plain` and requests without PKCE are intentionally rejected. Clients must send `code_challenge_method=S256`; omitted-method fallback is not supported. |
| [RFC 7009 — Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html), §2 | POST form endpoint, public client binding, access/refresh tokens, hint fallback and successful responses for unknown tokens. | Revoking either credential revokes its family. No confidential-client authentication. Optional browser CORS policy is host-owned; JSONP is not implemented. |
| [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html), §§2–3 | JSON registration, redirect/metadata validation, random client ID, 201 response and registration errors. Enabled in DCR-only and combined modes. | Restricted public-client profile with differing defaults; no software-statement verification or built-in initial-access-token authentication. Metadata persistence is limited; see below. |
| [RFC 8414 — Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html), §§2–3 | JSON discovery with issuer, endpoints, scopes, grants, response/auth methods, PKCE and extension support. Default well-known path uses issuer-path insertion. | No signed metadata. Registration metadata is omitted in CIMD-only mode. Custom `Paths.metadata` overrides the standard discovery location; hosts must account for that when configuring clients. |
| [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html), §§2–2.2 | Required allowlisted `resource` at authorization, exchange and refresh; exact binding to the grant and `invalid_target` errors. | Single-resource profile: repeated resources, resource switching, multiple audiences and omitted/default resources are unsupported. Resource URIs are restricted to safe HTTPS, with explicit development loopback exceptions. |
| [RFC 9207 — Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html), §§2–3 | Exact configured `iss` on authorization callbacks, including safe error redirects; discovery advertises support. | Query response mode only. Clients own exact issuer comparison and state validation. Invalid client/redirect requests return local errors rather than redirecting to an untrusted URI. |

## Known differences and incomplete behavior

### Core OAuth and authorization-code replay

The token request must include the stored exact `redirect_uri`, including when authorization originally omitted it and used the client's single registered redirect. This is stricter than RFC 6749's conditional requirement in §4.1.3.

Successful exchange deletes the code. A later replay returns `invalid_grant`, but there is no retained code-to-token-family association to revoke already issued tokens. Consequently, the additional **SHOULD** recommendation in [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2) is not implemented. Refresh-token replay is different: correctly bound predecessor reuse revokes its entire family.

### Registration defaults and metadata

When omitted, this profile selects `token_endpoint_auth_method=none` and `grant_types=[authorization_code, refresh_token]`. [RFC 7591 §2](https://www.rfc-editor.org/rfc/rfc7591.html#section-2) instead defaults to `client_secret_basic` and `[authorization_code]`. These are explicit compatibility deviations; send both fields to avoid relying on defaults. Omitted scope uses the configured server scopes.

Software statements are not verified or used as trusted claims; Authlib's configured endpoint ignores them. Shared secrets and JWKS registration are rejected. Additional recognized descriptive metadata can be validated/returned during registration, but storage retains only redirects, scope, grants, response types, name and identity/timestamps. There is no persisted localized-metadata model or UI support. The endpoint is open by default; a host `registration_hook` or middleware can add admission control, but no initial-access-token protocol is built in.

### Native applications

There is no full [RFC 8252 — OAuth for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html) implementation. Private-use URI schemes are rejected by the supplied redirect policies. HTTP loopback requires explicit opt-in, and registered redirects still match exactly, including port: the dynamic loopback-port rule in §7.3 is not implemented. HTTPS app links can pass the host allowlist, but OS ownership checks and external-browser client behavior are outside the library.

## Security guidance and drafts

**[RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html):** relevant controls include PKCE S256, exact registered redirect matching, issuer identification, audience restriction, scope checks, refresh rotation/replay detection, consent binding and framing protection. Sender-constrained tokens are not implemented; public refresh-token protection uses rotation instead. Clients remain responsible for state/issuer verification; hosts own secure login/session handling, TLS/proxy setup, escaped consent UI and durable transactional storage. This is selected BCP coverage, not a claim that every recommendation is satisfied in every deployment. See [SECURITY.md](../SECURITY.md).

**[OAuth 2.1, draft-ietf-oauth-v2-1-16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16):** a draft reference reviewed on the date above. The library follows several security choices, including mandatory S256, no implicit/password grants and rotating refresh tokens. It is not a complete implementation of that draft. In particular, its code exchange still requires `redirect_uri`, whereas the draft removes that requirement for OAuth 2.1 clients (§10.2). Confidential-client support is also absent. The package name does not promise final OAuth 2.1 compliance.

**[CIMD, draft-ietf-oauth-client-id-metadata-document-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html):** optional URL client identity, exact document `client_id`, JSON metadata validation, support discovery, bounded fetching, verified TLS, no redirects, DNS/SSRF checks and caching of valid documents. The public profile supports only `none`, not private-key JWT/JWKS authentication or software-statement verification. Caching handles selected Cache-Control/Age rules; conditional requests, ETag and Expires are absent, so this is not a complete RFC 9111 cache implementation. No background refetch or instant remote revocation is provided. The pinned draft target is not a claim to implement every later revision; see the [CIMD guide](cimd.md).

## Adjacent specifications not implemented

These are separate capabilities, not missing mandatory features of every OAuth server:

- **[RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html):** client registration read/update/delete management endpoints and registration access tokens.
- **[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html):** network token introspection. `validate_access_token()` is a local API, not an introspection endpoint.
- **[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html):** Protected Resource Metadata. This belongs to the host Resource Server; the MCP example delegates it to the official SDK.
- **[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html), [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html):** device authorization and token exchange.
- **[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html):** JWT assertions/access tokens, mutual TLS and DPoP.
- **[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html), [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html):** JWT authorization requests, pushed authorization requests and rich authorization requests.

OIDC and MCP are separate specifications, not IETF RFC compliance supplied by this package. No ID tokens, UserInfo endpoint or complete MCP server are provided.

## Implementation evidence

The mapping is based on [grant/registration integration](../src/oauth21_asgi/engine.py), [protocol extensions](../src/oauth21_asgi/extensions.py), [ASGI endpoints/discovery](../src/oauth21_asgi/server.py), [redirect policies](../src/oauth21_asgi/policies.py) and [CIMD transport](../src/oauth21_asgi/metadata_network.py). [Protocol tests](../tests/test_protocol.py), [security tests](../tests/test_security.py) and [CIMD tests](../tests/test_cimd.py) cover positive and negative behavior; [installed-wheel E2E tests](../scripts/e2e.py) exercise real transports. These tests establish the scenarios they cover, not exhaustive RFC conformance.
