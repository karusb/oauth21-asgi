# Client ID Metadata Documents

CIMD lets a public client use its HTTPS metadata document URL as its client ID without registration. This implementation targets [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02), reviewed alongside [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and [OpenAI OAuth documentation](https://developers.openai.com/plugins/build/auth). The draft can change; this is a deliberately restricted public-client profile, not final RFC compliance.

## Configuration

Install `oauth21-asgi[cimd]` for the built-in transport. DCR-only installations need neither aiohttp nor any metadata fetcher. All configuration types are exported from `oauth21_asgi`:

```python
from oauth21_asgi import (
    AuthorizationServer,
    CIMDLimits,
    ClientMetadataDocuments,
    ClientMode,
    MetadataNetworkPolicy,
)

oauth = AuthorizationServer(
    # Supply issuer, scopes, resources and host adapters as in README.md.
    ...,
    client_mode=ClientMode.CIMD_ONLY,
    cimd=ClientMetadataDocuments(
        network=MetadataNetworkPolicy(
            allowed_origins=frozenset({"https://client.example.com"}),
        ),
        limits=CIMDLimits(entries=256, max_ttl=3600, timeout=5),
    ),
)
```

The ellipsis represents the required host arguments; these fragments are configuration examples. An empty origin allowlist accepts public origins subject to network policy. A configured allowlist compares exact scheme/authority strings. Construct one `ClientMetadataDocuments` per server; sharing it across servers is rejected to prevent cached validation from crossing policies. Treat server configuration as fixed and restart with a fresh cache when policies change. `CIMDLimits` and `MetadataNetworkPolicy` are frozen records.

`DCR_ONLY` is the backwards-compatible default. Supplying CIMD configuration to that mode, or omitting it from a CIMD mode, raises a startup error. The built-in transport also checks its optional dependency at construction.

## Document and public authentication

```json
{
  "client_id": "https://client.example.com/oauth/client.json",
  "client_name": "Example application",
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "read"
}
```

The requested URL and document `client_id` must match byte for byte. The URL must have a meaningful path, production HTTPS, no userinfo, query or fragment, and no malformed port, percent encoding, dot segments or ambiguous encoded delimiters. IDs are never canonicalized. Only status 200 and `application/json` or `application/oauth-client-metadata+json` are accepted. Parsing requires UTF-8 JSON objects, rejects duplicate members and non-JSON numbers, and bounds the response.

Authlib's public metadata claims validate redirects, scopes and the supported code/refresh profile. Redirects must also satisfy the host redirect policy. Requested scopes cannot exceed configured AS scopes or the client's allowed scopes, including later exchanges and refreshes. This server supports token authentication `none` only. If the transition field `token_endpoint_auth_methods_supported` exists, its intersection with `{"none"}` controls selection: `["none", "private_key_jwt"]` selects `none` even when singular `token_endpoint_auth_method` prefers `private_key_jwt`. A document supporting only unsupported methods is rejected.

There is no client-secret authentication, private-key JWT or JWKS verification. Embedded key material and client secrets are rejected. `jwks_uri`, branding URLs and other referenced URLs are not fetched. Escape all displayed metadata. `AuthorizationContext.client_origin` supplies a parsed scheme/authority for CIMD clients; it is `None` for DCR clients and is not a trust endorsement.

## Resolution and migration

In CIMD-enabled modes, URI-shaped IDs (containing `:`) are reserved for CIMD and must pass its URL validation. They can never resolve through stored DCR records, including after a fetch or metadata failure. Opaque IDs use DCR only when that mechanism is enabled. Unknown opaque IDs do not initiate network traffic.

The ASGI boundary resolves metadata asynchronously before entering synchronous Authlib work. A request-local `ContextVar` passes a normal Authlib `Client` into `query_client()` and is reset in `finally`. Authorization GET, consent POST, exchange, refresh and revocation all use the same resolution policy. CIMD records are never written to persistent DCR storage; codes and grants retain a source discriminator to prevent cross-source confusion.

Switching to CIMD-only disables stored DCR clients and their credentials without deleting their records. Re-enabling DCR can restore still-valid state; normal expiry/pruning remains in effect. CIMD credentials likewise cannot be used in DCR-only mode. Opaque IDs are never silently migrated to URLs. Synchronous access-token validation checks source, identity/version, configured scopes and exact resource without performing remote metadata I/O.

## Network boundary

The built-in aiohttp transport uses public `AbstractResolver`, `ThreadedResolver` and `TCPConnector` APIs. Every DNS answer is vetted and only those numeric addresses are handed to the connector; it does not independently resolve the hostname again. The original URL preserves Host and TLS SNI, with normal certificate and hostname verification. Environment proxies, cookies, redirects and decompression are disabled. Streaming byte limits, timeout and header bounds apply. Non-200 responses, including any redirect, fail without following the location.

Policy rejects non-global, multicast and inappropriate IPv4/IPv6 special-use addresses, including mapped and transition/translation ranges that can hide private IPv4 destinations. This protects the library's destination selection, not arbitrary network routing: keep deployment egress restrictions as defense in depth, especially where NAT, special routing or trusted certificate configuration could change reachability.

Development loopback requires **both** `MetadataNetworkPolicy(allow_loopback=True)` and the server's explicit `allow_loopback=True` with a loopback issuer. A public issuer cannot enable this relaxation. Non-loopback private destinations remain rejected. Development does not disable TLS verification; explicitly trust a test CA through a custom configured transport when testing HTTPS.

For other environments, implement the async `ClientMetadataFetcher.fetch(client_id, *, max_bytes, timeout) -> MetadataResponse` protocol. Custom fetchers own DNS/connect pinning, destination safety, TLS verification, response bounds and redirect policy. The resolver still validates URL, response and document, but cannot prove a custom transport's network behavior. Use `MetadataFetchError` for expected sanitized transport rejection; unexpected programming failures reach generic 503 diagnostics. Never place credentials in metadata or error text.

## Cache and availability

Defaults: 16 KiB response, 256 validated entries, 16 distinct in-flight fetches, five-second fetch timeout, 300-second default TTL and 0–3600-second TTL bounds. The cache is process-local, lock-protected LRU with exact URL keys and cross-thread/event-loop single-flight coordination. Over-capacity new fetches fail closed. Only fully validated clients are cached; failed documents are retried on subsequent requests, not accepted from negative-cache state.

`Cache-Control: max-age` minus `Age` is clamped to configured bounds. `no-store` and `no-cache` always prevent reuse, including when minimum TTL is configured. Missing/invalid freshness headers use the default TTL. Conditional requests, ETag and Expires revalidation are not implemented. There are no bearer tokens in this cache. Metadata changes can take up to the cache TTL to apply; existing access tokens are not remotely revoked through metadata changes. Remote outages fail authorization/token/revocation resolution after cache expiry. Plan availability, rate controls and egress budgets accordingly.

## Compatibility evidence

Deterministic fixtures exercise both documented ChatGPT callback forms and the plural/singular auth-method transition in CIMD-only and combined modes without registration. Independent installed-wheel client processes cover all modes over real TCP and verified HTTPS through Caddy. The official Python MCP SDK 2.3.0 performs authenticated tool calls and cross-resource rejection. These are interoperability tests. A TypeScript SDK client and formal certifications have not been validated.
