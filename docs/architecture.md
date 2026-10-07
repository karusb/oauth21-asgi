# Architecture

The package embeds Authlib's framework-independent AuthorizationServer in Starlette/FastAPI. The host owns identity, consent UI and durable persistence; Resource Servers own authorization challenges and application permissions.

## Ownership

| Capability | Implementation |
|---|---|
| Authorization Code / refresh | Authlib AuthorizationCodeGrant and RefreshTokenGrant |
| Public-client authentication | Authlib ClientAuthentication and ClientMixin |
| PKCE | Authlib CodeChallenge; public subclass requires S256 and valid input syntax |
| Dynamic registration | Authlib ClientRegistrationEndpoint and ClientMetadataClaims |
| CIMD client identity | Async bounded resolver/transport and cache; Authlib metadata claims and normal ClientMixin objects |
| Registered callback checks | Authlib grants and exact ClientMixin membership |
| OAuth errors / responses | Authlib OAuth2Error and response generation |
| Revocation | Authlib RevocationEndpoint with host family callback |
| Server metadata | Authlib AuthorizationServerMetadata |
| Callback issuer | Authlib IssuerParameter server extension |
| Resource indicators | Small ResourceBinding extension using public grant hooks |
| ASGI adaptation | Public request/payload adapters, Starlette routes and responses |
| Atomic credential state | Storage/UnitOfWork callbacks |
| Authentication / account invalidation | Host Identity with fresh authorization_version checks |
| Consent | Host render/decide hooks plus one-use browser/subject ticket |

The engine uses public server/grant/endpoint callbacks: query_client, save_token, create_oauth2_request, create_json_request, handle_response, register_grant, register_endpoint and register_extension. No fork, private patch or copied RFC implementation is used. Authlib validates and generates protocol responses; callbacks persist digests and enforce resource/lifetime policies.

The RFC 8707 extension accepts one exact configured resource, binds it to the code and family and rejects changes during exchange/refresh. Authlib 1.8 does not provide this extension. Wrong client/resource is checked before replay revocation to prevent family poisoning.

RFC 9207 success and late errors use Authlib's server hook. Early consent-grant errors use Authlib's response encoder and public add_issuer_parameter method once, after callback validation. Unsafe callbacks receive local errors.

## Supported engine

Authlib >=1.8.0,<2 includes current callback/transport fixes. Earlier releases were affected by early-response callback vulnerabilities; requiring the current patched baseline keeps those paths out of the supported profile. Review upstream advisories when changing this minimum.

Primary references: [generic server](https://docs.authlib.org/en/stable/oauth2/authorization_server.html), [PKCE](https://docs.authlib.org/en/stable/specs/rfc7636.html), [issuer identification](https://docs.authlib.org/en/stable/specs/rfc9207.html), [changelog](https://docs.authlib.org/en/stable/upgrades/changelog.html), [callback advisory](https://github.com/authlib/authlib/security/advisories/GHSA-w8p2-r796-3vmq).

## Security-sensitive integration

The package owns bounded/duplicate-safe request adaptation, explicit S256/public-only restrictions, exact resource/redirect policy, digested transaction callbacks, rotation/replay/absolute expiry, fresh subject checks and consent binding. Constant-time digest comparisons protect direct comparisons; digest-indexed lookups use high-entropy credentials.

Tests exercise actual Authlib methods, both resource audiences, callback errors, single-use/concurrent exchanges, concurrent refresh/replay, commit failures and credential secrecy. Development MemoryStorage supplies rollback and single-process serialization; production adapters must meet the [atomic storage contract](storage.md).

## Client resolution

`ClientMode` is explicit and defaults to DCR-only. The ASGI resolver extracts exactly one client ID and, only in CIMD-enabled modes, asynchronously resolves URI-shaped IDs. Authlib's synchronous `query_client()` reads the request-local normal Client through a separate ContextVar; opaque DCR clients are read from the transactional store only in DCR-enabled modes. Cleanup always resets request-local state, including errors, cancellation and consent POST. No production monkeypatches or global request-client state are used.

CIMD uses public Authlib metadata claims for OAuth validation, plus project-owned draft identity, public-auth intersection, host policy and network/cache checks. Its fetch completes outside storage transactions and never inserts persistent clients. Codes/grants identify their source. Mode changes cannot reuse cached CIMD clients or stored DCR credentials through the wrong source. See [CIMD](cimd.md) for draft revision, transport and cache limits.

The built-in optional aiohttp resolver vets every resolved IP and returns those addresses directly to the public TCPConnector, retaining original Host/SNI and certificate verification. Request-local OAuth handling remains separate from DNS/network work. Ordinary DCR imports and operations do not load this transport or require aiohttp.

Security wrappers are checked under strict mypy. Untyped Authlib mixin inheritance has local documented ignores; project callbacks and hook boundaries have explicit types/Protocols. The token logging filter matches the exact upstream token-dictionary event rather than silencing whole log levels. Sanitized diagnostics report unexpected failures without exception text or tracebacks.

Validation combines transactional/unit coverage with clean installed-wheel subprocesses, real TCP, verified HTTPS through Caddy and optional official MCP SDK interoperability. The runtime does not depend on MCP or OpenAI.
