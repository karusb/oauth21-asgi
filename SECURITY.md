# Security policy

## Supported versions

Security fixes target the latest release. Use Authlib >=1.8.0 and patched framework dependencies. CI checks Python 3.11–3.14 and audits dependencies. This project has not undergone an independent security audit.

## Reporting a vulnerability

Use **Security → Report a vulnerability** in this GitHub repository to contact maintainers privately. If private reporting is unavailable, contact a maintainer privately before sharing exploit details. Do not post credentials, account data or uncoordinated vulnerability details in public issues.

Include the affected version, a minimal reproduction using synthetic credentials, expected behavior and impact. Maintainers will coordinate a fix and disclosure.

## Deployment responsibilities

Hosts own login/session security, explicit consent UX, durable transactional storage, account authorization, Resource Server challenges and rate controls. Never deploy MemoryStorage or the demonstration login as production authentication. Account incarnation/version checks must use fresh authoritative state and coordinate with account changes.

Consent tickets bind the exact resolved scopes and redirect displayed to the user; changing client defaults cannot expand an existing consent. Legacy tickets missing those resolved values require a fresh authorization. Request query limits apply before parsing; JSON rejects duplicate fields and non-JSON numbers. `Limits.body_timeout` bounds total body-read time (10 seconds by default), alongside the byte limit. Hosts still need connection, header, endpoint rate and backend transaction limits.

Consent responses preserve the host's Content Security Policy and append a separate enforced `frame-ancestors 'none'` policy. Browser enforcement intersects these policies, retaining host script/form restrictions while blocking framing. Hosts must still escape untrusted client metadata.

Configure HTTPS and trusted proxy scope correctly. Redact callback code/state, bodies and Authorization headers from infrastructure logs. The package suppresses Authlib 1.8 token-bearing grant DEBUG records with standard logging filters; this process-wide filter also affects other Authlib servers using those loggers. Review upstream logging when upgrading.

Storage outages fail closed with generic 503 responses. Keep telemetry free of credentials. The supported profile has no client secrets, passwords, JWT signing keys, remote branding fetches or token introspection.

## Client-mode threat surfaces

- **DCR_ONLY (default):** no CIMD fetching or optional network dependency. Public registration needs host rate limits and admission policy; persistent client growth needs bounded capacity and inactivity cleanup. Active codes, consents and grants protect clients from pruning, so capacity must account for live integrations.
- **CIMD_ONLY:** no public registration route or DCR acceptance. Protect metadata egress against SSRF, DNS rebinding, remote outages and cache poisoning. The built-in transport vets all resolved addresses, pins those answers through public connector APIs, preserves verified TLS/Host/SNI, rejects redirects and bounds responses/cache/in-flight work. Exact URL and document identity plus host redirect/scope policy are mandatory. Metadata publishers are not automatically trusted applications.
- **CIMD_AND_DCR:** both surfaces are enabled. URI-shaped IDs are reserved for CIMD; opaque IDs use DCR storage. Failed CIMD never downgrades to DCR, and persisted code/grant sources prevent cross-mechanism credential use.

Choose DCR-only when compatibility requires registration without remote metadata, CIMD-only when clients support metadata identities and registration is unnecessary, or combined mode when both populations must work. There is no universally smallest useful mode. Switching to CIMD-only disables existing DCR integrations without deleting their records; plan migration explicitly.

Loopback metadata is allowed only by explicit development policy with an explicitly loopback-enabled issuer. Public issuers reject that configuration. Custom fetchers must implement their own vetted DNS/connect, TLS and redirect policy; library response validation cannot enforce a custom transport's routing. Use network egress restrictions as defense in depth. Cache freshness is bounded rather than instant remote revocation; synchronous access validation never fetches metadata. See [CIMD boundaries and limitations](docs/cimd.md).

Unexpected endpoint failures emit only a fixed event plus endpoint, operation, exception class and locally generated incident ID; clients receive generic 503 and the incident ID. No traceback, exception message, request URL/body, cookies or callback parameters are logged by this diagnostic path. Expected OAuth errors do not produce exception logs. Transport diagnostics likewise omit URLs and exception text.

The standard Authlib logging filter suppresses only its exact issued-token-dictionary event (`Issue token %r to %r`), preserving unrelated INFO/DEBUG records. This narrow filter still applies process-wide to those Authlib grant loggers. Review upstream logging on upgrades and redact host/proxy logs independently. This repository's engineering review and local compatibility fixtures are not an independent security audit or hosted ChatGPT acceptance.
