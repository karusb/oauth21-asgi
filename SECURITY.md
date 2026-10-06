# Security policy

## Supported versions

Security fixes target the latest release. Use Authlib >=1.8.0 and patched framework dependencies. CI checks Python 3.11–3.14 and audits dependencies. This project has not undergone an independent security audit.

## Reporting a vulnerability

Use **Security → Report a vulnerability** in this GitHub repository to contact maintainers privately. If private reporting is unavailable, contact a maintainer privately before sharing exploit details. Do not post credentials, account data or uncoordinated vulnerability details in public issues.

Include the affected version, a minimal reproduction using synthetic credentials, expected behavior and impact. Maintainers will coordinate a fix and disclosure.

## Deployment responsibilities

Hosts own login/session security, explicit consent UX, durable transactional storage, account authorization, Resource Server challenges and rate controls. Never deploy MemoryStorage or the demonstration login as production authentication. Account incarnation/version checks must use fresh authoritative state and coordinate with account changes.

Configure HTTPS and trusted proxy scope correctly. Redact callback code/state, bodies and Authorization headers from infrastructure logs. The package suppresses Authlib 1.8 token-bearing grant DEBUG records with standard logging filters; this process-wide filter also affects other Authlib servers using those loggers. Review upstream logging when upgrading.

Storage outages fail closed with generic 503 responses. Keep telemetry free of credentials. The supported profile has no client secrets, passwords, JWT signing keys, remote branding fetches or token introspection.
