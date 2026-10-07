# Contributing

Use Python 3.11 or newer in a virtual environment:

```sh
python -m pip install -e '.[dev,example]'
```

Run the development checks listed in README.md. CI tests Python 3.11–3.14, branch coverage of at least 90%, formatting, lint, source typing, dependency/security checks and distribution installation.

Protocol/security changes need public HTTP/API regression tests, negative cases and storage rollback/concurrency coverage where applicable. Explain ownership changes in docs/architecture.md. Actual Authlib grants/endpoints must execute; test spies must delegate to real methods. Runtime forks, private patches and monkeypatches are prohibited.

Use Conventional Commits: feat/fix/perf/docs/ci and BREAKING CHANGE or ! for API changes. `_version.py` is the authoritative runtime/build version. Release Please updates it and CHANGELOG.md; its manifest records release history. Review the release PR before merging.

Verify built distributions in a second environment outside the checkout:

```sh
python -m build
python -m twine check --strict dist/*
python scripts/check_distribution.py dist
```

Install the wheel with FastAPI, itsdangerous and httpx2 into a clean environment, change outside the checkout and run `python /absolute/repo/scripts/wheel_smoke.py /absolute/repo`. CI exercises this discovery/login/consent/token flow.

Keep dependencies narrow and integration contracts generic. Durable adapters require transaction and identity conformance tests. Follow SECURITY.md for private vulnerability reporting and preserve third-party license/provenance obligations.

## Integration validation

CI separates Python 3.11–3.14 unit/branch coverage, strict lint/type/security checks, declared-minimum and latest-compatible dependency profiles, distribution validation and three installed-wheel integration layers. The same suite runs weekly against compatible dependencies. Minimum pins are explicit in the workflow; update them with declared lower bounds.

```sh
python scripts/e2e.py dist/oauth21_asgi-VERSION-py3-none-any.whl
python scripts/e2e.py dist/oauth21_asgi-VERSION-py3-none-any.whl --https
python scripts/e2e.py dist/oauth21_asgi-VERSION-py3-none-any.whl --https --mcp
```

Each command creates a clean virtualenv outside the checkout, installs the wheel, and launches Uvicorn and a separate protocol client. Every mode is exercised; combined mode runs both client sources. HTTPS requires `CADDY_BINARY` pointing to Caddy 2.11.7 (CI downloads and verifies its checksum). It uses an explicitly trusted temporary test certificate, never disabled verification. MCP interoperability installs only the pinned official Python SDK 2.3.0 in that ephemeral environment and performs a tool call plus cross-resource rejection. The SDK is not a runtime dependency. See [audit results](docs/audit.md) and [storage conformance](docs/storage.md#adapter-conformance).

## Release and PyPI setup

Conventional commits produce one Release Please PR; merging it produces a tag and GitHub Release. Release automation checks tagged source, builds once, validates and tests that exact wheel, then attaches wheel/sdist plus `SHA256SUMS`. Existing assets are never overwritten. Publishing downloads those assets and verifies their hashes and distribution metadata; it never rebuilds. Failed/partial attachment needs maintainer investigation rather than an automatic overwrite. Existing versions cannot silently be replaced on PyPI.

Configure a PyPI Trusted Publisher for project `oauth21-asgi`, owner `karusb`, repository `oauth21-asgi`, workflow `release-please.yml`, environment `pypi`. Create that GitHub environment (with desired reviewer rules) and set repository variable `PYPI_PUBLISH=true` when ready. The publishing job alone has OIDC permission and enables attestations. No PyPI API token is required. An optional `RELEASE_PLEASE_TOKEN` supports automation that must trigger downstream workflows; the default GitHub token can still create the release PR, but its events do not trigger other workflows. Review release changes manually.

After a new release has validated assets, `workflow_dispatch` with its `release_tag` can retry publishing those same assets when initial PyPI setup was deferred. It cannot rebuild or replace them. Historical `v0.1.0` predates the checksum manifest and cannot use this new retry gate as-is; use the next validated release rather than silently recreating old artifacts. This change does not publish anything or rewrite version history.

The two historical `chore(main): release 0.1.0` commits are the release PR commit and its normal merge commit, not evidence of duplicate releases. See the [release audit](docs/audit.md#release-history-and-artifacts) for IDs and observed release assets.
