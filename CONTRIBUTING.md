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
