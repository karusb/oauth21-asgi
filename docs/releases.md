# Releases

## Repository setup

Use `main` as the default branch. In **Settings → Actions → General**, allow GitHub Actions to create pull requests. Enable private vulnerability reporting in **Settings → Code security**.

The initial manifest is empty because nothing has been released. Release Please is enabled by default and starts at **0.1.0**. Push the first commit with a Conventional Commit message, for example:

```text
feat: initial release
```

Main runs the complete CI matrix. After it passes, Release Please opens the initial release PR. Merge that PR to create `v0.1.0` and attach the validated wheel and source distribution. Subsequent conventional changes advance the version normally; `initial-version` does not pin later releases.

Release Please uses GITHUB_TOKEN by default. GitHub does not run new workflows for PRs created by that token. For automatic CI on release PRs, configure RELEASE_PLEASE_TOKEN with a narrowly scoped GitHub App installation token or repository token supporting contents and pull requests. Otherwise use **Actions → CI → Run workflow** on the release branch before merging. CI runs on main again and revalidates clean tagged source before attaching release artifacts.

`_version.py` is the only runtime/build version source. Hatch reads it dynamically and Release Please updates its annotation. The manifest tracks published history. Do not manually create a competing static pyproject version.

## PyPI Trusted Publishing

GitHub releases work independently of PyPI. Enable PyPI publication after configuring:

1. Confirm the BSD-3-Clause license and packaged license metadata are retained in the release.
2. A GitHub environment named **pypi**, optionally with required reviewers.
3. A PyPI Trusted Publisher for this distribution, your GitHub owner/repository, workflow **release-please.yml** and environment **pypi**.
4. Repository variable **PYPI_PUBLISH=true**.

The publishing job downloads the already validated GitHub release distributions and uses the official PyPA action with OIDC attestations. It does not use a long-lived PyPI token or rebuild a second set of artifacts. The license check prevents publishing incomplete legal metadata.

If publication fails, fix the configuration and rerun the failed job. Do not overwrite a published PyPI version. Package or repository renaming must update metadata/imports, release configuration and the Trusted Publisher together.

References: [Release Please](https://github.com/googleapis/release-please-action), [manifest configuration](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md), [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/).
