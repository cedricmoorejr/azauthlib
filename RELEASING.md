# Releasing azauthlib

Releases are built once by GitHub Actions. The same wheel and source distribution are published to
PyPI and attached to the GitHub release with a SHA-256 checksum file.

## One-time repository configuration

1. Create a GitHub environment named `pypi`. Add required reviewers when another trusted maintainer
   is available.
2. In the PyPI `azauthlib` project, add a GitHub Trusted Publisher with:
   - owner: `cedricmoorejr`
   - repository: `azauthlib`
   - workflow: `publish.yml`
   - environment: `pypi`
3. Protect `main` with a ruleset requiring pull requests, CI, CodeQL, resolved conversations, and
   blocked force pushes and deletion.
4. Restrict GitHub Actions to approved actions and require full-length commit SHA pinning.

Do not configure a long-lived PyPI API token. The publish job requests a short-lived OIDC token.

## Release procedure

1. Confirm the version in `src/azauthlib/__init__.py` is unused on both PyPI and GitHub.
2. Replace `Unreleased` in `CHANGELOG.md` with the release date and prepare release notes under
   `.github/release-notes/`.
3. Run the complete local release checks:

   ```bash
   python -m pip install -e ".[dev]"
   ruff check .
   ruff format --check .
   bandit -c pyproject.toml -r src
   pip-audit --skip-editable
   pytest
   python -m build
   twine check dist/*
   ```

4. Merge the release pull request into `main` only after all required checks pass.
5. Create a draft GitHub release targeting `main` with a tag matching `v` plus the exact package
   version, for example `v1.4.0b1`. Paste the matching release-notes file and mark beta releases as
   pre-releases.
6. Publish the GitHub release. The `Publish to PyPI` workflow verifies that the tagged commit is on
   `main`, verifies the tag/version match, builds and smoke-tests the distributions, publishes them
   to PyPI, and attaches them plus `SHA256SUMS.txt` to the GitHub release.
7. Verify the GitHub workflow, PyPI metadata, provenance, and a clean-environment installation.

Published PyPI files and release tags are immutable release records. If a release is wrong, publish
a corrected version rather than replacing its files or moving its tag.
