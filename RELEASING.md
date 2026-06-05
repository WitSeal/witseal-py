# Releasing

Releases are cut from a `v*` tag. Pushing the tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which tests,
builds the wheel and sdist, signs them with Sigstore (keyless), publishes a
GitHub release, and — after a manual approval — publishes to PyPI via OIDC
trusted publishing.

## One-time setup

Configured once by a repository admin.

### PyPI trusted publishing (OIDC)

Publishing authenticates with [PyPI trusted publishing][tp]; no API token is
stored in the repository. Register the trusted publisher on PyPI:

| Field        | Value         |
| ------------ | ------------- |
| Project name | `witseal`     |
| Owner        | `WitSeal`     |
| Repository   | `witseal-py`  |
| Workflow     | `release.yml` |
| Environment  | `pypi`        |

For the first release, register it through PyPI's *pending publisher* form —
it creates the project on the first successful upload.

### `pypi` deployment environment

The `publish-pypi` job runs in the `pypi` environment. Add a **required
reviewer** to it (*Settings → Environments → `pypi`*) so every publish needs an
explicit approval. Environment protection rules become available once the
repository is public.

[tp]: https://docs.pypi.org/trusted-publishers/

## Cutting a release

1. Make sure `main` is green.
2. Set the version in `pyproject.toml` (`project.version`). It is the single
   source of truth — `witseal.__version__` is read from the installed
   distribution metadata.
3. In `CHANGELOG.md`, move the `[Unreleased]` notes under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading.
4. Open a PR and merge it once CI is green. The version-consistency gate
   verifies that the `pyproject.toml` version, the installed metadata, and the
   changelog section agree.
5. Tag the merge commit and push the tag:
   ```sh
   git tag -a vX.Y.Z -m "witseal vX.Y.Z"
   git push origin vX.Y.Z
   ```
6. The release workflow runs. It re-checks that the tag matches the
   `pyproject.toml` version, then waits on the `pypi` environment approval
   before publishing to PyPI.

## Verifying a published release

Artifacts are signed with Sigstore (Cosign, keyless). Verify a downloaded
file against the release tag:

```sh
cosign verify-blob \
  --certificate <file>.crt \
  --signature <file>.sig \
  --certificate-identity "https://github.com/WitSeal/witseal-py/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <file>
```

Install from PyPI:

```sh
pip install "witseal==X.Y.Z"
```

The PyPI distribution additionally carries PEP 740 attestations generated
during trusted publishing.
