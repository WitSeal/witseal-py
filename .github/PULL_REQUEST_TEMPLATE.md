<!--
Before opening: read CONTRIBUTING.md. Discuss non-trivial changes in an
issue first. Run the gates locally:
  uv run pytest
  uv run mypy src
  uv run ruff check .
-->

## What

<!-- A short description of the change. -->

## Why

<!-- Motivation / context. Refs / Fixes #<issue>. -->

## How

<!-- Notable implementation details or trade-offs. -->

## Checklist

- [ ] Tests added or updated (or N/A, with reason)
- [ ] Documentation updated (README / docstrings) if behavior changed
- [ ] `uv run pytest` passes locally
- [ ] `uv run mypy src` passes (strict)
- [ ] `uv run ruff check .` passes
- [ ] Commits follow Conventional Commits
- [ ] Commits signed off (`git commit -s`) per the DCO
- [ ] Change does **not** alter wire-format schemas or hashing/signing
      semantics (else it needs cross-track coordination)
- [ ] The cross-track golden receipt is unchanged (byte-identical)
- [ ] If user-visible, `CHANGELOG.md` updated under `[Unreleased]`
