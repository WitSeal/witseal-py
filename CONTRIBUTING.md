# Contributing

Thanks for your interest in contributing. This is the Python **SDK /
verifier** line of WitSeal — it consumes, verifies, and inspects artifacts.
Artifact generation, signing, and the execution runtime live in other lines
and are out of scope here.

## Before you start

- Trivial changes (typos, docs, dependency bumps): open a PR directly.
- Non-trivial changes: open an issue first to discuss.
- Changes to wire-format schemas or hashing/signing semantics need
  cross-track coordination (they must stay byte-identical across the
  TypeScript, Rust, and Python lines) — raise an issue before starting.

## What we accept

Bug fixes (with a regression test), documentation, performance improvements
(with measurements), additional consume/verify integration helpers, and test
coverage.

## What we don't accept

Runtime/generation/signing features (out of scope for this line), speculative
features, vendor lock-in, and unreviewed machine-generated PRs.

## Workflow

1. Fork and branch from `main`.
2. Make your change with tests.
3. Run the gates (below); all must pass.
4. Open a PR using the template; respond to review.
5. Squash if asked.

## Development setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/WitSeal/witseal-py
cd witseal-py
uv sync
uv run pytest
```

## Tests, lint, type-check

| Command | Purpose |
|---|---|
| `uv run pytest` | full test suite |
| `uv run pytest --cov=witseal` | coverage |
| `uv run mypy src` | strict type checking |
| `uv run ruff check .` | lint |
| `uv run ruff format` | format |
| `uv run python scripts/style_check.py` | vocabulary discipline (Markdown) |

Tests live in `tests/`, named `test_<module>.py` (pytest conventions).

## Vocabulary discipline

Public text follows [STYLE.md](STYLE.md). The vocabulary check scans Markdown
for diluting terms; wrap a justified exception in
`<!-- style-allow -->` … `<!-- /style-allow -->`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/)
(`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, …). Keep the
description under 72 characters. Sign off your commits (`git commit -s`) per
the [DCO](https://developercertificate.org/).

## Security

Do not file public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
