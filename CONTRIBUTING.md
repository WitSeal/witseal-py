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
The main CI and dependency canary use uv 0.11.14. Main CI uses the committed
`uv.lock`.

```bash
git clone https://github.com/WitSeal/witseal-py
cd witseal-py
uv sync --locked
uv run --locked pytest
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

## Dependency checks

The main CI tests the committed lock on Python 3.11, 3.12 and 3.13. Its weekly
run repeats that environment and checks current advisories; it does not select
new dependency versions. A lock that disagrees with project metadata fails
`uv sync --locked` instead of being silently updated in CI.

The separate **Dependency canary** runs weekly and on manual request, on Python
3.13 only. It runs `uv lock --upgrade` in a disposable checkout, installs that
graph with the dev/oracle groups and MCP extra, and runs the existing tests and
dependency audit. It does not establish compatibility on every Python version
allowed by the package metadata.

The main test jobs and canary also import the MCP API used by this integration
explicitly. The optional integration tests may otherwise skip when
`mcp.server.fastmcp` is
unavailable, including when an allowed dependency upgrade changes that API.
That skip must not become a successful compatibility signal for a canary that
requested MCP. Versions allowed by dependency constraints are candidates for
testing, not a promise of runtime compatibility.

The canary retains its source identity, resolver version, selected lock,
installed package versions, test output and audit output as diagnostic artifacts
for 30 days. Failures remain visible; this scheduled workflow is not a required
pull-request check. It has read-only repository permissions and does not commit
its new lock or publish a package. A maintainer reviews any dependency update
separately and then updates the committed lock through the usual contribution
process. Keep existing required CI check names when changing workflows.

Both current audit commands inspect a development environment containing MCP;
their findings are not a base-install-only assessment. A passing canary does not
resolve findings against the committed lock. Track dependency dispositions
separately from the scheduling and resolver mechanics.

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
