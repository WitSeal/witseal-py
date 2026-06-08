# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Pre-1.0 note: the public API, schemas, and CLI are unstable. Minor releases
may introduce breaking changes; patch releases will not.

## [Unreleased]

### Added

- **`witseal.integrations.mcp`** — the first framework integration: a
  consume/verify seam for the Model Context Protocol.
  `verify_witseal_artifact(artifact, *, public_key=None)` accepts a receipt
  or evidence package as a mapping or raw JSON and returns a VALID / INVALID
  verdict via the existing `verify_artifact` path (pure consumer of the
  frozen wire format). An optional MCP tool/server surface
  (`build_mcp_server`, `register_witseal_tools`) exposes the verifier as the
  `witseal.verify_artifact` MCP tool; the `mcp` SDK is imported lazily, so
  importing the module without the new `mcp` extra still works. Provisional,
  pre-1.0: the `witseal.integrations` namespace is not yet frozen.
- **`mcp` optional-dependency extra** (`pip install "witseal[mcp]"`) for the
  MCP protocol surface. The base package stays minimal — the verify-only core
  needs no new runtime dependency.
- **`witseal.verify.resolve_public_key`** — public helper that resolves the
  externally-supplied Ed25519 key from any on-hand form (PEM path, 32-byte
  hex, PEM bytes, or a loaded key). The CLI's key handling now reuses it, so
  the CLI and the library resolve keys identically.

## [0.1.1] - 2026-06-07

### Changed

- **CLI command renamed `witseal` → `witseal-py`** to avoid a name collision with
  the npm `@witseal/cli` `witseal` command (the canonical WitSeal runtime CLI).
  The module invocation `python -m witseal` and the package name
  (`pip install witseal`) are unchanged.

## [0.1.0] - 2026-06-05

> First public SDK release of the Python line: the read-side path that
> consumes, verifies, and inspects WitSeal artifacts. Canonical generation
> remains the Rust trust core; the Python line does not generate artifacts
> and is not a runtime. Cross-track golden receipt is byte-identical
> (`8fc29592…`, 1050 bytes).

### Added

- Wire-format schemas (Pydantic v2): witness events, execution receipts
  (v0.1 + v0.2), evidence packages, intents, policy packs, approvals, with
  RFC 8785 (JCS) canonical serialization byte-identical to the TypeScript
  and Rust implementations.
- Integrity primitives: RFC 8785 canonicalization, SHA-256 hashing, receipt
  signing-bytes assembly, and the witness-event `event_hash` rule.
- Receipt verification: independent v0.2 receipt verification (recompute
  `receipt_hash` over the signing pre-image and verify the Ed25519 signature
  in its `ed25519:`-prefixed wire form) under a caller-supplied public key.
- Hash-chain and evidence-package verification: chain linkage, self-hashes,
  sequence monotonicity, head match, and per-receipt cross-check against
  companion events.
- Unified `verify_artifact` discriminator and keyless `inspect`.
- CLI: `witseal verify {receipt,evidence,artifact}` and `witseal inspect`.
- `witseal.__version__` is read from the installed distribution metadata, so
  it cannot drift from the packaged version.
- Project scaffolding: CI (pytest matrix, ruff, mypy, wheel build, `pip-audit`
  dependency audit, version-consistency gate), a tag-driven release workflow
  with Sigstore keyless signing and OIDC trusted publishing to PyPI, SECURITY,
  CONTRIBUTING, STYLE, CODE_OF_CONDUCT, RELEASING, issue/PR templates,
  Dependabot, and a sanitary-barrier CI gate.

### Security

- No private-key cryptography in the SDK: signing is out of scope; the
  verifier takes a public key as an explicit input and never reads keys from
  the network, environment, config files, or bundled defaults.

[Unreleased]: https://github.com/WitSeal/witseal-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/WitSeal/witseal-py/releases/tag/v0.1.0
