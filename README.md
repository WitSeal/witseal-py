# WitSeal Python

Native Python implementation of the WitSeal wire-format types and the
read-side verifier path for the WitSeal runtime ecosystem.

## Status

**Pre-release, Phase 1.** Public API is not yet defined.
Namespace reserved on PyPI as `witseal` v0.0.0.

## What this package does today

- **Wire-format schemas** — Pydantic v2 models for witness events,
  execution receipts (v0.1 + v0.2), evidence packages, intents, policy
  packs, and approvals. Byte-identical canonical serialization (RFC 8785
  / JCS) with the TypeScript and Rust implementations.
- **Integrity primitives** — RFC 8785 canonicalization, SHA-256 hashing,
  receipt signing-bytes assembly per the empty-string sentinel rule.
- **Ed25519 signature verification** — public-key-in / boolean-out
  verifier for v0.2 receipts, validating the RFC-002 §6 `ed25519:`
  algorithm-prefixed signature wire form.

## What this package does NOT do today

The Python track is **verifier + schema only** in Phase 1. The package
does not currently provide:

- Subprocess mediation or `witseal exec` execution path
- Policy engine / runtime policy evaluation
- Witness event log append (no event-log writer, no exclusive-lock
  acquisition)
- Approval flow execution or timeout enforcement
- File mediation, idempotent file writes, or rollback semantics
- A working CLI — `witseal` on the command line prints a placeholder
  notice pointing at the TypeScript reference

Runtime parity with the TypeScript reference (`witseal exec`, mediator,
policy engine, witness append, approval) is a future-phase deliverable,
not a present capability.

## Forward plan (not yet implemented)

- Native integration with LangChain, LangGraph, OpenAI Agents SDK,
  CrewAI, AutoGen, and MCP servers
- `witseal exec` CLI (parity with the TypeScript reference where
  applicable)

This package does **not** wrap the TypeScript or Rust binaries. It is a
native Python implementation per the TS byte-parity reference.

## References

- TypeScript reference implementation: <https://github.com/WitSeal/witseal>
- Rust parallel implementation: <https://github.com/WitSeal/witseal-rs>
- Wire-format specification: forthcoming `pai-receipt-spec` repository (Q3 2026)

## License

Apache 2.0. See LICENSE.
