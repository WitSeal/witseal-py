# WitSeal Python

Native Python **Ecosystem SDK** for WitSeal: the read-side path that
consumes, verifies, and inspects WitSeal artifacts (receipts and evidence
packages). Per [redacted] the Python line is the SDK layer — it does not
generate artifacts and is not a runtime; canonical generation is the Rust
trust core.

## Status

**Pre-release.** Public API is not yet frozen.
Namespace reserved on PyPI as `witseal` v0.0.0.

## What this package does today

- **Wire-format schemas** — Pydantic v2 models for witness events,
  execution receipts (v0.1 + v0.2), evidence packages, intents, policy
  packs, and approvals. Byte-identical canonical serialization (RFC 8785
  / JCS) with the TypeScript and Rust implementations — proven against the
  three-track golden receipt (`8fc29592…`, 1050 bytes).
- **Integrity primitives** — RFC 8785 canonicalization, SHA-256 hashing,
  receipt signing-bytes assembly per the v0.2 S1 64-zero `receipt_hash`
  placeholder rule, and the witness-event `event_hash` rule
  (`SHA-256(canonicalize(event without event_hash))`).
- **Receipt verification** — independent v0.2 receipt verification:
  recompute `receipt_hash` over the S1 pre-image and verify the Ed25519
  signature (RFC-002 §6 `ed25519:` algorithm-prefixed form) under a
  caller-supplied public key.
- **Hash-chain & evidence-package verification** — walk a witness-event
  chain (linkage, self-hashes, sequence monotonicity) and verify a full
  evidence package: chain + `chain_head_after_range` match + per-receipt
  integrity cross-checked against each companion event.
- **Unified verification** — `verify_artifact` discriminates on
  `schema_version` and routes to the right verifier (v0.1 receipt, v0.2
  receipt, or evidence package).
- **Keyless inspection** — `inspect` summarizes any artifact and reports
  the integrity checks that need no key (receipt-hash self-consistency,
  chain integrity), explicitly flagging signature checks as key-requiring.
- **Verifier / SDK CLI** — `verify receipt|evidence|artifact` and
  `inspect` (see below).

## What this package does NOT do ([redacted] boundary)

The Python line is the **SDK / verifier** layer — consume, verify,
integrate. It deliberately does **not** provide:

- **Artifact generation** — no receipt/event/evidence generation, no
  signing. Canonical generation is the Rust trust core ([redacted]).
- **Runtime** — no `witseal exec`, no subprocess mediation, no policy
  engine / runtime policy evaluation, no witness event-log append or
  exclusive-lock acquisition, no approval-flow execution, no file
  mediation / rollback.

These are not Python deliverables. A full Python runtime (variant D) is
closed as off-architecture; Python↔Rust bindings (variant E) are deferred
to 0.3.0+.

## CLI

```bash
# Verify a v0.2 receipt with an explicit Ed25519 public key (PEM path or 32-byte hex)
python -m witseal verify receipt receipt.json --public-key ed25519-public.pem
python -m witseal verify receipt receipt.json --public-key fd62f46e…c91862

# Verify an evidence package (chain + per-receipt integrity); key needed only
# if the package contains a v0.2 receipt
python -m witseal verify evidence package.json [--public-key …]

# Verify any artifact, auto-discriminating on schema_version
python -m witseal verify artifact artifact.json [--public-key …]

# Keyless inspection — structure + no-key integrity checks
python -m witseal inspect artifact.json
```

The public key is always an explicit verifier input. The CLI never reads
keys from the network, environment, config files, or bundled defaults.

Exit codes: `0` VALID, `1` INVALID (JSON diagnostics on stdout), `2`
input/usage error (unreadable file, malformed artifact or key, missing
required `--public-key`).

## Forward plan (not yet implemented)

- Native integration helpers for LangChain, LangGraph, OpenAI Agents SDK,
  CrewAI, AutoGen, and MCP servers (consume/verify side)
- Python↔Rust bindings to the Rust trust core (variant E, 0.3.0+)

This package does **not** wrap the TypeScript or Rust binaries. It is a
native Python implementation per [redacted].

## References

- TypeScript reference implementation: <https://github.com/WitSeal/witseal>
- Rust parallel implementation: <https://github.com/WitSeal/witseal-rs>
- Wire-format specification: forthcoming `pai-receipt-spec` repository (Q3 2026)

## License

Apache 2.0. See LICENSE.
