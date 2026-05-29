# Golden-receipt fixed-input-vector (vendored)

Cross-track byte-identity fixtures for the v0.2 `receipt` (RFC-001 v0.2 /
D6 § 8.1 conformance). **Vendored** into witseal-py from the authoritative
Rust-track corpus so the Python verifier's golden cross-check
(`tests/test_golden_receipt_v0_2.py`) is hermetic — it does not read a
sibling repository at test time.

| File | Role in the Python golden test |
|------|--------------------------------|
| `rust-golden.json` | The authoritative final v0.2 wire receipt (pretty-printed). Parsed through `ReceiptV02`, then independently verified. |
| `rust-golden.canonical` | Raw RFC 8785 canonical bytes of the final wire receipt (1050 bytes; `SHA-256 = 8fc29592fd3317e48caccc9b5c64d01cfa32d5e27846c50f233829e1bb17ef1b`). Byte-identity target. |
| `rust-golden.sig` | Detached `ed25519:`-prefixed signature over the S1 pre-image. |
| `test-only-do-not-use-in-prod.key.json` | Deterministic test-only Ed25519 key derivation (public key is re-derived in the test). |
| `inputs.json` | Fixed input-vector spec + the S1 construction procedure (steps 1–6). |

## Source of truth

These files are copies of
`tests/fixtures/golden-receipt/` in the WitSeal TypeScript repo, which are
in turn copies of the Rust-track corpus
(`crates/witseal-testkit/corpus/v0.2/golden_receipt/`). The Rust track is
authoritative. To refresh, re-copy from the Rust-track corpus; do not edit
by hand.

## Security

`test-only-do-not-use-in-prod.key.json` contains a deterministic private
key seed. It is a **test fixture only** — NEVER reuse this seed or the
derived key for any real signing operation (see the file's
`_security_posture`).
