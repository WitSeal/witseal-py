"""Verifier surface — the SDK read-side verification path ([redacted] role B).

Library-level, key-aware verification:

- :func:`verify_artifact` — unified, version-discriminating entry point:
  given a parsed JSON mapping it routes to the right verifier (v0.1 receipt,
  v0.2 receipt, or evidence package) and returns one VALID / INVALID verdict.
- :func:`verify_receipt` — independent check of a v0.2 receipt: recompute
  ``receipt_hash`` over the S1 pre-image AND verify the Ed25519 signature,
  with an externally-supplied public key.
- :func:`verify_evidence_package` — chain verification + per-receipt
  integrity for an evidence package.
- :func:`verify_chain` — witness-event hash-chain verification (linkage,
  self-hashes, sequence monotonicity).
- :func:`verify_receipt_signature` — signature-only check (returns ``bool``).
- :func:`load_public_key_pem` — load the externally-supplied Ed25519
  public key from PEM bytes.

The package CLI exposes ``witseal verify {receipt,evidence,artifact}`` and
``witseal inspect`` (keyless, in :mod:`witseal.inspect`).

Python is the ecosystem SDK: it consumes and verifies artifacts, it does not
generate them at runtime (generation is the Rust track per [redacted]).
"""

from witseal.verify.artifact import ArtifactVerifyResult, verify_artifact
from witseal.verify.chain import ChainVerifyResult, verify_chain, verify_event_hash
from witseal.verify.ed25519 import load_public_key_pem, verify_receipt_signature
from witseal.verify.evidence import (
    EvidenceVerifyResult,
    ReceiptSubResult,
    verify_evidence_package,
)
from witseal.verify.receipt import verify_receipt
from witseal.verify.result import VerificationResult

__all__ = [
    "ArtifactVerifyResult",
    "ChainVerifyResult",
    "EvidenceVerifyResult",
    "ReceiptSubResult",
    "VerificationResult",
    "load_public_key_pem",
    "verify_artifact",
    "verify_chain",
    "verify_event_hash",
    "verify_evidence_package",
    "verify_receipt",
    "verify_receipt_signature",
]
