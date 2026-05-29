"""Verifier surface for v0.2 receipts.

Library-level read-side verification path. Phase B scope:

- :func:`verify_receipt` — independent VALID / INVALID check of a v0.2
  receipt: recompute ``receipt_hash`` over the S1 pre-image AND verify the
  Ed25519 signature, with an externally-supplied public key.
- :func:`verify_receipt_signature` — signature-only check (component of
  the above; returns ``bool``).
- :func:`load_public_key_pem` — load the externally-supplied Ed25519
  public key from PEM bytes.

Phase C (later): reason classifier, verifier CLI, attestation file
handling.
"""

from witseal.verify.ed25519 import load_public_key_pem, verify_receipt_signature
from witseal.verify.receipt import verify_receipt
from witseal.verify.result import VerificationResult

__all__ = [
    "VerificationResult",
    "load_public_key_pem",
    "verify_receipt",
    "verify_receipt_signature",
]
