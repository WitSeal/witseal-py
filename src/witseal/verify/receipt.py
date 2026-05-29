"""Independent verification of a v0.2 receipt.

This is the verifier the Python track exposes to *independently* check a
v0.2 ``receipt`` produced by another track (Rust signer / TS pipeline):
it reconstructs the S1 pre-image from the receipt bytes alone, recomputes
``receipt_hash``, and verifies the Ed25519 signature over that same
pre-image. No private key, no bundled public key, no network fetch (D5
T10): the public key is supplied by the caller.

The procedure (cross-track canon — golden-receipt ``inputs.json``
``_construction_procedure`` steps 3/4/6):

1. Accept a parsed :class:`~witseal.schemas.receipt.ReceiptV02` (17
   fields, including ``artifact_type`` and ``build_id``).
2. Rebuild the S1 pre-image: clear ``signature`` -> ``""`` and
   ``receipt_hash`` -> 64 zeros, canonicalize per RFC 8785
   (:func:`witseal.integrity.signing.compute_signing_bytes`).
3. Check ``receipt_hash == SHA-256(pre-image)`` and
   ``ed25519_verify(public_key, pre-image, signature)``.
4. Return a :class:`~witseal.verify.result.VerificationResult` — VALID
   iff both checks pass.

Python remains the verification-and-schema track: it never *produces* a
receipt at runtime.
"""

from __future__ import annotations

import hmac

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from witseal.integrity.signing import compute_receipt_hash
from witseal.schemas._primitives import VerifierReason
from witseal.schemas.receipt import ReceiptV02
from witseal.verify.ed25519 import verify_receipt_signature
from witseal.verify.result import VerificationResult


def verify_receipt(
    receipt: ReceiptV02, public_key: Ed25519PublicKey
) -> VerificationResult:
    """Independently verify a v0.2 *receipt* under *public_key*.

    Returns a :class:`VerificationResult` whose ``valid`` is ``True`` iff
    the recomputed ``receipt_hash`` matches the stored value AND the
    Ed25519 signature verifies over the S1 pre-image.

    Does NOT raise on a bad signature or a hash mismatch — those are
    reported via the result. A malformed ``signature`` value (missing or
    wrong algorithm prefix, undecodable base64) propagates as
    ``ValueError`` from the signature layer; the caller maps it to
    ``INVALID_SCHEMA`` per RFC-002 § 4.
    """
    expected_hash = compute_receipt_hash(receipt)
    # Constant-time compare: receipt_hash is attacker-influenced wire data.
    receipt_hash_valid = hmac.compare_digest(expected_hash, receipt.receipt_hash)

    signature_valid = verify_receipt_signature(receipt, public_key)

    valid = receipt_hash_valid and signature_valid
    # Only the signature-failure reason is fixed in the current RFC-002 § 4
    # canon; a receipt_hash-only failure is left unclassified (reason=None)
    # with receipt_hash_valid carrying the detail (see VerificationResult).
    reason: VerifierReason | None = None
    if not signature_valid:
        reason = "INVALID_SIGNATURE"
    return VerificationResult(
        valid=valid,
        receipt_hash_valid=receipt_hash_valid,
        signature_valid=signature_valid,
        reason=reason,
    )
