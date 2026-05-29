"""Tests for `witseal.verify.verify_receipt` and the receipt_hash recompute.

These exercise the combined VALID / INVALID verifier with locally
generated keys (independent of the cross-track golden vector, which is
covered in test_golden_receipt_v0_2.py). The production verifier path
never sees a private key; `Ed25519PrivateKey.generate()` is used only to
mint test signatures.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02
from witseal.verify import VerificationResult, verify_receipt

_HASH2 = "b" * 64
_HASH3 = "c" * 64
_HASH4 = "d" * 64
_HASH5 = "e" * 64
_TS = "2026-05-19T20:00:00Z"
_EVT_ID = "evt_" + "0" * 22
_RCPT_ID = "rcpt_" + "0" * 22
_DIGEST = "sha256:" + "a" * 64
_ATTEST = "sha256:" + "b" * 64
_GIT_SHA = "0" * 40
_PLACEHOLDER_SIG = "ed25519:" + "A" * 86 + "=="


def _unsigned_receipt() -> ReceiptV02:
    return ReceiptV02.model_validate(
        {
            "schema_version": "witseal.receipt.v0.2",
            "receipt_id": _RCPT_ID,
            "witness_event_id": _EVT_ID,
            "chain_segment_id": "default",
            "finalized_at": _TS,
            "receipt_hash": "0" * 64,
            "policy_decision_hash": _HASH2,
            "classified_intent_hash": _HASH3,
            "execution_result_hash": _HASH4,
            "outcome": "allowed_executed",
            "artifact_digest": _DIGEST,
            "artifact_type": "generic-binary",
            "build_id": "local",
            "git_commit": _GIT_SHA,
            "attestation_digest": _ATTEST,
            "signature": _PLACEHOLDER_SIG,
            "prev_hash": _HASH5,
        }
    )


def _finalize(receipt: ReceiptV02, priv: Ed25519PrivateKey) -> ReceiptV02:
    """Produce a fully valid receipt: set receipt_hash and signature over the
    S1 pre-image (mirrors the cross-track construction steps 3-5)."""
    receipt_hash = compute_receipt_hash(receipt)
    sig_bytes = priv.sign(compute_signing_bytes(receipt))
    sig = "ed25519:" + base64.b64encode(sig_bytes).decode("ascii")
    return receipt.model_copy(update={"receipt_hash": receipt_hash, "signature": sig})


def test_compute_receipt_hash_is_sha256_of_preimage() -> None:
    import hashlib

    receipt = _unsigned_receipt()
    assert compute_receipt_hash(receipt) == hashlib.sha256(
        compute_signing_bytes(receipt)
    ).hexdigest()


def test_compute_receipt_hash_independent_of_stored_values() -> None:
    """receipt_hash recompute must ignore the stored receipt_hash and
    signature (they are cleared to placeholders in the pre-image)."""
    a = _unsigned_receipt()
    b = a.model_copy(update={"receipt_hash": "9" * 64, "signature": _PLACEHOLDER_SIG})
    assert compute_receipt_hash(a) == compute_receipt_hash(b)


def test_verify_receipt_valid() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize(_unsigned_receipt(), priv)
    result = verify_receipt(receipt, priv.public_key())
    assert isinstance(result, VerificationResult)
    assert result.valid is True
    assert result.receipt_hash_valid is True
    assert result.signature_valid is True
    assert result.reason is None


def test_verify_receipt_invalid_signature_wrong_key() -> None:
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    receipt = _finalize(_unsigned_receipt(), priv)
    result = verify_receipt(receipt, other.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is True  # hash is key-independent
    assert result.signature_valid is False
    assert result.reason == "INVALID_SIGNATURE"


def test_verify_receipt_invalid_receipt_hash_only() -> None:
    """Stored receipt_hash wrong, signature still valid (signature does not
    cover the stored receipt_hash). Result is INVALID; the hash component
    flags the failure. reason is left None (receipt_hash reason class owned
    by the Phase C classifier, not asserted here)."""
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize(_unsigned_receipt(), priv).model_copy(
        update={"receipt_hash": "9" * 64}
    )
    result = verify_receipt(receipt, priv.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is True
    assert result.reason is None


def test_verify_receipt_invalid_body_tampered() -> None:
    """Tampering a signed field after finalize breaks both checks."""
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize(_unsigned_receipt(), priv).model_copy(
        update={"artifact_type": "npm-package"}
    )
    result = verify_receipt(receipt, priv.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is False


def test_verification_result_bool_protocol() -> None:
    valid = VerificationResult(
        valid=True, receipt_hash_valid=True, signature_valid=True
    )
    invalid = VerificationResult(
        valid=False,
        receipt_hash_valid=False,
        signature_valid=True,
        reason=None,
    )
    assert bool(valid) is True
    assert bool(invalid) is False
