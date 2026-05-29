"""Tests for `witseal.verify.ed25519`.

Uses ``cryptography``'s own ``Ed25519PrivateKey.generate()`` only to
construct test signatures — the production verifier path never sees a
private key (D5 T10: external public key argument, no signing duty).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from witseal.integrity.signing import compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02
from witseal.verify import load_public_key_pem, verify_receipt_signature

_HASH = "a" * 64
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
            "receipt_hash": _HASH,
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


def _sign_receipt(
    receipt: ReceiptV02, private_key: Ed25519PrivateKey
) -> ReceiptV02:
    """Sign a receipt: compute signing bytes with current signature, sign,
    then replace `signature` with the algorithm-prefixed base64 signature
    per RFC-002 § 6 amendment 2026-05-23 (form: ``ed25519:<88-char-base64>``)."""
    canonical_bytes = compute_signing_bytes(receipt)
    sig_bytes = private_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    return receipt.model_copy(update={"signature": f"ed25519:{sig_b64}"})


def _public_pem(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def test_load_public_key_pem_happy_path() -> None:
    priv = Ed25519PrivateKey.generate()
    pem = _public_pem(priv)
    loaded = load_public_key_pem(pem)
    assert isinstance(loaded, Ed25519PublicKey)


def test_load_public_key_pem_rejects_rsa() -> None:
    rsa_priv = generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ValueError, match="expected Ed25519 public key"):
        load_public_key_pem(rsa_pem)


def test_load_public_key_pem_rejects_malformed() -> None:
    with pytest.raises(ValueError):
        load_public_key_pem(b"-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n")


def test_verify_returns_true_for_valid_signature() -> None:
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    assert verify_receipt_signature(signed, priv.public_key()) is True


def test_verify_returns_false_for_tampered_body() -> None:
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    tampered = signed.model_copy(update={"build_id": "tampered"})
    assert verify_receipt_signature(tampered, priv.public_key()) is False


def test_verify_returns_false_for_tampered_signature() -> None:
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    # Strip the 'ed25519:' prefix before decoding raw bytes, re-add after re-encode.
    _, _, payload = signed.signature.partition(":")
    sig_bytes = base64.b64decode(payload, validate=True)
    flipped = bytes([sig_bytes[0] ^ 0x01]) + sig_bytes[1:]
    tampered = signed.model_copy(
        update={"signature": "ed25519:" + base64.b64encode(flipped).decode("ascii")}
    )
    assert verify_receipt_signature(tampered, priv.public_key()) is False


def test_verify_returns_false_for_wrong_public_key() -> None:
    priv_a = Ed25519PrivateKey.generate()
    priv_b = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv_a)
    assert verify_receipt_signature(signed, priv_b.public_key()) is False


def test_verify_loaded_pem_round_trip() -> None:
    """Full PEM-load → verify round trip: simulates production where the
    public key arrives as PEM bytes on disk / stdin / arg."""
    priv = Ed25519PrivateKey.generate()
    pem = _public_pem(priv)
    signed = _sign_receipt(_unsigned_receipt(), priv)
    loaded_pub = load_public_key_pem(pem)
    assert verify_receipt_signature(signed, loaded_pub) is True


def test_verify_sensitive_to_each_signed_field() -> None:
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    pub = priv.public_key()
    for field, new_value in [
        ("prev_hash", "9" * 64),
        ("attestation_digest", "sha256:" + "9" * 64),
        ("artifact_digest", "sha256:" + "9" * 64),
        ("git_commit", "f" * 40),
    ]:
        mutated = signed.model_copy(update={field: new_value})
        assert verify_receipt_signature(mutated, pub) is False, (
            f"verifier must reject tampered {field}"
        )


def test_verify_insensitive_to_receipt_hash_tampering() -> None:
    """Per the S1 interpretation the signature does NOT cover the stored
    ``receipt_hash`` value (it is cleared to the 64-zero placeholder during
    canonicalization). A receipt with a tampered ``receipt_hash`` therefore
    still passes *signature* verification. Detection of receipt_hash
    mismatch is a SEPARATE check — performed by :func:`verify_receipt`
    (see test_verify_receipt.py), owned at the reason-classifier layer per
    RFC-002 § 4, classified separately from ``INVALID_SIGNATURE``.
    """
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    tampered = signed.model_copy(update={"receipt_hash": "9" * 64})
    assert verify_receipt_signature(tampered, priv.public_key()) is True, (
        "signature must remain valid when only the stored receipt_hash "
        "differs — receipt_hash is cleared to the 64-zero placeholder in the "
        "S1 pre-image per the golden-receipt construction procedure"
    )


def test_verify_signature_decoded_length_is_64_bytes() -> None:
    """Ed25519 signatures are always 64 bytes raw → 86 base64 chars + ==
    padding (88 chars). Wire form per RFC-002 § 6 amendment 2026-05-23 is
    ``ed25519:<88-char-base64>`` (96 chars total). Strip prefix before
    decode; decoded length must be 64."""
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    assert signed.signature.startswith("ed25519:")
    assert len(signed.signature) == 96  # 8 (prefix) + 88 (base64)
    _, _, payload = signed.signature.partition(":")
    decoded = base64.b64decode(payload, validate=True)
    assert len(decoded) == 64


def test_verify_rejects_missing_algorithm_prefix() -> None:
    """RFC-002 § 6 amendment 2026-05-23: verifier raises ValueError when
    signature value has no '<algorithm>:' prefix. Caller maps to
    ``INVALID_SCHEMA`` per RFC-002 § 4. Defensive against callers that
    construct receipts bypassing schema validation."""
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    # Strip the prefix to simulate a bare-base64 signature (pre-amendment form).
    _, _, payload = signed.signature.partition(":")
    bare = signed.model_construct(**{**signed.model_dump(), "signature": payload})
    with pytest.raises(ValueError, match="missing '<algorithm>:' prefix"):
        verify_receipt_signature(bare, priv.public_key())


def test_verify_rejects_non_ed25519_algorithm_prefix() -> None:
    """RFC-002 § 6 amendment 2026-05-23: verifier raises ValueError on any
    algorithm tag other than 'ed25519' in a v0.2 receipt. Caller maps to
    ``INVALID_SCHEMA`` per RFC-002 § 4. Future algorithm tags are reserved
    for v0.3+."""
    priv = Ed25519PrivateKey.generate()
    signed = _sign_receipt(_unsigned_receipt(), priv)
    _, _, payload = signed.signature.partition(":")
    # Construct bypassing schema validation (schema layer rejects too,
    # tested separately in test_schemas_smoke); here exercise verifier path.
    wrong_algo = signed.model_construct(**{**signed.model_dump(), "signature": f"ecdsa:{payload}"})
    with pytest.raises(ValueError, match="unsupported signature algorithm 'ecdsa'"):
        verify_receipt_signature(wrong_algo, priv.public_key())
