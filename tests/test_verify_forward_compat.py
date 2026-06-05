"""Forward-compatibility of the v0.2 verifier.

A v0.2 receipt that carries an unknown top-level *additive* field (a field
outside the 17-field canon), signed correctly over ALL its fields including
that extra one, must verify VALID. Previously the verifier parsed the
wire JSON into a typed model that DROPPED unknown fields and recomputed the
S1 pre-image from the stripped model, so the pre-image no longer matched
what was signed and the receipt verified INVALID.

The fix is verifier-side only: ``ReceiptV02`` uses ``extra="allow"`` and the
pre-image (:func:`witseal.integrity.signing.compute_signing_bytes`) is built
from the received mapping INCLUDING unknown fields. Canonicalization stays
RFC 8785 / JCS, which sorts the unknown keys in lexicographically.

Scope is STRICT: this relaxation covers unknown additive fields only. A
receipt missing a required field, or with a wrong-typed canon field, or
whose existing field value was tampered after signing, must STILL be
INVALID — those cases are asserted here and in
``test_schemas_smoke.py`` / ``test_verify_receipt.py``.

Receipts are REALLY signed with a locally generated Ed25519 keypair via the
repo's own signing primitives (``compute_signing_bytes`` /
``compute_receipt_hash``); the production verifier path never sees a private
key (D5 T10) — the private key here only mints test signatures.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02
from witseal.verify import verify_receipt

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

# An unknown top-level additive field — NOT one of the 17 canon fields.
_EXTRA_KEY = "experimental_trace_id"
_EXTRA_VALUE = "trace-9f3c2a-forward-compat"


def _canon_body() -> dict[str, object]:
    """The 17 canon v0.2 fields (receipt_hash/signature at placeholders)."""
    return {
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


def _finalize(receipt: ReceiptV02, priv: Ed25519PrivateKey) -> ReceiptV02:
    """Produce a fully valid, REALLY-signed receipt.

    Sets ``receipt_hash`` and ``signature`` over the S1 pre-image of
    *receipt* (which already carries any unknown additive fields, so the
    signature covers them). Mirrors cross-track construction steps 3-5.
    """
    receipt_hash = compute_receipt_hash(receipt)
    sig_bytes = priv.sign(compute_signing_bytes(receipt))
    sig = "ed25519:" + base64.b64encode(sig_bytes).decode("ascii")
    return receipt.model_copy(update={"receipt_hash": receipt_hash, "signature": sig})


# --------------------------------------------------------------------------
# (a) control: a valid receipt with NO extra field, signed -> VALID
# --------------------------------------------------------------------------
def test_forward_compat_control_no_extra_field_valid() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize(ReceiptV02.model_validate(_canon_body()), priv)

    # No extras present — this is exactly the 17-field canon receipt.
    assert not receipt.model_extra
    assert len(receipt.model_dump()) == 17

    result = verify_receipt(receipt, priv.public_key())
    assert result.valid is True
    assert result.receipt_hash_valid is True
    assert result.signature_valid is True
    assert result.reason is None


# --------------------------------------------------------------------------
# (b) forward-compat: same receipt PLUS one unknown additive field, signed
#     over ALL fields incl. the extra -> VALID
# --------------------------------------------------------------------------
def test_forward_compat_unknown_additive_field_valid() -> None:
    priv = Ed25519PrivateKey.generate()

    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    parsed = ReceiptV02.model_validate(body)

    # The unknown field survives parsing (extra="allow") rather than being
    # dropped — this is the crux of the forward-compat fix.
    assert parsed.model_extra == {_EXTRA_KEY: _EXTRA_VALUE}

    # Sign over ALL fields, INCLUDING the unknown one: the pre-image carries
    # it (RFC 8785 sorts it in lexicographically).
    assert _EXTRA_KEY.encode() in compute_signing_bytes(parsed)
    receipt = _finalize(parsed, priv)

    result = verify_receipt(receipt, priv.public_key())
    assert result.valid is True, "receipt signed over an unknown additive field must verify VALID"
    assert result.receipt_hash_valid is True
    assert result.signature_valid is True
    assert result.reason is None


def test_forward_compat_signature_genuinely_covers_extra_field() -> None:
    """Guard against vacuous pass: the signature must REALLY commit to the
    unknown field. The same receipt with the extra REMOVED produces a
    different pre-image and so fails verification under the same signature.
    """
    priv = Ed25519PrivateKey.generate()

    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    signed_with_extra = _finalize(ReceiptV02.model_validate(body), priv)
    assert verify_receipt(signed_with_extra, priv.public_key()).valid is True

    # Strip the unknown field but KEEP the signature/receipt_hash that were
    # computed over the with-extra pre-image. Pre-image now differs ->
    # INVALID. (Confirms the extra is inside the signed pre-image, not
    # ignored.)
    stripped = ReceiptV02.model_validate(_canon_body()).model_copy(
        update={
            "receipt_hash": signed_with_extra.receipt_hash,
            "signature": signed_with_extra.signature,
        }
    )
    assert not stripped.model_extra
    result = verify_receipt(stripped, priv.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is False


# --------------------------------------------------------------------------
# (c) tamper: take a signed valid receipt, mutate an existing field value
#     WITHOUT re-signing -> INVALID
# --------------------------------------------------------------------------
def test_forward_compat_tampered_existing_field_invalid() -> None:
    priv = Ed25519PrivateKey.generate()

    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    signed = _finalize(ReceiptV02.model_validate(body), priv)
    assert verify_receipt(signed, priv.public_key()).valid is True

    # Mutate an EXISTING canon field value, do NOT re-sign.
    tampered = signed.model_copy(update={"artifact_type": "npm-package"})
    result = verify_receipt(tampered, priv.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is False


def test_forward_compat_tampered_extra_field_invalid() -> None:
    """Tampering the UNKNOWN additive field value after signing also breaks
    verification — the extra is part of the signed pre-image, not free."""
    priv = Ed25519PrivateKey.generate()

    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    signed = _finalize(ReceiptV02.model_validate(body), priv)

    tampered = signed.model_copy(update={_EXTRA_KEY: "trace-TAMPERED"})
    result = verify_receipt(tampered, priv.public_key())
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is False


# --------------------------------------------------------------------------
# Strictness is preserved: forward-compat relaxes ONLY unknown additive
# fields. Missing-required and wrong-typed canon fields stay INVALID.
# --------------------------------------------------------------------------
def test_forward_compat_does_not_relax_missing_required_field() -> None:
    body = _canon_body()
    del body["prev_hash"]  # required canon field absent
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(body)


def test_forward_compat_does_not_relax_required_field_with_extra_present() -> None:
    """Adding an unknown field does NOT excuse a missing required field."""
    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    del body["receipt_id"]  # required canon field absent
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(body)


def test_forward_compat_does_not_relax_wrong_typed_canon_field() -> None:
    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    body["git_commit"] = "0" * 7  # abbreviated SHA — wrong shape, must reject
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(body)


def test_forward_compat_does_not_make_receipt_id_nullable() -> None:
    body = _canon_body()
    body[_EXTRA_KEY] = _EXTRA_VALUE
    body["receipt_id"] = None  # receipt_id must remain non-nullable str
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(body)
