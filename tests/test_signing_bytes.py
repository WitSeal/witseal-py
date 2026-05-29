"""Tests for `witseal.integrity.signing.compute_signing_bytes`.

Per the cross-track S1 canon, reconciled with the
golden-receipt construction procedure (``inputs.json`` step 1/4): the S1
pre-image is the canonical JSON of the v0.2 receipt body with
``signature`` cleared to the empty-string sentinel ``""`` AND
``receipt_hash`` cleared to its 64-zero placeholder (``"0" * 64``, the
wire form of a zero SHA-256 digest) — NOT an empty string. Both fields
are PRESENT in the canonical output; all other v0.2 fields carry their
populated values.
"""

from __future__ import annotations

import json

import pytest

from witseal.integrity.canonical_json import canonicalize
from witseal.integrity.signing import (
    RECEIPT_HASH_PLACEHOLDER,
    SIGNATURE_PLACEHOLDER,
    compute_signing_bytes,
)
from witseal.schemas.receipt import ReceiptV02

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
_ED25519_SIG = "ed25519:" + "A" * 86 + "=="


def _receipt_v02() -> ReceiptV02:
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
            "signature": _ED25519_SIG,
            "prev_hash": _HASH5,
        }
    )


def test_signing_bytes_returns_bytes() -> None:
    out = compute_signing_bytes(_receipt_v02())
    assert isinstance(out, bytes)
    assert len(out) > 0


def test_signing_bytes_sets_signature_to_empty_string_sentinel() -> None:
    out = compute_signing_bytes(_receipt_v02())
    decoded = json.loads(out.decode("utf-8"))
    assert decoded["signature"] == "", (
        "the S1 interpretation: signature MUST be cleared to empty-string "
        "sentinel in signing bytes (present, value '')"
    )
    assert SIGNATURE_PLACEHOLDER == ""


def test_signing_bytes_sets_receipt_hash_to_zero_placeholder() -> None:
    out = compute_signing_bytes(_receipt_v02())
    decoded = json.loads(out.decode("utf-8"))
    assert decoded["receipt_hash"] == "0" * 64, (
        "Golden-receipt construction procedure step 1: receipt_hash MUST be "
        "cleared to the 64-zero placeholder (wire form of Sha256Hash::zero()) "
        "in the S1 pre-image — NOT an empty string"
    )
    assert RECEIPT_HASH_PLACEHOLDER == "0" * 64
    assert decoded["receipt_hash"] != "", (
        "regression guard: the pre-2026-05 empty-string sentinel for "
        "receipt_hash does NOT reproduce the golden v0.2 vector"
    )


def test_signing_bytes_includes_all_v02_fields_with_two_cleared() -> None:
    out = compute_signing_bytes(_receipt_v02())
    decoded = json.loads(out.decode("utf-8"))
    expected_fields = {
        "schema_version",
        "receipt_id",
        "witness_event_id",
        "chain_segment_id",
        "finalized_at",
        "receipt_hash",
        "policy_decision_hash",
        "classified_intent_hash",
        "execution_result_hash",
        "outcome",
        "artifact_digest",
        "artifact_type",
        "build_id",
        "git_commit",
        "attestation_digest",
        "signature",
        "prev_hash",
    }
    assert set(decoded.keys()) == expected_fields


def test_signing_bytes_deterministic_across_calls() -> None:
    receipt = _receipt_v02()
    a = compute_signing_bytes(receipt)
    b = compute_signing_bytes(receipt)
    assert a == b


def test_signing_bytes_matches_canonicalize_of_cleared_body() -> None:
    receipt = _receipt_v02()
    body = receipt.model_dump(by_alias=True)
    body["receipt_hash"] = "0" * 64
    body["signature"] = ""
    assert compute_signing_bytes(receipt) == canonicalize(body)


def test_signing_bytes_emits_explicit_null_for_genesis_prev_hash() -> None:
    """the genesis prev_hash rule (Option B): at chain
    genesis ``prev_hash = null`` and the field MUST be emitted as explicit
    ``null`` in the canonical signing bytes (never absent). "no
    skip-empty" addresses field absence, not value — null-valued required
    fields are still on the wire."""
    receipt = _receipt_v02().model_copy(update={"prev_hash": None})
    out = compute_signing_bytes(receipt)
    decoded = json.loads(out.decode("utf-8"))
    assert "prev_hash" in decoded, "prev_hash field MUST be present at genesis"
    assert decoded["prev_hash"] is None, (
        "Option B: genesis prev_hash value is explicit null"
    )


def test_signing_bytes_emits_explicit_null_for_execution_result_hash() -> None:
    """strict-required: ``execution_result_hash`` (nullable) is on the
    wire as explicit ``null`` when no result is recorded; never absent."""
    receipt = _receipt_v02().model_copy(update={"execution_result_hash": None})
    out = compute_signing_bytes(receipt)
    decoded = json.loads(out.decode("utf-8"))
    assert "execution_result_hash" in decoded
    assert decoded["execution_result_hash"] is None


def test_signing_bytes_genesis_byte_identical_across_calls() -> None:
    """Genesis-prev_hash byte-identity is the cross-track demonstration
    surface; the canonical bytes must be deterministic across calls."""
    a = compute_signing_bytes(_receipt_v02().model_copy(update={"prev_hash": None}))
    b = compute_signing_bytes(_receipt_v02().model_copy(update={"prev_hash": None}))
    assert a == b


def test_signing_bytes_changes_when_body_changes() -> None:
    a = compute_signing_bytes(_receipt_v02())
    mutated = _receipt_v02()
    mutated = mutated.model_copy(update={"build_id": "different"})
    b = compute_signing_bytes(mutated)
    assert a != b


def test_signing_bytes_unchanged_when_only_signature_changes() -> None:
    receipt_a = _receipt_v02()
    receipt_b = receipt_a.model_copy(update={"signature": "ed25519:" + "B" * 86 + "=="})
    assert compute_signing_bytes(receipt_a) == compute_signing_bytes(receipt_b), (
        "signature is cleared to '' sentinel in signing bytes — changing the "
        "stored value must not alter the canonical pre-image"
    )


def test_signing_bytes_unchanged_when_only_receipt_hash_changes() -> None:
    receipt_a = _receipt_v02()
    receipt_b = receipt_a.model_copy(update={"receipt_hash": "9" * 64})
    assert compute_signing_bytes(receipt_a) == compute_signing_bytes(receipt_b), (
        "receipt_hash is cleared to '' sentinel in signing bytes — changing "
        "the stored value must not alter the canonical pre-image"
    )


def test_signing_bytes_key_order_canonical() -> None:
    """RFC 8785 sorts keys by UTF-16 code unit. Verify by checking that the
    output starts with the lowest-sorting key (`artifact_digest`)."""
    out = compute_signing_bytes(_receipt_v02())
    assert out.startswith(b'{"artifact_digest":'), out[:64]


def test_signing_bytes_stable_under_field_insertion_order() -> None:
    """Pydantic constructors don't reorder fields, but the canonicalizer
    must produce identical output regardless of source dict order."""
    base_kwargs = {
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
        "signature": _ED25519_SIG,
        "prev_hash": _HASH5,
    }
    reordered_kwargs = dict(reversed(base_kwargs.items()))
    a = compute_signing_bytes(ReceiptV02.model_validate(base_kwargs))
    b = compute_signing_bytes(ReceiptV02.model_validate(reordered_kwargs))
    assert a == b


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("prev_hash", "9" * 64),
        ("attestation_digest", "sha256:" + "9" * 64),
        ("artifact_digest", "sha256:" + "9" * 64),
        ("git_commit", "f" * 40),
        ("artifact_type", "npm-package"),
        ("build_id", "ci-1234"),
        ("outcome", "denied_pre_classification"),
    ],
)
def test_signing_bytes_sensitive_to_any_signed_field(
    field: str, new_value: str
) -> None:
    a = compute_signing_bytes(_receipt_v02())
    b = compute_signing_bytes(_receipt_v02().model_copy(update={field: new_value}))
    assert a != b, f"changing {field} must alter signing bytes"
