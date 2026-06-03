"""Tests for `witseal.verify.evidence` — evidence-package verification."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests._artifact_builders import (
    make_evidence_package,
    two_event_chain,
    v01_receipt_dict,
    v02_receipt_dict,
)
from witseal.integrity.hash import sha256_canonical
from witseal.verify.evidence import verify_evidence_package


def _reseal_receipt_hash(receipt: dict[str, object]) -> None:
    """Recompute a v0.1 receipt's self-hash after mutating other fields, so a
    test isolates the cross-check failure rather than tripping the self-hash."""
    receipt["receipt_hash"] = sha256_canonical(
        {k: v for k, v in receipt.items() if k != "receipt_hash"}
    )


def test_valid_v01_package_no_key_required() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    result = verify_evidence_package(pkg)
    assert result.valid is True
    assert result.chain_valid is True
    assert all(r.valid for r in result.receipt_results)


def test_valid_v02_package_with_key() -> None:
    priv = Ed25519PrivateKey.generate()
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v02_receipt_dict(events[0], priv), v02_receipt_dict(events[1], priv)]
    )
    result = verify_evidence_package(pkg, priv.public_key())
    assert result.valid is True
    assert result.chain_valid is True


def test_v02_package_without_key_fails() -> None:
    priv = Ed25519PrivateKey.generate()
    events = two_event_chain()
    pkg = make_evidence_package(events, [v02_receipt_dict(events[0], priv)])
    # chain only has the receipt for event 0; trim events to match cleanly
    pkg["events"] = [events[0].model_dump(by_alias=True)]
    pkg["chain_head_after_range"] = events[0].event_hash
    pkg["range"]["end_sequence"] = 0
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "public key" in (result.reason or "")


def test_tampered_chain_detected() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    pkg["events"][0]["event_hash"] = "9" * 64
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "chain verification failed" in (result.reason or "")
    assert result.chain_valid is False


def test_head_after_range_mismatch_detected() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    pkg["chain_head_after_range"] = "0" * 64
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "chain_head_after_range mismatch" in (result.reason or "")
    assert result.chain_valid is True


def test_receipt_cross_check_mismatch_detected() -> None:
    events = two_event_chain()
    bad_receipt = v01_receipt_dict(events[0])
    bad_receipt["policy_decision_hash"] = "7" * 64  # no longer matches event
    _reseal_receipt_hash(bad_receipt)
    pkg = make_evidence_package(events, [bad_receipt, v01_receipt_dict(events[1])])
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "policy_decision_hash does not match" in (result.reason or "")


def test_receipt_with_no_companion_event_detected() -> None:
    events = two_event_chain()
    orphan = v01_receipt_dict(events[0])
    orphan["witness_event_id"] = "evt_" + "9" * 22
    _reseal_receipt_hash(orphan)
    pkg = make_evidence_package(events, [orphan, v01_receipt_dict(events[1])])
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "no companion event" in (result.reason or "")


def test_receipts_not_array_detected() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(events, [])
    pkg["receipts"] = "not-an-array"
    result = verify_evidence_package(pkg)
    assert result.valid is False
    assert "not an array" in (result.reason or "")


def test_malformed_envelope_detected() -> None:
    result = verify_evidence_package({"schema_version": "witseal.evidence-package.v0.1"})
    assert result.valid is False
    assert "schema validation failed" in (result.reason or "")


def test_tampered_v02_signature_in_package_detected() -> None:
    priv = Ed25519PrivateKey.generate()
    events = two_event_chain()
    receipt = v02_receipt_dict(events[0], priv)
    # flip the algorithm-prefixed signature payload
    import base64

    algorithm, _, payload = receipt["signature"].partition(":")
    raw = base64.b64decode(payload, validate=True)
    flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
    receipt["signature"] = f"{algorithm}:{base64.b64encode(flipped).decode('ascii')}"
    pkg = make_evidence_package(events, [receipt])
    pkg["events"] = [events[0].model_dump(by_alias=True)]
    pkg["chain_head_after_range"] = events[0].event_hash
    pkg["range"]["end_sequence"] = 0
    result = verify_evidence_package(pkg, priv.public_key())
    assert result.valid is False
    assert result.receipt_results[0].valid is False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
