"""Tests for `witseal.verify.artifact` — unified discriminating verifier."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tests._artifact_builders import (
    make_evidence_package,
    two_event_chain,
    v01_receipt_dict,
)
from witseal.verify.artifact import verify_artifact

_FIXTURES = Path(__file__).parent / "fixtures" / "golden-receipt"
_GOLDEN_JSON = _FIXTURES / "rust-golden.json"
_PUBLIC_KEY_HEX = "fd62f46e4e64333ef4c0693e9caf52a540cb21a3546547f016bcd0e990c91862"


def _golden_public_key() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(_PUBLIC_KEY_HEX))


def test_discriminates_v02_receipt_valid() -> None:
    data = json.loads(_GOLDEN_JSON.read_text())
    result = verify_artifact(data, _golden_public_key())
    assert result.valid is True
    assert result.kind == "receipt.v0.2"
    assert result.schema_version == "witseal.receipt.v0.2"


def test_v02_receipt_without_key_fails_clearly() -> None:
    data = json.loads(_GOLDEN_JSON.read_text())
    result = verify_artifact(data)
    assert result.valid is False
    assert result.kind == "receipt.v0.2"
    assert "public key" in (result.reason or "")


def test_discriminates_v01_receipt_self_hash() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = verify_artifact(receipt)
    assert result.valid is True
    assert result.kind == "receipt.v0.1"


def test_v01_receipt_tampered_self_hash_fails() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    receipt["receipt_hash"] = "9" * 64
    result = verify_artifact(receipt)
    assert result.valid is False
    assert result.kind == "receipt.v0.1"
    assert "self-hash" in (result.reason or "")


def test_discriminates_evidence_package() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    result = verify_artifact(pkg)
    assert result.valid is True
    assert result.kind == "evidence-package.v0.1"


def test_unknown_schema_version() -> None:
    result = verify_artifact({"schema_version": "witseal.bogus.v9"})
    assert result.valid is False
    assert result.kind == "unknown"
    assert "unrecognized schema_version" in (result.reason or "")


def test_missing_schema_version() -> None:
    result = verify_artifact({"not": "a witseal artifact"})
    assert result.valid is False
    assert result.kind == "unknown"
    assert "no schema_version" in (result.reason or "")
