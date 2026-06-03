"""Tests for `witseal.inspect` — keyless artifact inspection."""

from __future__ import annotations

import json
from pathlib import Path

from tests._artifact_builders import (
    make_evidence_package,
    two_event_chain,
    v01_receipt_dict,
)
from witseal.inspect import inspect_artifact

_FIXTURES = Path(__file__).parent / "fixtures" / "golden-receipt"
_GOLDEN_JSON = _FIXTURES / "rust-golden.json"


def test_inspect_v02_receipt_keyless_hash_ok() -> None:
    data = json.loads(_GOLDEN_JSON.read_text())
    insp = inspect_artifact(data)
    assert insp.kind == "receipt.v0.2"
    assert insp.integrity["receipt_hash_self_consistent"] is True
    assert insp.fields["signature_algorithm"] == "ed25519"
    assert insp.fields["is_genesis"] is True  # golden prev_hash is null
    # signature is NOT checked by inspect (no key)
    assert any("signature" in note for note in insp.notes)
    assert insp.reason is None


def test_inspect_v02_receipt_detects_bad_hash_without_key() -> None:
    data = json.loads(_GOLDEN_JSON.read_text())
    data["receipt_hash"] = "9" * 64
    insp = inspect_artifact(data)
    assert insp.kind == "receipt.v0.2"
    assert insp.integrity["receipt_hash_self_consistent"] is False


def test_inspect_v01_receipt() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    insp = inspect_artifact(receipt)
    assert insp.kind == "receipt.v0.1"
    assert insp.integrity["receipt_hash_self_consistent"] is True
    assert insp.fields["receipt_id"] == events[0].receipt_id
    assert any("unsigned" in note for note in insp.notes)


def test_inspect_evidence_package_chain_ok() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    insp = inspect_artifact(pkg)
    assert insp.kind == "evidence-package.v0.1"
    assert insp.integrity["chain_valid"] is True
    assert insp.integrity["chain_head_after_range_matches"] is True
    assert insp.fields["event_count"] == 2
    assert insp.fields["receipt_count"] == 2


def test_inspect_evidence_package_detects_broken_chain_keyless() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(events, [])
    pkg["events"][0]["event_hash"] = "9" * 64
    insp = inspect_artifact(pkg)
    assert insp.kind == "evidence-package.v0.1"
    assert insp.integrity["chain_valid"] is False
    assert any("chain broke" in note for note in insp.notes)


def test_inspect_unknown_artifact() -> None:
    insp = inspect_artifact({"foo": "bar"})
    assert insp.kind == "unknown"
    assert insp.reason is not None
