"""Tests for `witseal.verify.chain` — witness-event hash-chain verification."""

from __future__ import annotations

from tests._artifact_builders import finalize_event, two_event_chain
from witseal.integrity.hash_chain import hash_event
from witseal.verify.chain import verify_chain, verify_event_hash


def test_empty_chain_is_vacuously_valid() -> None:
    result = verify_chain([])
    assert result.valid is True
    assert result.chain_head_after is None


def test_valid_two_event_chain() -> None:
    events = two_event_chain()
    result = verify_chain(events)
    assert result.valid is True
    assert result.chain_head_after == events[-1].event_hash
    assert bool(result) is True


def test_verify_event_hash_true_for_finalized_event() -> None:
    events = two_event_chain()
    assert verify_event_hash(events[0]) is True
    assert verify_event_hash(events[1]) is True


def test_tampered_event_hash_breaks_at_index() -> None:
    events = two_event_chain()
    tampered = events[0].model_copy(update={"event_hash": "9" * 64})
    result = verify_chain([tampered, events[1]])
    assert result.valid is False
    assert result.broken_at == 0
    assert "event_hash invalid" in (result.reason or "")


def test_broken_linkage_detected() -> None:
    events = two_event_chain()
    # Re-point event[1].previous_event_hash to a wrong value and re-finalize
    # so its self-hash stays valid but linkage is wrong.
    broken = finalize_event(
        events[1].model_copy(update={"previous_event_hash": "1" * 64})
    )
    result = verify_chain([events[0], broken])
    assert result.valid is False
    assert result.broken_at == 1
    assert "previous_event_hash mismatch" in (result.reason or "")


def test_non_monotonic_sequence_detected() -> None:
    events = two_event_chain()
    # Bump event[1].sequence to 5 (should be 1), keep linkage + self-hash valid.
    bad = finalize_event(events[1].model_copy(update={"sequence": 5}))
    result = verify_chain([events[0], bad])
    assert result.valid is False
    assert result.broken_at == 1
    assert "sequence non-monotonic" in (result.reason or "")


def test_anchor_mismatch_at_genesis() -> None:
    events = two_event_chain()
    # Genesis event has previous_event_hash=None; anchoring at a non-None
    # head must fail at index 0.
    result = verify_chain(events, expected_chain_head_before="2" * 64)
    assert result.valid is False
    assert result.broken_at == 0


def test_event_hash_rule_matches_recompute() -> None:
    events = two_event_chain()
    # The stored event_hash equals hash_event() over the event with the
    # event_hash field omitted (cross-track canon).
    assert events[0].event_hash == hash_event(events[0])
