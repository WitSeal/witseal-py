"""Witness-event hash-chain verification — mirror of TS ``verifyChain``.

Walks a sequence of witness events and confirms, at each position:

1. **Linkage** — ``previous_event_hash`` equals the prior event's
   ``event_hash`` (or the anchor ``expected_chain_head_before`` for the
   first event).
2. **Self-hash** — the stored ``event_hash`` matches
   ``SHA-256(canonicalize(event without event_hash))``
   (:func:`witseal.integrity.hash_chain.hash_event`).
3. **Sequence monotonicity** — ``sequence`` increases by exactly 1 from the
   previous event (the first event anchors at its own ``sequence``).

Stops at the first failure, reporting the index and a precise reason — the
same shape and order of checks as the TS reference, so a chain that one
track rejects is rejected at the same position by the other.

Pure read-side function: no key, no I/O, no event generation.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from dataclasses import dataclass

from witseal.integrity.hash_chain import hash_event
from witseal.schemas.witness_event import WitnessEvent


@dataclass(frozen=True, slots=True)
class ChainVerifyResult:
    """Outcome of verifying a witness-event chain segment.

    ``valid`` is the single boolean a caller checks. On failure,
    ``broken_at`` is the 0-based index of the offending event and ``reason``
    is a precise human-readable description. On success, ``chain_head_after``
    is the last event's ``event_hash`` (or ``None`` for an empty segment).
    """

    valid: bool
    broken_at: int | None = None
    reason: str | None = None
    chain_head_after: str | None = None

    def __bool__(self) -> bool:
        return self.valid


def verify_event_hash(event: WitnessEvent) -> bool:
    """Return ``True`` iff *event*'s stored ``event_hash`` is self-consistent.

    Constant-time compare: ``event_hash`` is attacker-influenced wire data.
    """
    expected = hash_event(event)
    return hmac.compare_digest(expected, event.event_hash)


def verify_chain(
    events: Sequence[WitnessEvent],
    expected_chain_head_before: str | None = None,
) -> ChainVerifyResult:
    """Verify a witness-event chain segment.

    *expected_chain_head_before* anchors the first event's
    ``previous_event_hash`` (``None`` for a genesis segment). An empty
    segment is vacuously valid with ``chain_head_after`` equal to the anchor.
    """
    prev_hash: str | None = expected_chain_head_before

    for index, event in enumerate(events):
        # 1. Linkage.
        if event.previous_event_hash != prev_hash:
            return ChainVerifyResult(
                valid=False,
                broken_at=index,
                reason=(
                    f"previous_event_hash mismatch at index {index}: "
                    f"expected {prev_hash}, got {event.previous_event_hash}"
                ),
            )

        # 2. Self-hash.
        if not verify_event_hash(event):
            return ChainVerifyResult(
                valid=False,
                broken_at=index,
                reason=(
                    f"event_hash invalid at index {index} "
                    f"(event_id={event.event_id})"
                ),
            )

        # 3. Sequence monotonicity.
        expected_seq = (
            event.sequence if index == 0 else events[index - 1].sequence + 1
        )
        if event.sequence != expected_seq:
            return ChainVerifyResult(
                valid=False,
                broken_at=index,
                reason=(
                    f"sequence non-monotonic at index {index}: "
                    f"expected {expected_seq}, got {event.sequence}"
                ),
            )

        prev_hash = event.event_hash

    return ChainVerifyResult(valid=True, chain_head_after=prev_hash)
