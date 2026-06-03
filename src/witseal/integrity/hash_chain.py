"""Witness-event hashing primitive — mirror of TS `src/integrity/hash-chain.ts`.

The witness-event hash chain links events via ``previous_event_hash``; each
event self-attests via ``event_hash``. The hashing rule (cross-track canon,
wire-format spec § 3.3 / TS ``hashEvent``):

    event_hash = SHA-256( canonicalize( event WITHOUT the event_hash field ) )

The ``event_hash`` key is OMITTED entirely from the pre-image — not set to
``null``, not set to ``""`` — exactly as the TS reference strips it
(``const { event_hash, ...draft } = event``). Canonicalization is RFC 8785
via :func:`witseal.integrity.canonical_json.canonicalize`, the same
byte-identity-proven canonicalizer used for the golden receipt
(``8fc29592…``). Because event_hash is a deterministic composition over that
canonicalizer with a fixed field-omission rule, an event_hash computed here
matches the value any conforming track (TS / Rust) computes for the same
event bytes.

Python is the ecosystem-facing SDK: it *consumes and verifies* events, it
does not generate them at runtime. This module is the read-side primitive
the chain verifier (:mod:`witseal.verify.chain`) builds on.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from witseal.integrity.canonical_json import canonicalize
from witseal.integrity.hash import sha256_hex_of_bytes
from witseal.schemas.witness_event import WitnessEvent

EVENT_HASH_FIELD: str = "event_hash"
PREVIOUS_EVENT_HASH_FIELD: str = "previous_event_hash"


def _event_body(event: WitnessEvent | Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical wire dict of *event* (by-alias), as a plain dict.

    Accepts a parsed :class:`WitnessEvent` (preferred — the §7 model
    serializer applies, so unset ``identity_origin`` / ``operation_id`` are
    omitted, preserving pre-§7 byte-identity) or a raw mapping (used when a
    caller already holds wire bytes and only needs the hash recomputation).
    """
    if isinstance(event, WitnessEvent):
        return event.model_dump(by_alias=True)
    return dict(event)


def hash_event(event: WitnessEvent | Mapping[str, Any]) -> str:
    """Compute the ``event_hash`` for *event* (lowercase hex).

    Strips the ``event_hash`` field, canonicalizes the remainder per
    RFC 8785, and returns the SHA-256 hex. The input is never mutated.
    """
    body = _event_body(event)
    body.pop(EVENT_HASH_FIELD, None)
    return sha256_hex_of_bytes(canonicalize(body))
