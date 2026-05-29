"""Execution Receipt schema — mirror of TS `schemas/receipt.schema.ts`.

Schema versions:
- `witseal.receipt.v0.1` — pre-Bridge-Proof receipt (current `main`).
- `witseal.receipt.v0.2` — the wire-format spec wire-format v0.2 per receipt-schema
  v0.2 concurrence directive + RFC-002 frozen value sets + clarification
  the prev_hash ruling + a provisional schema (strict-required, all 7 new
  fields mandatory). Lives on `feature/bridge-proof-v0.2-receipt`; `main`
  stays v0.1 until Rust canonical reference lands v0.2.

The two models are union members keyed off `schema_version`; downstream
consumers dispatch via pydantic discriminated union (`Receipt`).
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ._primitives import (
    ArtifactType,
    Ed25519SignaturePrefixed,
    Rfc3339UtcTimestamp,
    Sha1HexFull,
    Sha256DigestPrefixed,
    Sha256Hex,
)

_RECEIPT_ID_RE = re.compile(r"^rcpt_[0-9a-zA-Z]{20,}$")
_EVENT_ID_RE = re.compile(r"^evt_[0-9a-zA-Z]{20,}$")


class ExecutionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.receipt.v0.1"]
    receipt_id: str
    witness_event_id: str
    chain_segment_id: str = Field(min_length=1)
    finalized_at: Rfc3339UtcTimestamp
    receipt_hash: Sha256Hex
    policy_decision_hash: Sha256Hex
    classified_intent_hash: Sha256Hex
    execution_result_hash: Sha256Hex | None
    outcome: str

    def model_post_init(self, _: object) -> None:
        if not _RECEIPT_ID_RE.match(self.receipt_id):
            raise ValueError("receipt_id must match ^rcpt_[0-9a-zA-Z]{20,}$")
        if not _EVENT_ID_RE.match(self.witness_event_id):
            raise ValueError("witness_event_id must match ^evt_[0-9a-zA-Z]{20,}$")


class ReceiptV02(BaseModel):
    """v0.2 wire-format receipt — strict-required per a provisional schema.

    Carries the v0.1 chain/decision fields plus 7 the wire-format spec fields:
    `artifact_digest`, `artifact_type`, `build_id`, `git_commit`,
    `attestation_digest`, `signature`, `prev_hash`. All mandatory in the
    the strict sense — every field is *present* in the wire bytes (`extra=forbid`
    forbids unknown fields; the schema declaration forbids absence). Two
    fields carry `null` semantically — `execution_result_hash` is `null`
    when no result hash is recorded; `prev_hash` is `null` at chain
    genesis (the genesis prev_hash rule (Option B),
    aligned with the `receipt_id` nullable-mandatory precedent RFC-001
    v0.2 § 7.1 Path B). "No skip-empty" addresses field absence, not
    field value — null-valued fields are still emitted on the wire.

    `signature` covers the canonical JSON of this body (the S1 pre-image)
    with `signature` cleared to the empty-string sentinel `""` AND
    `receipt_hash` cleared to its 64-zero placeholder (`"0" * 64`, the wire
    form of a zero SHA-256 digest) — NOT an empty string (the canon
    Interpretation S1; confirmed; the correction;
    golden-receipt construction procedure step 1/4). `receipt_hash` is the
    SHA-256 of that same pre-image. Canonical bytes per RFC 8785 / JCS —
    procedure validated cross-track byte-identical against the golden v0.2
    vector (`tests/test_golden_receipt_v0_2.py`). RFC-002 freezes the
    encoding only.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.receipt.v0.2"]
    receipt_id: str
    witness_event_id: str
    chain_segment_id: str = Field(min_length=1)
    finalized_at: Rfc3339UtcTimestamp
    receipt_hash: Sha256Hex
    policy_decision_hash: Sha256Hex
    classified_intent_hash: Sha256Hex
    execution_result_hash: Sha256Hex | None
    outcome: str
    artifact_digest: Sha256DigestPrefixed
    artifact_type: ArtifactType
    build_id: str = Field(min_length=1)
    git_commit: Sha1HexFull
    attestation_digest: Sha256DigestPrefixed
    signature: Ed25519SignaturePrefixed
    prev_hash: Sha256Hex | None

    def model_post_init(self, _: object) -> None:
        if not _RECEIPT_ID_RE.match(self.receipt_id):
            raise ValueError("receipt_id must match ^rcpt_[0-9a-zA-Z]{20,}$")
        if not _EVENT_ID_RE.match(self.witness_event_id):
            raise ValueError("witness_event_id must match ^evt_[0-9a-zA-Z]{20,}$")


Receipt = Annotated[
    ExecutionReceipt | ReceiptV02,
    Field(discriminator="schema_version"),
]
"""Discriminated union dispatching on `schema_version`. A v0.2 receipt
parses ONLY through the `ReceiptV02` arm; a v0.1 receipt parses ONLY
through the `ExecutionReceipt` arm. No retroactive invalidation of v0.1
per the v0.2 canon."""
