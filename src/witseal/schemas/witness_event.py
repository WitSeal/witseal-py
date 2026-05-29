"""Witness Event schemas — mirror of TS `schemas/witness-event.schema.ts`.

Schema version: `witseal.witness.v0.1`.

Hashing rule (per ADR-0001 / RFC 8785):
  1. Take this object with `event_hash` field omitted
  2. Canonicalize via JCS (RFC 8785)
  3. SHA-256 the canonical bytes
  4. Hex-encode lowercase, set as `event_hash`
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)

from ._primitives import Rfc3339UtcTimestamp, Sha256Hex
from .approval import ApprovalRecord
from .execution_result import ExecutionResult
from .intent import ClassifiedIntent
from .policy import PolicyDecision

_EVENT_ID_RE = re.compile(r"^evt_[0-9a-zA-Z]{20,}$")
_RECEIPT_ID_RE = re.compile(r"^rcpt_[0-9a-zA-Z]{20,}$")


class WitnessOutcome(StrEnum):
    ALLOWED_EXECUTED = "allowed_executed"
    ALLOWED_EXECUTED_WITH_ERROR = "allowed_executed_with_error"
    APPROVED_EXECUTED = "approved_executed"
    APPROVED_EXECUTED_WITH_ERROR = "approved_executed_with_error"
    DENIED_BY_POLICY = "denied_by_policy"
    DENIED_BY_APPROVAL = "denied_by_approval"
    DENIED_BY_CLASSIFICATION_FAILURE = "denied_by_classification_failure"


class WitnessEventVersions(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    witseal_runtime: str
    classifier: str
    schema_: Literal["witseal.witness.v0.1"] = Field(
        alias="schema", serialization_alias="schema"
    )


class WitnessEvent(BaseModel):
    """Witness event record — append-only entry in the chain.

    Per RFC-002 §7.2 (rev2 ratified 2026-05-26), carries optional
    `identity_origin` flag distinguishing a configured principal identity
    from a runtime fallback (e.g. anonymous, hostname-derived). Absent
    field defaults to «origin not declared» and is omitted from canonical
    bytes — pre-§7 events canonicalize identically.

    Per RFC-002 §7.3 (rev2 ratified 2026-05-26), carries optional
    `operation_id` linking this event to a higher-level operation. Absent
    field is omitted from canonical bytes.

    Both new fields use the `model_serializer` skip-on-None pattern
    (PolicyPack precedent) for byte-identity defense-in-depth — JCS
    canonicalization produces identical bytes regardless of whether
    `model_dump()` is called with or without `exclude_none=True`.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.witness.v0.1"]
    event_id: str
    chain_segment_id: str = Field(default="default", min_length=1)
    sequence: int = Field(ge=0)
    timestamp: Rfc3339UtcTimestamp
    previous_event_hash: Sha256Hex | None
    event_hash: Sha256Hex
    originating_node: str = "local"
    agent_identifier: str = Field(min_length=1)
    identity_origin: Literal["configured", "fallback"] | None = None
    classified_intent: ClassifiedIntent
    policy_decision: PolicyDecision
    approval: ApprovalRecord | None
    execution_result: ExecutionResult | None
    outcome: WitnessOutcome
    receipt_id: str
    operation_id: str | None = Field(default=None, min_length=1)
    versions: WitnessEventVersions

    @model_serializer(mode="wrap")
    def _serialize(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # RFC-002 §7.2 / §7.3 byte-identity invariant: when the new optional
        # fields are unset (None), they MUST be omitted from canonical bytes,
        # not serialized as `null`. Mirrors PolicyPack._serialize precedent
        # for `allow_paths` / `deny_paths`. Pre-§7 events with no
        # `identity_origin` / `operation_id` canonicalize identically.
        if data.get("identity_origin") is None:
            data.pop("identity_origin", None)
        if data.get("operation_id") is None:
            data.pop("operation_id", None)
        return data

    def model_post_init(self, _: object) -> None:
        if not _EVENT_ID_RE.match(self.event_id):
            raise ValueError("event_id must match ^evt_[0-9a-zA-Z]{20,}$")
        if not _RECEIPT_ID_RE.match(self.receipt_id):
            raise ValueError("receipt_id must match ^rcpt_[0-9a-zA-Z]{20,}$")
