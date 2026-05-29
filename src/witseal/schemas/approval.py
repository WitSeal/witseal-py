"""Approval Record schemas — mirror of TS `schemas/approval.schema.ts`.

Schema version: `witseal.approval.v0.1`.
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

from ._primitives import Rfc3339UtcTimestamp

_APPROVAL_ID_RE = re.compile(r"^apr_[0-9a-zA-Z]{20,}$")
_INTENT_ID_RE = re.compile(r"^int_[0-9a-zA-Z]{20,}$")


class PrincipalType(StrEnum):
    HUMAN = "human"
    CI = "ci"


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ApprovalPrincipal(BaseModel):
    """Approval principal — identity that granted/rejected an approval.

    Per RFC-002 §7.2 (rev2 ratified 2026-05-26), carries optional
    `identity_origin` flag distinguishing a configured principal identity
    from a runtime fallback (e.g. anonymous, hostname-derived). Absent
    field is omitted from canonical bytes via the `model_serializer`
    skip-on-None pattern (PolicyPack precedent) — pre-§7 approval records
    canonicalize identically.
    """

    model_config = ConfigDict(extra="forbid")

    type: PrincipalType
    identifier: str = Field(min_length=1)
    identity_origin: Literal["configured", "fallback"] | None = None

    @model_serializer(mode="wrap")
    def _serialize(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # RFC-002 §7.2 byte-identity invariant: unset `identity_origin` is
        # omitted from canonical bytes, not serialized as `null`. Mirrors
        # PolicyPack._serialize precedent.
        if data.get("identity_origin") is None:
            data.pop("identity_origin", None)
        return data


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.approval.v0.1"]
    approval_id: str
    intent_id: str
    prompted_at: Rfc3339UtcTimestamp
    resolved_at: Rfc3339UtcTimestamp
    outcome: ApprovalOutcome
    principal: ApprovalPrincipal
    reason: str | None = Field(default=None, max_length=1024)
    timeout_seconds: int = Field(gt=0)

    def model_post_init(self, _: object) -> None:
        if not _APPROVAL_ID_RE.match(self.approval_id):
            raise ValueError("approval_id must match ^apr_[0-9a-zA-Z]{20,}$")
        if not _INTENT_ID_RE.match(self.intent_id):
            raise ValueError("intent_id must match ^int_[0-9a-zA-Z]{20,}$")
