"""Evidence Package schema — mirror of TS `schemas/evidence-package.schema.ts`.

Schema version: `witseal.evidence-package.v0.1`.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ._primitives import Rfc3339UtcTimestamp, Sha256Hex
from .policy import PolicyPack
from .receipt import ExecutionReceipt
from .witness_event import WitnessEvent

_PACKAGE_ID_RE = re.compile(r"^pkg_[0-9a-zA-Z]{20,}$")


class EvidencePackageRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_sequence: int = Field(ge=0)
    end_sequence: int = Field(ge=0)


class EvidencePackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.evidence-package.v0.1"]
    package_id: str
    exported_at: Rfc3339UtcTimestamp
    chain_segment_id: str
    range: EvidencePackageRange
    chain_head_before_range: Sha256Hex | None
    chain_head_after_range: Sha256Hex
    events: list[WitnessEvent]
    receipts: list[ExecutionReceipt]
    policy_packs: list[PolicyPack]
    classifier_version: str
    witseal_runtime_version: str

    def model_post_init(self, _: object) -> None:
        if not _PACKAGE_ID_RE.match(self.package_id):
            raise ValueError("package_id must match ^pkg_[0-9a-zA-Z]{20,}$")
