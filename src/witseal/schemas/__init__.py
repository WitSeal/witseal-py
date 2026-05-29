"""WitSeal canonical schemas — Pydantic v2 mirror of TS reference.

Schema versions tracked here mirror TS `schemas/*.schema.ts`. TS behavior wins
on any cross-track ambiguity (per spec § 0). Wire-format invariants
(per the wire-format spec):

- Optional fields skip on `None` (NOT serialized as `null`).
  Use `model_dump(exclude_none=True)` for canonical output.
- Required-nullable fields (e.g. `previous_event_hash`, `approval`,
  `execution_result`) DO serialize `null`. Keep them required and
  exclude only via field name when needed.
- `execution_lost` (when added in v0.2) is self-contained: classified_intent,
  policy_decision, approval are copied — not referenced.
"""

from __future__ import annotations

from ._primitives import (
    ArtifactType,
    Ed25519SignaturePrefixed,
    Rfc3339UtcTimestamp,
    Sha1HexFull,
    Sha256DigestPrefixed,
    Sha256Hex,
    VerifierReason,
)
from .approval import (
    ApprovalOutcome,
    ApprovalPrincipal,
    ApprovalRecord,
    PrincipalType,
)
from .evidence_package import EvidencePackage, EvidencePackageRange
from .execution_result import ExecutionResult, StreamCapture
from .intent import (
    ActionType,
    ClassifiedIntent,
    FileReadIntent,
    FileWriteIntent,
    Intent,
    RiskClass,
    ShellCommandIntent,
)
from .policy import (
    ActivePackHash,
    MatchedRule,
    PolicyDecision,
    PolicyPack,
    PolicyRule,
    PolicyRuleExamples,
    RuleMatch,
)
from .receipt import ExecutionReceipt, Receipt, ReceiptV02
from .witness_event import WitnessEvent, WitnessEventVersions, WitnessOutcome

__all__ = [
    "ActionType",
    "ActivePackHash",
    "ApprovalOutcome",
    "ApprovalPrincipal",
    "ApprovalRecord",
    "ArtifactType",
    "ClassifiedIntent",
    "Ed25519SignaturePrefixed",
    "EvidencePackage",
    "EvidencePackageRange",
    "ExecutionReceipt",
    "ExecutionResult",
    "FileReadIntent",
    "FileWriteIntent",
    "Intent",
    "MatchedRule",
    "PolicyDecision",
    "PolicyPack",
    "PolicyRule",
    "PolicyRuleExamples",
    "PrincipalType",
    "Receipt",
    "ReceiptV02",
    "Rfc3339UtcTimestamp",
    "RiskClass",
    "RuleMatch",
    "Sha1HexFull",
    "Sha256DigestPrefixed",
    "Sha256Hex",
    "ShellCommandIntent",
    "StreamCapture",
    "VerifierReason",
    "WitnessEvent",
    "WitnessEventVersions",
    "WitnessOutcome",
]
