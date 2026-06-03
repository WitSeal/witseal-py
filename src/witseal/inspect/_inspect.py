"""Keyless inspection of WitSeal artifacts — the SDK *consume* surface.

``inspect`` answers "what is this artifact and what can I confirm about it
*without a key*". It parses a receipt or evidence package, summarizes its
salient fields, and reports the integrity checks that need no public key:

- receipt ``receipt_hash`` self-consistency (recomputed over the S1
  pre-image for v0.2, over the body for v0.1);
- evidence-package chain integrity (linkage, self-hashes, sequence
  monotonicity) and head-after-range match.

Checks that DO need a key — Ed25519 signature verification on v0.2 receipts —
are explicitly reported as *not checked here*; use ``verify`` with a public
key for those. Inspection never fails closed on a bad artifact: it returns a
structured report (including ``kind='unknown'`` for unrecognized input) so a
consumer can see what it received.

Read-side only. Python does not generate artifacts ([redacted]).
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from witseal.integrity.hash import sha256_canonical
from witseal.integrity.signing import compute_receipt_hash
from witseal.schemas.evidence_package import EvidencePackage
from witseal.schemas.receipt import ExecutionReceipt, ReceiptV02
from witseal.verify.chain import verify_chain

_RECEIPT_HASH_FIELD = "receipt_hash"


@dataclass(frozen=True, slots=True)
class ArtifactInspection:
    """Structured, keyless summary of a WitSeal artifact.

    ``fields`` holds salient identifiers/values for display. ``integrity``
    holds the keyless checks that were run (name -> bool). ``notes`` lists
    things a consumer should know — notably which checks require a key and
    were therefore not run here.
    """

    kind: str
    schema_version: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, bool] = field(default_factory=dict)
    notes: tuple[str, ...] = field(default_factory=tuple)
    reason: str | None = None


def _read_schema_version(value: Any) -> str | None:  # noqa: ANN401
    if isinstance(value, Mapping):
        sv = value.get("schema_version")
        return sv if isinstance(sv, str) else None
    return None


def _inspect_receipt_v01(value: Mapping[str, Any]) -> ArtifactInspection:
    try:
        receipt = ExecutionReceipt.model_validate(dict(value))
    except (ValidationError, ValueError) as exc:
        return ArtifactInspection(
            kind="receipt.v0.1",
            schema_version="witseal.receipt.v0.1",
            reason=f"schema validation failed: {exc}",
        )
    body = receipt.model_dump(by_alias=True)
    body.pop(_RECEIPT_HASH_FIELD, None)
    receipt_hash_ok = hmac.compare_digest(
        sha256_canonical(body), receipt.receipt_hash
    )
    return ArtifactInspection(
        kind="receipt.v0.1",
        schema_version="witseal.receipt.v0.1",
        fields={
            "receipt_id": receipt.receipt_id,
            "witness_event_id": receipt.witness_event_id,
            "chain_segment_id": receipt.chain_segment_id,
            "outcome": receipt.outcome,
            "finalized_at": receipt.finalized_at,
        },
        integrity={"receipt_hash_self_consistent": receipt_hash_ok},
        notes=("v0.1 receipts are unsigned; no signature check applies.",),
    )


def _inspect_receipt_v02(value: Mapping[str, Any]) -> ArtifactInspection:
    try:
        receipt = ReceiptV02.model_validate(dict(value))
    except (ValidationError, ValueError) as exc:
        return ArtifactInspection(
            kind="receipt.v0.2",
            schema_version="witseal.receipt.v0.2",
            reason=f"schema validation failed: {exc}",
        )
    receipt_hash_ok = hmac.compare_digest(
        compute_receipt_hash(receipt), receipt.receipt_hash
    )
    signature_algorithm = receipt.signature.split(":", 1)[0] if ":" in receipt.signature else None
    return ArtifactInspection(
        kind="receipt.v0.2",
        schema_version="witseal.receipt.v0.2",
        fields={
            "receipt_id": receipt.receipt_id,
            "witness_event_id": receipt.witness_event_id,
            "chain_segment_id": receipt.chain_segment_id,
            "outcome": receipt.outcome,
            "finalized_at": receipt.finalized_at,
            "artifact_type": receipt.artifact_type,
            "build_id": receipt.build_id,
            "git_commit": receipt.git_commit,
            "signature_algorithm": signature_algorithm,
            "is_genesis": receipt.prev_hash is None,
        },
        integrity={"receipt_hash_self_consistent": receipt_hash_ok},
        notes=(
            "signature verification requires a public key; not checked by "
            "inspect — use `verify` with --public-key.",
        ),
    )


def _inspect_evidence(value: Mapping[str, Any]) -> ArtifactInspection:
    envelope_raw = {**value, "receipts": []}
    try:
        envelope = EvidencePackage.model_validate(envelope_raw)
    except (ValidationError, ValueError) as exc:
        return ArtifactInspection(
            kind="evidence-package.v0.1",
            schema_version="witseal.evidence-package.v0.1",
            reason=f"schema validation failed: {exc}",
        )
    chain = verify_chain(envelope.events, envelope.chain_head_before_range)
    recomputed_head = envelope.events[-1].event_hash if envelope.events else None
    head_ok = recomputed_head == envelope.chain_head_after_range
    raw_receipts = value.get("receipts")
    receipt_count = len(raw_receipts) if isinstance(raw_receipts, list) else 0
    return ArtifactInspection(
        kind="evidence-package.v0.1",
        schema_version="witseal.evidence-package.v0.1",
        fields={
            "package_id": envelope.package_id,
            "chain_segment_id": envelope.chain_segment_id,
            "exported_at": envelope.exported_at,
            "range_start": envelope.range.start_sequence,
            "range_end": envelope.range.end_sequence,
            "event_count": len(envelope.events),
            "receipt_count": receipt_count,
            "policy_pack_count": len(envelope.policy_packs),
        },
        integrity={
            "chain_valid": chain.valid,
            "chain_head_after_range_matches": head_ok,
        },
        notes=(
            "receipt signature verification requires a public key; not "
            "checked by inspect — use `verify` with --public-key.",
        )
        + ((f"chain broke at index {chain.broken_at}: {chain.reason}",) if not chain.valid else ()),
    )


def inspect_artifact(value: Mapping[str, Any]) -> ArtifactInspection:
    """Inspect *value* (a parsed JSON mapping) and return a keyless summary.

    Discriminates on ``schema_version``; returns ``kind='unknown'`` for an
    unrecognized artifact rather than raising.
    """
    schema_version = _read_schema_version(value)
    if schema_version == "witseal.receipt.v0.1":
        return _inspect_receipt_v01(value)
    if schema_version == "witseal.receipt.v0.2":
        return _inspect_receipt_v02(value)
    if schema_version == "witseal.evidence-package.v0.1":
        return _inspect_evidence(value)
    reason = (
        "no schema_version field: not a recognized WitSeal artifact"
        if schema_version is None
        else f"unrecognized schema_version '{schema_version}'"
    )
    return ArtifactInspection(
        kind="unknown", schema_version=schema_version, reason=reason
    )
