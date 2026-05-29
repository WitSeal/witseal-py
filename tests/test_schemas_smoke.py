"""Smoke tests for `witseal.schemas` — round-trip a minimal exemplar of each
top-level model and verify wire-format invariants (Optional fields skip on
None; required-nullable fields serialize as `null`)."""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from witseal.schemas import (
    ApprovalOutcome,
    ApprovalPrincipal,
    ApprovalRecord,
    ClassifiedIntent,
    EvidencePackage,
    EvidencePackageRange,
    ExecutionReceipt,
    ExecutionResult,
    FileWriteIntent,
    PolicyDecision,
    PolicyPack,
    PolicyRule,
    PrincipalType,
    Receipt,
    ReceiptV02,
    RiskClass,
    RuleMatch,
    ShellCommandIntent,
    StreamCapture,
    WitnessEvent,
    WitnessEventVersions,
    WitnessOutcome,
)

_HASH = "a" * 64
_HASH2 = "b" * 64
_HASH3 = "c" * 64
_HASH4 = "d" * 64
_HASH5 = "e" * 64
_TS = "2026-05-19T20:00:00Z"
_EVT_ID = "evt_" + "0" * 22
_RCPT_ID = "rcpt_" + "0" * 22
_INT_ID = "int_" + "0" * 22
_APR_ID = "apr_" + "0" * 22
_PKG_ID = "pkg_" + "0" * 22


def _classified_intent() -> ClassifiedIntent:
    return ClassifiedIntent(
        schema_version="witseal.intent.v0.1",
        intent_id=_INT_ID,
        intent=ShellCommandIntent(
            action_type="shell_command",
            executable="ls",
            args=["-la"],
            cwd="/tmp",
        ),
        risk_class=RiskClass.C1,
        classifier_version="v1.0.0",
    )


def _policy_decision() -> PolicyDecision:
    return PolicyDecision(
        schema_version="witseal.policy.v0.1",
        outcome="allow",
        matched_rule=None,
        reason="default_decision",
        active_pack_hashes=[],
    )


def _execution_result() -> ExecutionResult:
    empty_stream = StreamCapture(
        total_bytes=0,
        content_hash=_HASH,
        head=None,
        tail=None,
        head_bytes=0,
        tail_bytes=0,
        truncated=False,
    )
    return ExecutionResult(
        schema_version="witseal.execution.v0.1",
        started_at=_TS,
        finished_at=_TS,
        exit_code=0,
        signal=None,
        stdout=empty_stream,
        stderr=empty_stream,
        executable_resolved="/bin/ls",
        env_keys_hash=_HASH,
        spawn_error=None,
    )


def _witness_event() -> WitnessEvent:
    return WitnessEvent(
        schema_version="witseal.witness.v0.1",
        event_id=_EVT_ID,
        sequence=0,
        timestamp=_TS,
        previous_event_hash=None,
        event_hash=_HASH,
        agent_identifier="agent-1",
        classified_intent=_classified_intent(),
        policy_decision=_policy_decision(),
        approval=None,
        execution_result=_execution_result(),
        outcome=WitnessOutcome.ALLOWED_EXECUTED,
        receipt_id=_RCPT_ID,
        versions=WitnessEventVersions.model_validate(
            {
                "witseal_runtime": "0.0.0",
                "classifier": "v1.0.0",
                "schema": "witseal.witness.v0.1",
            }
        ),
    )


def test_witness_event_roundtrip() -> None:
    event = _witness_event()
    dumped = event.model_dump(by_alias=True)
    assert dumped["schema_version"] == "witseal.witness.v0.1"
    # Required-nullable fields (TS `.nullable()`) DO serialize as `null`.
    # A canonical serializer that distinguishes optional-skip from
    # required-nullable is a Week 2 follow-up; for now `exclude_none=False`
    # preserves the required-nullable shape for wire compatibility tests.
    assert dumped["previous_event_hash"] is None
    assert dumped["approval"] is None
    assert dumped["versions"]["schema"] == "witseal.witness.v0.1"
    restored = WitnessEvent.model_validate(dumped)
    assert restored == event


def test_optional_field_skipped_on_none() -> None:
    intent = ShellCommandIntent(
        action_type="shell_command", executable="ls", args=[], cwd="/tmp"
    )
    dumped = intent.model_dump(exclude_none=True)
    assert "env_keys_passed" not in dumped, (
        "Optional fields MUST be skipped on None, not serialized as null"
    )


def test_invalid_sha256_rejected() -> None:
    with pytest.raises(ValidationError):
        ExecutionReceipt(
            schema_version="witseal.receipt.v0.1",
            receipt_id=_RCPT_ID,
            witness_event_id=_EVT_ID,
            chain_segment_id="default",
            finalized_at=_TS,
            receipt_hash="not-a-hash",
            policy_decision_hash=_HASH,
            classified_intent_hash=_HASH,
            execution_result_hash=None,
            outcome="allowed_executed",
        )


def test_invalid_event_id_rejected() -> None:
    with pytest.raises(ValueError, match="event_id"):
        _ = WitnessEvent(
            schema_version="witseal.witness.v0.1",
            event_id="not-evt",
            sequence=0,
            timestamp=_TS,
            previous_event_hash=None,
            event_hash=_HASH,
            agent_identifier="agent-1",
            classified_intent=_classified_intent(),
            policy_decision=_policy_decision(),
            approval=None,
            execution_result=_execution_result(),
            outcome=WitnessOutcome.ALLOWED_EXECUTED,
            receipt_id=_RCPT_ID,
            versions=WitnessEventVersions.model_validate(
                {
                    "witseal_runtime": "0.0.0",
                    "classifier": "v1.0.0",
                    "schema": "witseal.witness.v0.1",
                }
            ),
        )


def test_intent_discriminated_union() -> None:
    parsed = ClassifiedIntent.model_validate(
        {
            "schema_version": "witseal.intent.v0.1",
            "intent_id": _INT_ID,
            "intent": {
                "action_type": "file_write",
                "path": "/tmp/x",
                "content_hash": "sha256:" + "0" * 64,
                "content_size_bytes": 12,
                "mode": "overwrite",
            },
            "risk_class": "C2",
            "classifier_version": "v1.0.0",
        }
    )
    assert isinstance(parsed.intent, FileWriteIntent)


def test_policy_rule_match_self_reference() -> None:
    pack = PolicyPack(
        schema_version="witseal.policy.v0.1",
        pack_id="default-pack",
        version="0.1.0",
        description="default",
        rules=[
            PolicyRule(
                id="r1",
                match=RuleMatch(
                    any_of=[
                        RuleMatch(risk_class=RiskClass.C4),
                        RuleMatch(action_type=None, command_matches="^rm -rf"),
                    ]
                ),
                decision="deny",
                reason="dangerous",
            )
        ],
    )
    dumped = pack.model_dump(by_alias=True, exclude_none=True)
    assert dumped["rules"][0]["match"]["any_of"][0]["risk_class"] == "C4"


def test_approval_record_optional_reason_skipped() -> None:
    record = ApprovalRecord(
        schema_version="witseal.approval.v0.1",
        approval_id=_APR_ID,
        intent_id=_INT_ID,
        prompted_at=_TS,
        resolved_at=_TS,
        outcome=ApprovalOutcome.APPROVED,
        principal=ApprovalPrincipal(type=PrincipalType.HUMAN, identifier="alice"),
        timeout_seconds=60,
    )
    dumped = record.model_dump(exclude_none=True)
    assert "reason" not in dumped


# ---------------------------------------------------------------------------
# RFC-002 / v0.2 wire-format receipt smoke tests
# ---------------------------------------------------------------------------

_DIGEST = "sha256:" + "a" * 64
_ATTEST = "sha256:" + "b" * 64
_GIT_SHA = "0" * 40
_ED25519_SIG = "ed25519:" + "A" * 86 + "=="


def _receipt_v02_kwargs() -> dict[str, object]:
    return {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": _RCPT_ID,
        "witness_event_id": _EVT_ID,
        "chain_segment_id": "default",
        "finalized_at": _TS,
        "receipt_hash": _HASH,
        "policy_decision_hash": _HASH2,
        "classified_intent_hash": _HASH3,
        "execution_result_hash": _HASH4,
        "outcome": "allowed_executed",
        "artifact_digest": _DIGEST,
        "artifact_type": "generic-binary",
        "build_id": "local",
        "git_commit": _GIT_SHA,
        "attestation_digest": _ATTEST,
        "signature": _ED25519_SIG,
        "prev_hash": _HASH5,
    }


def test_receipt_v02_roundtrip() -> None:
    receipt = ReceiptV02.model_validate(_receipt_v02_kwargs())
    dumped = receipt.model_dump()
    assert dumped["schema_version"] == "witseal.receipt.v0.2"
    assert dumped["artifact_digest"] == _DIGEST
    assert dumped["artifact_type"] == "generic-binary"
    assert dumped["signature"] == _ED25519_SIG
    assert dumped["prev_hash"] == _HASH5
    restored = ReceiptV02.model_validate(dumped)
    assert restored == receipt


def test_receipt_v02_artifact_digest_prefix_required() -> None:
    bad = _receipt_v02_kwargs()
    bad["artifact_digest"] = "a" * 64  # missing sha256: prefix
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_artifact_type_frozen_set() -> None:
    bad = _receipt_v02_kwargs()
    bad["artifact_type"] = "python-package"  # not in RFC-002 § 3 taxonomy
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_git_commit_full_sha_required() -> None:
    bad = _receipt_v02_kwargs()
    bad["git_commit"] = "0" * 7  # abbreviated; RFC-002 § 7.2 forbids
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_signature_padded_base64_required() -> None:
    bad = _receipt_v02_kwargs()
    bad["signature"] = "ed25519:" + "A" * 86  # missing == padding
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_signature_algorithm_prefix_required() -> None:
    """RFC-002 § 6 amendment 2026-05-23: signature value MUST carry an
    'ed25519:' algorithm prefix. Bare base64 (the pre-amendment form) is
    a schema violation."""
    bad = _receipt_v02_kwargs()
    bad["signature"] = "A" * 86 + "=="  # bare base64, no algorithm prefix
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_signature_non_ed25519_algorithm_rejected() -> None:
    """RFC-002 § 6 amendment 2026-05-23: in schema v0.2 the only permitted
    algorithm tag is 'ed25519'. Any other prefix is malformed."""
    bad = _receipt_v02_kwargs()
    bad["signature"] = "ecdsa:" + "A" * 86 + "=="  # wrong algorithm tag
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_required_field_missing_rejected() -> None:
    bad = _receipt_v02_kwargs()
    del bad["prev_hash"]  # strict-required: prev_hash mandatory
    with pytest.raises(ValidationError):
        ReceiptV02.model_validate(bad)


def test_receipt_v02_prev_hash_null_at_genesis_accepted() -> None:
    """the genesis prev_hash rule (Option B): genesis
    receipt carries ``prev_hash = null``; field always emitted, value
    ``null`` at chain genesis (aligned with the ``receipt_id``
    nullable-mandatory precedent RFC-001 v0.2 § 7.1 Path B)."""
    kwargs = _receipt_v02_kwargs()
    kwargs["prev_hash"] = None
    receipt = ReceiptV02.model_validate(kwargs)
    assert receipt.prev_hash is None
    dumped = receipt.model_dump()
    assert "prev_hash" in dumped
    assert dumped["prev_hash"] is None


def test_receipt_discriminated_union_dispatch() -> None:
    adapter: TypeAdapter[Receipt] = TypeAdapter(Receipt)
    v01 = adapter.validate_python(
        {
            "schema_version": "witseal.receipt.v0.1",
            "receipt_id": _RCPT_ID,
            "witness_event_id": _EVT_ID,
            "chain_segment_id": "default",
            "finalized_at": _TS,
            "receipt_hash": _HASH,
            "policy_decision_hash": _HASH2,
            "classified_intent_hash": _HASH3,
            "execution_result_hash": None,
            "outcome": "allowed_executed",
        }
    )
    assert isinstance(v01, ExecutionReceipt)
    v02 = adapter.validate_python(_receipt_v02_kwargs())
    assert isinstance(v02, ReceiptV02)


def test_receipt_v02_dumpable_for_sentinel_canonicalization() -> None:
    """Per the S1 interpretation + golden-receipt construction
    procedure: the S1 pre-image is the canonical body with ``signature``
    cleared to ``""`` and ``receipt_hash`` cleared to the 64-zero
    placeholder. This smoke test asserts the schema permits the
    precondition: full ``model_dump`` succeeds, both fields appear, both
    values are overwriteable in the post-dump dict (the algorithm itself
    is in Phase B :mod:`witseal.integrity.signing`)."""
    receipt = ReceiptV02.model_validate(_receipt_v02_kwargs())
    body = receipt.model_dump()
    assert "signature" in body and "receipt_hash" in body
    body["receipt_hash"] = "0" * 64
    body["signature"] = ""
    assert body["receipt_hash"] == "0" * 64 and body["signature"] == ""


def test_evidence_package_empty() -> None:
    pkg = EvidencePackage(
        schema_version="witseal.evidence-package.v0.1",
        package_id=_PKG_ID,
        exported_at=_TS,
        chain_segment_id="default",
        range=EvidencePackageRange(start_sequence=0, end_sequence=0),
        chain_head_before_range=None,
        chain_head_after_range=_HASH,
        events=[],
        receipts=[],
        policy_packs=[],
        classifier_version="v1.0.0",
        witseal_runtime_version="0.0.0",
    )
    dumped = pkg.model_dump(by_alias=True)
    assert dumped["chain_head_before_range"] is None
    assert dumped["events"] == []


# ---------------------------------------------------------------------------
# RFC-002 §7 (rev2 ratified 2026-05-26) schema additions
# §7.1 — outcome enum gains "no_policy_configured" (evaluation outcome only)
# §7.2 — identity_origin on WitnessEvent + ApprovalPrincipal
# §7.3 — operation_id on WitnessEvent
# All optional. Skip-on-None via @model_serializer (PolicyPack precedent).
# JCS byte-identity preserved for pre-§7 receipts.
# ---------------------------------------------------------------------------


def test_policy_decision_outcome_accepts_no_policy_configured() -> None:
    """§7.1 — `no_policy_configured` is a valid evaluation outcome on
    `PolicyDecision`. Distinct from `allow` per the binding decision
    decision (no-policy mode fails closed; must be distinguishable in
    evidence)."""
    decision = PolicyDecision(
        schema_version="witseal.policy.v0.1",
        outcome="no_policy_configured",
        matched_rule=None,
        reason="no policy loaded; fail-closed default emitted",
        active_pack_hashes=[],
    )
    assert decision.outcome == "no_policy_configured"
    restored = PolicyDecision.model_validate(decision.model_dump())
    assert restored == decision


def test_policy_pack_default_decision_rejects_no_policy_configured() -> None:
    """§7.1 placement guard — `no_policy_configured` is valid ONLY as an
    evaluation outcome on `PolicyDecision`. It is NOT a valid configuration
    value on `PolicyPack.default_decision` (which is itself a configured
    policy state, not the no-policy-loaded state). Enforced by separate
    Literal types on the two fields."""
    with pytest.raises(ValidationError):
        PolicyPack(
            schema_version="witseal.policy.v0.1",
            pack_id="default-pack",
            version="0.1.0",
            description="default",
            rules=[],
            default_decision="no_policy_configured",  # type: ignore[arg-type]
        )


def test_policy_decision_outcome_rejects_unknown_value() -> None:
    """§7.1 — outcome enum remains closed: only the four ratified values
    accepted (allow, deny, require-approval, no_policy_configured)."""
    with pytest.raises(ValidationError):
        PolicyDecision(
            schema_version="witseal.policy.v0.1",
            outcome="bogus",  # type: ignore[arg-type]
            matched_rule=None,
            reason="x",
            active_pack_hashes=[],
        )


def test_witness_event_identity_origin_round_trip_configured() -> None:
    """§7.2 — `identity_origin="configured"` round-trips through dump/load."""
    base = _witness_event()
    event = base.model_copy(update={"identity_origin": "configured"})
    dumped = event.model_dump(by_alias=True)
    assert dumped["identity_origin"] == "configured"
    restored = WitnessEvent.model_validate(dumped)
    assert restored.identity_origin == "configured"


def test_witness_event_identity_origin_round_trip_fallback() -> None:
    """§7.2 — `identity_origin="fallback"` round-trips and is the value
    runtimes MUST emit when identity is not declared by the principal
    (per the binding decision: fallback identity visibly marked
    in evidence/receipt)."""
    base = _witness_event()
    event = base.model_copy(update={"identity_origin": "fallback"})
    dumped = event.model_dump(by_alias=True)
    assert dumped["identity_origin"] == "fallback"
    restored = WitnessEvent.model_validate(dumped)
    assert restored.identity_origin == "fallback"


def test_witness_event_identity_origin_absent_skipped_in_dump() -> None:
    """§7.2 byte-identity invariant — when `identity_origin` is unset (None),
    it MUST NOT appear in `model_dump()` output. PolicyPack `_serialize`
    precedent: skip-on-None via `@model_serializer`. Pre-§7 events
    canonicalize bytewise-identically to post-§7 events that leave the
    field unset."""
    event = _witness_event()
    assert event.identity_origin is None
    dumped = event.model_dump(by_alias=True)
    assert "identity_origin" not in dumped, (
        "absent identity_origin MUST be omitted from canonical bytes, "
        "not serialized as null — JCS byte-identity with pre-§7"
    )


def test_witness_event_identity_origin_rejects_unknown_value() -> None:
    """§7.2 — enum membership enforced: only configured|fallback accepted."""
    base = _witness_event()
    bad = base.model_dump(by_alias=True)
    bad["identity_origin"] = "default"  # not in the Literal
    with pytest.raises(ValidationError):
        WitnessEvent.model_validate(bad)


def test_witness_event_operation_id_round_trip() -> None:
    """§7.3 — `operation_id` accepts any non-empty string; round-trips."""
    base = _witness_event()
    event = base.model_copy(update={"operation_id": "op-2026-05-26-abc123"})
    dumped = event.model_dump(by_alias=True)
    assert dumped["operation_id"] == "op-2026-05-26-abc123"
    restored = WitnessEvent.model_validate(dumped)
    assert restored.operation_id == "op-2026-05-26-abc123"


def test_witness_event_operation_id_absent_skipped_in_dump() -> None:
    """§7.3 byte-identity invariant — unset `operation_id` is omitted from
    canonical bytes (skip-on-None via `@model_serializer`)."""
    event = _witness_event()
    assert event.operation_id is None
    dumped = event.model_dump(by_alias=True)
    assert "operation_id" not in dumped, (
        "absent operation_id MUST be omitted from canonical bytes, "
        "not serialized as null — JCS byte-identity with pre-§7"
    )


def test_witness_event_operation_id_rejects_empty_string() -> None:
    """§7.3 — `operation_id` has `min_length=1` to forbid empty strings
    masquerading as «set» values."""
    base = _witness_event()
    bad = base.model_dump(by_alias=True)
    bad["operation_id"] = ""
    with pytest.raises(ValidationError):
        WitnessEvent.model_validate(bad)


def test_witness_event_pre_s7_canonical_bytes_unchanged() -> None:
    """§7 cross-track byte-identity invariant — a pre-§7 event (constructed
    without specifying either new field) produces canonical JSON bytes
    that are bytewise identical to a hypothetical pre-§7 reference. This
    is the load-bearing test for «receipts without the new fields
    canonicalize identically to pre-§7»."""
    from witseal.integrity.canonical_json import canonicalize

    event = _witness_event()
    dumped = event.model_dump(by_alias=True)
    canonical_bytes = canonicalize(dumped)
    # Neither new key MUST appear in the canonical bytes when unset.
    assert b"identity_origin" not in canonical_bytes
    assert b"operation_id" not in canonical_bytes


def test_approval_principal_identity_origin_round_trip() -> None:
    """§7.2 — `ApprovalPrincipal.identity_origin` round-trips for both
    values."""
    for value in ("configured", "fallback"):
        principal = ApprovalPrincipal(
            type=PrincipalType.HUMAN,
            identifier="alice",
            identity_origin=value,  # type: ignore[arg-type]
        )
        dumped = principal.model_dump()
        assert dumped["identity_origin"] == value
        restored = ApprovalPrincipal.model_validate(dumped)
        assert restored.identity_origin == value


def test_approval_principal_identity_origin_absent_skipped_in_dump() -> None:
    """§7.2 byte-identity invariant on `ApprovalPrincipal` — unset
    `identity_origin` is omitted from canonical bytes (skip-on-None via
    `@model_serializer`)."""
    principal = ApprovalPrincipal(type=PrincipalType.HUMAN, identifier="alice")
    assert principal.identity_origin is None
    dumped = principal.model_dump()
    assert "identity_origin" not in dumped, (
        "absent identity_origin on ApprovalPrincipal MUST be omitted from "
        "canonical bytes — JCS byte-identity with pre-§7"
    )


def test_approval_principal_identity_origin_rejects_unknown_value() -> None:
    """§7.2 — enum membership enforced on `ApprovalPrincipal` too."""
    with pytest.raises(ValidationError):
        ApprovalPrincipal.model_validate(
            {"type": "human", "identifier": "alice", "identity_origin": "synthetic"}
        )


def test_approval_record_with_principal_carrying_identity_origin() -> None:
    """§7.2 — `ApprovalRecord.principal` propagates `identity_origin` through
    nested serialization."""
    record = ApprovalRecord(
        schema_version="witseal.approval.v0.1",
        approval_id=_APR_ID,
        intent_id=_INT_ID,
        prompted_at=_TS,
        resolved_at=_TS,
        outcome=ApprovalOutcome.APPROVED,
        principal=ApprovalPrincipal(
            type=PrincipalType.HUMAN,
            identifier="alice",
            identity_origin="fallback",
        ),
        timeout_seconds=60,
    )
    dumped = record.model_dump(exclude_none=True)
    assert dumped["principal"]["identity_origin"] == "fallback"
