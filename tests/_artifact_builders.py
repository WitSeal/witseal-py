"""Shared builders for verify/inspect tests.

Constructs internally-consistent witness events, v0.1 / v0.2 receipts, and
evidence packages so the read-side verifier can be exercised end to end.
These build *test* artifacts in Python only to drive the consume/verify path;
they are not a runtime generator (Python does not generate at runtime —
this is test scaffolding).
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from witseal.integrity.hash import sha256_canonical
from witseal.integrity.hash_chain import hash_event
from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.execution_result import ExecutionResult, StreamCapture
from witseal.schemas.intent import ClassifiedIntent, RiskClass, ShellCommandIntent
from witseal.schemas.policy import PolicyDecision
from witseal.schemas.witness_event import (
    WitnessEvent,
    WitnessEventVersions,
    WitnessOutcome,
)

_TS = "2026-05-19T20:00:00Z"
_HASH = "a" * 64


def classified_intent() -> ClassifiedIntent:
    return ClassifiedIntent(
        schema_version="witseal.intent.v0.1",
        intent_id="int_" + "0" * 22,
        intent=ShellCommandIntent(
            action_type="shell_command", executable="ls", args=["-la"], cwd="/tmp"
        ),
        risk_class=RiskClass.C1,
        classifier_version="v1.0.0",
    )


def policy_decision() -> PolicyDecision:
    return PolicyDecision(
        schema_version="witseal.policy.v0.1",
        outcome="allow",
        matched_rule=None,
        reason="default_decision",
        active_pack_hashes=[],
    )


def execution_result() -> ExecutionResult:
    empty = StreamCapture(
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
        stdout=empty,
        stderr=empty,
        executable_resolved="/bin/ls",
        env_keys_hash=_HASH,
        spawn_error=None,
    )


def _hash_sub(model: Any) -> str:  # noqa: ANN401
    return sha256_canonical(model.model_dump(by_alias=True))


def finalize_event(event: WitnessEvent) -> WitnessEvent:
    """Return *event* with a correct self-consistent ``event_hash``."""
    return event.model_copy(update={"event_hash": hash_event(event)})


def make_event(
    *,
    sequence: int,
    previous_event_hash: str | None,
    event_id: str,
    receipt_id: str,
    ci: ClassifiedIntent,
    pd: PolicyDecision,
    er: ExecutionResult | None,
) -> WitnessEvent:
    draft = WitnessEvent(
        schema_version="witseal.witness.v0.1",
        event_id=event_id,
        chain_segment_id="seg-1",
        sequence=sequence,
        timestamp=_TS,
        previous_event_hash=previous_event_hash,
        event_hash="0" * 64,  # placeholder; replaced by finalize_event
        agent_identifier="agent-1",
        classified_intent=ci,
        policy_decision=pd,
        approval=None,
        execution_result=er,
        outcome=WitnessOutcome.ALLOWED_EXECUTED,
        receipt_id=receipt_id,
        versions=WitnessEventVersions.model_validate(
            {
                "witseal_runtime": "0.0.0",
                "classifier": "v1.0.0",
                "schema": "witseal.witness.v0.1",
            }
        ),
    )
    return finalize_event(draft)


def v01_receipt_dict(event: WitnessEvent) -> dict[str, Any]:
    """A v0.1 receipt whose cross-check hashes match *event* and whose
    ``receipt_hash`` is self-consistent."""
    body: dict[str, Any] = {
        "schema_version": "witseal.receipt.v0.1",
        "receipt_id": event.receipt_id,
        "witness_event_id": event.event_id,
        "chain_segment_id": event.chain_segment_id,
        "finalized_at": _TS,
        "policy_decision_hash": _hash_sub(event.policy_decision),
        "classified_intent_hash": _hash_sub(event.classified_intent),
        "execution_result_hash": (
            _hash_sub(event.execution_result) if event.execution_result else None
        ),
        "outcome": "allowed_executed",
    }
    body["receipt_hash"] = sha256_canonical(body)
    return body


def v02_receipt_dict(
    event: WitnessEvent,
    private_key: Ed25519PrivateKey,
    *,
    prev_hash: str | None = None,
) -> dict[str, Any]:
    """A signed v0.2 receipt whose cross-check hashes match *event*."""
    from witseal.schemas.receipt import ReceiptV02

    base: dict[str, Any] = {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": event.receipt_id,
        "witness_event_id": event.event_id,
        "chain_segment_id": event.chain_segment_id,
        "finalized_at": _TS,
        "receipt_hash": "0" * 64,
        "policy_decision_hash": _hash_sub(event.policy_decision),
        "classified_intent_hash": _hash_sub(event.classified_intent),
        "execution_result_hash": (
            _hash_sub(event.execution_result) if event.execution_result else None
        ),
        "outcome": "allowed_executed",
        "artifact_digest": "sha256:" + "c" * 64,
        "artifact_type": "generic-binary",
        "build_id": "test-build-0001",
        "git_commit": "0" * 40,
        "attestation_digest": "sha256:" + "d" * 64,
        "signature": "ed25519:" + "A" * 86 + "==",
        "prev_hash": prev_hash,
    }
    receipt = ReceiptV02.model_validate(base)
    real_hash = compute_receipt_hash(receipt)
    receipt = receipt.model_copy(update={"receipt_hash": real_hash})
    sig = private_key.sign(compute_signing_bytes(receipt))
    sig_value = "ed25519:" + base64.b64encode(sig).decode("ascii")
    receipt = receipt.model_copy(update={"signature": sig_value})
    return receipt.model_dump(by_alias=True)


def make_evidence_package(
    events: list[WitnessEvent], receipts: list[dict[str, Any]]
) -> dict[str, Any]:
    head_before = events[0].previous_event_hash if events else None
    head_after = events[-1].event_hash if events else (head_before or _HASH)
    return {
        "schema_version": "witseal.evidence-package.v0.1",
        "package_id": "pkg_" + "0" * 22,
        "exported_at": _TS,
        "chain_segment_id": "seg-1",
        "range": {
            "start_sequence": events[0].sequence if events else 0,
            "end_sequence": events[-1].sequence if events else 0,
        },
        "chain_head_before_range": head_before,
        "chain_head_after_range": head_after,
        "events": [e.model_dump(by_alias=True) for e in events],
        "receipts": receipts,
        "policy_packs": [],
        "classifier_version": "v1.0.0",
        "witseal_runtime_version": "0.0.0",
    }


def two_event_chain() -> list[WitnessEvent]:
    e0 = make_event(
        sequence=0,
        previous_event_hash=None,
        event_id="evt_" + "0" * 22,
        receipt_id="rcpt_" + "0" * 22,
        ci=classified_intent(),
        pd=policy_decision(),
        er=execution_result(),
    )
    e1 = make_event(
        sequence=1,
        previous_event_hash=e0.event_hash,
        event_id="evt_" + "1" * 22,
        receipt_id="rcpt_" + "1" * 22,
        ci=classified_intent(),
        pd=policy_decision(),
        er=execution_result(),
    )
    return [e0, e1]
