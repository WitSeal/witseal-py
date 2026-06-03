"""Evidence-package verification — mirror of TS ``verifyEvidencePackageObject``.

An evidence package bundles a witness-event chain segment, the receipts
paired with those events, and the policy packs that were active. Verifying a
package (read-side, consume role) means, in order:

1. **Envelope** — structural schema parse (package id, timestamps, range,
   events, policy packs).
2. **Chain** — :func:`witseal.verify.chain.verify_chain` over the events,
   anchored at ``chain_head_before_range``.
3. **Head** — ``chain_head_after_range`` equals the recomputed head (the last
   event's ``event_hash``, or the anchor for an empty segment).
4. **Receipts** — each receipt is discriminated by its own ``schema_version``
   (v0.1 / v0.2), validated, resolved to its companion event by
   ``witness_event_id``, and cross-checked: its hash references must match the
   companion event, and a v0.2 receipt additionally needs a valid Ed25519
   signature (so the package verifier requires a public key only when it
   contains a v0.2 receipt).

The envelope's ``receipts`` array is typed against the v0.1 receipt in the
frozen package schema; a package may legitimately carry v0.2 receipts, so —
exactly as the TS layer does — this verifier parses the envelope with the
receipts array emptied and then discriminates the real receipts per element.

Python never builds an evidence package at runtime (generation is the Rust
track); this is the consume/verify path only.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import TypeAdapter, ValidationError

from witseal.integrity.hash import sha256_canonical
from witseal.schemas.evidence_package import EvidencePackage
from witseal.schemas.receipt import ExecutionReceipt, Receipt, ReceiptV02
from witseal.schemas.witness_event import WitnessEvent
from witseal.verify.chain import verify_chain
from witseal.verify.receipt import verify_receipt

_RECEIPT_ADAPTER: TypeAdapter[ExecutionReceipt | ReceiptV02] = TypeAdapter(Receipt)
_RECEIPT_HASH_FIELD = "receipt_hash"


@dataclass(frozen=True, slots=True)
class ReceiptSubResult:
    """Per-receipt outcome within an evidence-package verification."""

    index: int
    valid: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceVerifyResult:
    """Outcome of verifying an evidence package.

    ``valid`` is ``True`` iff the envelope parses, the chain verifies, the
    declared head matches the recomputed head, and every receipt verifies
    against its companion event.
    """

    valid: bool
    kind: str = "evidence-package.v0.1"
    reason: str | None = None
    chain_valid: bool = False
    chain_head_after: str | None = None
    receipt_results: tuple[ReceiptSubResult, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return self.valid


def _hash_subobject(model: Any) -> str:  # noqa: ANN401
    """SHA-256 hex of the RFC 8785 canonical form of a sub-model's wire dict."""
    return sha256_canonical(model.model_dump(by_alias=True))


def _cross_check_against_event(
    receipt: ExecutionReceipt | ReceiptV02, event: WitnessEvent
) -> str | None:
    """Return a failure reason if *receipt*'s hash references do not match its
    companion *event*, else ``None``.

    Mirrors the TS ``crossCheckAgainstEvent``: confirms the receipt actually
    describes the event it is paired with. ``execution_result_hash`` may be
    ``None`` (denied / execution_lost); when present it must match.
    """
    if receipt.classified_intent_hash != _hash_subobject(event.classified_intent):
        return "classified_intent_hash does not match companion event"
    if receipt.policy_decision_hash != _hash_subobject(event.policy_decision):
        return "policy_decision_hash does not match companion event"
    if receipt.execution_result_hash is not None:
        expected = (
            _hash_subobject(event.execution_result)
            if event.execution_result is not None
            else None
        )
        if receipt.execution_result_hash != expected:
            return "execution_result_hash does not match companion event"
    return None


def _verify_package_receipt(
    raw: object,
    events_by_id: Mapping[str, WitnessEvent],
    public_key: Ed25519PublicKey | None,
) -> str | None:
    """Verify one receipt drawn from a package. Returns a failure reason or
    ``None`` on success. Discriminates on the receipt's own schema_version.
    """
    try:
        receipt = _RECEIPT_ADAPTER.validate_python(raw)
    except ValidationError as exc:
        return f"schema validation failed: {exc.error_count()} error(s)"

    event = events_by_id.get(receipt.witness_event_id)
    if event is None:
        return (
            f"witness_event_id {receipt.witness_event_id} has no companion "
            "event in the package"
        )

    if isinstance(receipt, ReceiptV02):
        if public_key is None:
            return "v0.2 receipt in package requires a public key (none supplied)"
        try:
            sig = verify_receipt(receipt, public_key)
        except ValueError as exc:
            return f"invalid receipt signature encoding: {exc}"
        if not sig.valid:
            return sig.reason or "v0.2 receipt verification failed"
    else:
        # v0.1 receipt: unsigned, so the self-hash is the integrity gate
        # (mirrors TS verifyReceipt's receipt_hash check) before cross-ref.
        body = receipt.model_dump(by_alias=True)
        body.pop(_RECEIPT_HASH_FIELD, None)
        if not hmac.compare_digest(sha256_canonical(body), receipt.receipt_hash):
            return "receipt_hash invalid (self-hash check failed)"

    return _cross_check_against_event(receipt, event)


def verify_evidence_package(
    raw: Mapping[str, Any],
    public_key: Ed25519PublicKey | None = None,
) -> EvidenceVerifyResult:
    """Verify an evidence package given its raw parsed JSON mapping.

    *public_key* is required only if the package contains a v0.2 receipt;
    a package of v0.1 receipts verifies without one.
    """
    # 1. Envelope (parse with receipts emptied — the frozen package schema
    #    types receipts as v0.1; real receipts are discriminated per element).
    envelope_raw = {**raw, "receipts": []}
    try:
        envelope = EvidencePackage.model_validate(envelope_raw)
    except (ValidationError, ValueError) as exc:
        return EvidenceVerifyResult(
            valid=False, reason=f"schema validation failed: {exc}"
        )

    # 2. Chain.
    chain = verify_chain(envelope.events, envelope.chain_head_before_range)
    if not chain.valid:
        return EvidenceVerifyResult(
            valid=False,
            reason=f"chain verification failed: {chain.reason}",
            chain_valid=False,
        )

    # 3. Head-after-range must match the recomputed head.
    recomputed_head = (
        envelope.events[-1].event_hash if envelope.events else None
    )
    if recomputed_head != envelope.chain_head_after_range:
        return EvidenceVerifyResult(
            valid=False,
            reason=(
                f"chain_head_after_range mismatch: declared "
                f"{envelope.chain_head_after_range}, recomputed {recomputed_head}"
            ),
            chain_valid=True,
            chain_head_after=chain.chain_head_after,
        )

    # 4. Per-receipt integrity.
    raw_receipts = raw.get("receipts")
    if not isinstance(raw_receipts, list):
        return EvidenceVerifyResult(
            valid=False,
            reason="receipts: missing or not an array",
            chain_valid=True,
            chain_head_after=chain.chain_head_after,
        )

    events_by_id = {ev.event_id: ev for ev in envelope.events}
    sub_results: list[ReceiptSubResult] = []
    first_failure: ReceiptSubResult | None = None
    for index, raw_receipt in enumerate(raw_receipts):
        reason = _verify_package_receipt(raw_receipt, events_by_id, public_key)
        sub = ReceiptSubResult(index=index, valid=reason is None, reason=reason)
        sub_results.append(sub)
        if not sub.valid and first_failure is None:
            first_failure = sub

    if first_failure is not None:
        return EvidenceVerifyResult(
            valid=False,
            reason=(
                f"receipt[{first_failure.index}] verification failed: "
                f"{first_failure.reason}"
            ),
            chain_valid=True,
            chain_head_after=chain.chain_head_after,
            receipt_results=tuple(sub_results),
        )

    return EvidenceVerifyResult(
        valid=True,
        chain_valid=True,
        chain_head_after=chain.chain_head_after,
        receipt_results=tuple(sub_results),
    )
