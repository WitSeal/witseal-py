"""Conservative receipt redaction for shareable evidence packs.

WitSeal receipts are hash-based by design — classified intent, policy
decision and execution result are carried as SHA-256 digests, so a receipt
already discloses no raw source content. Redaction here is therefore a thin,
honest extra step for the *sample copies* placed in a pack:

- any non-canonical (unknown additive) field is replaced with a placeholder;
- a configurable set of canon fields (default: ``git_commit``, ``build_id``)
  is masked, since they can reveal internal build specifics.

Redacted copies are for human review only and are intentionally NOT
re-verifiable — verification is always performed on the ORIGINAL receipts
(see :mod:`witseal_grc.pack`) before redaction, and recorded separately.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from witseal.schemas.receipt import ExecutionReceipt, ReceiptV02

#: Canon fields masked by default in shareable copies.
DEFAULT_REDACT_FIELDS: tuple[str, ...] = ("git_commit", "build_id")

_REDACTED = "[REDACTED]"


@dataclass(frozen=True, slots=True)
class RedactionEntry:
    """One field that was redacted in one receipt copy."""

    receipt_index: int
    receipt_id: str | None
    field: str
    rule: str


def _canon_fields(schema_version: str | None) -> set[str]:
    """The declared canon field names for a receipt of *schema_version*.

    Sourced from the SDK schema so it cannot drift from the wire format.
    Returns an empty set for an unrecognized version (then nothing is
    treated as 'non-canonical', so only the configured fields are masked).
    """
    if schema_version == "witseal.receipt.v0.2":
        return set(ReceiptV02.model_fields)
    if schema_version == "witseal.receipt.v0.1":
        return set(ExecutionReceipt.model_fields)
    return set()


def redact_receipt(
    index: int,
    receipt: Mapping[str, Any],
    redact_fields: Sequence[str] = DEFAULT_REDACT_FIELDS,
) -> tuple[dict[str, Any], list[RedactionEntry]]:
    """Return a redacted copy of *receipt* and the list of redactions applied."""
    schema_version_raw = receipt.get("schema_version")
    schema_version = schema_version_raw if isinstance(schema_version_raw, str) else None
    canon = _canon_fields(schema_version)

    receipt_id_raw = receipt.get("receipt_id")
    receipt_id = receipt_id_raw if isinstance(receipt_id_raw, str) else None

    redacted: dict[str, Any] = {}
    entries: list[RedactionEntry] = []
    for key, value in receipt.items():
        if canon and key not in canon:
            redacted[key] = _REDACTED
            entries.append(RedactionEntry(index, receipt_id, key, "non_canonical_field"))
        elif key in redact_fields:
            redacted[key] = _REDACTED
            entries.append(RedactionEntry(index, receipt_id, key, "configured_field"))
        else:
            redacted[key] = value
    return redacted, entries
