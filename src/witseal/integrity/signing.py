"""S1 pre-image computation for v0.2 receipts.

The Ed25519 signature on a v0.2 receipt -- and the receipt's own
``receipt_hash`` -- both cover the **same** canonical pre-image: the
receipt body with two fields cleared to their S1 placeholders before
canonicalization, with both fields still PRESENT in the output:

- ``signature`` -> ``""`` (empty-string sentinel);
- ``receipt_hash`` -> 64 ASCII zeros (``"0" * 64``), i.e. the wire form
  of a zero SHA-256 digest (32 zero bytes rendered as bare lowercase
  hex). NOT an empty string.

The 64-zero placeholder -- not an empty string -- is the canonical S1
value. It is the only value that reproduces the golden v0.2 vector:
``SHA-256(pre-image)`` equals the stored ``receipt_hash`` and the stored
``signature`` verifies against the pre-image. References:

- Golden-receipt construction procedure (cross-track source of truth),
  ``tests/fixtures/golden-receipt/inputs.json`` ``_construction_procedure``
  + ``README.md`` steps 1/4/6: step 1 sets ``receipt_hash`` to a zero
  SHA-256 digest and ``signature = ""``; step 4 signs **those** bytes;
  step 6 re-derives by zeroing ``receipt_hash`` and emptying
  ``signature``;
- At chain genesis ``prev_hash`` is ``null``; the field is always
  emitted, never absent.

Canonical bytes per RFC 8785 / JCS via
:func:`witseal.integrity.canonical_json.canonicalize`.

The signing operation itself (private-key handling) is NOT performed by
witseal-py: Python is the ecosystem-facing SDK with a verifier-and-schema
role only. This module produces the pre-image consumed by the Python
verify path (:mod:`witseal.verify.ed25519`) and by
:func:`compute_receipt_hash`; runtime signing belongs to the Rust track.
"""

from __future__ import annotations

from witseal.integrity.canonical_json import canonicalize
from witseal.integrity.hash import sha256_hex_of_bytes
from witseal.schemas.receipt import ReceiptV02

RECEIPT_HASH_PLACEHOLDER: str = "0" * 64
"""S1 placeholder for ``receipt_hash`` in the signing/hash pre-image: the
wire form of a zero SHA-256 digest (32 zero bytes -> 64 ASCII zeros).
See the module docstring and golden-receipt ``inputs.json`` step 1."""

SIGNATURE_PLACEHOLDER: str = ""
"""S1 placeholder for ``signature`` in the signing/hash pre-image:
the empty-string sentinel."""


def compute_signing_bytes(receipt: ReceiptV02) -> bytes:
    """Return the canonical S1 pre-image bytes the receipt commits to.

    These are the bytes the Ed25519 signature covers AND the bytes
    ``receipt_hash`` is the SHA-256 of (the two are the same pre-image per
    the golden-receipt construction procedure). Both ``receipt_hash`` and
    ``signature`` are cleared to their S1 placeholders before
    canonicalization:

    - ``receipt_hash`` -> :data:`RECEIPT_HASH_PLACEHOLDER` (64 zeros);
    - ``signature`` -> :data:`SIGNATURE_PLACEHOLDER` (``""``).

    All other v0.2 fields carry their populated values; null-valued
    required fields (``execution_result_hash`` when no result is recorded;
    ``prev_hash`` at chain genesis) are emitted as explicit ``null``,
    never absent (the no-skip-empty rule addresses field absence, not
    field value).

    Canonicalization is RFC 8785 / JCS.
    """
    body = receipt.model_dump(by_alias=True)
    body["receipt_hash"] = RECEIPT_HASH_PLACEHOLDER
    body["signature"] = SIGNATURE_PLACEHOLDER
    return canonicalize(body)


def compute_receipt_hash(receipt: ReceiptV02) -> str:
    """Return the expected ``receipt_hash`` for *receipt* (lowercase hex).

    ``receipt_hash = SHA-256(S1 pre-image)`` per the golden-receipt
    construction procedure step 3. The pre-image is exactly
    :func:`compute_signing_bytes` output (receipt_hash and signature
    cleared to their S1 placeholders), so the hash a verifier recomputes
    is independent of the stored ``receipt_hash`` / ``signature`` values.
    """
    return sha256_hex_of_bytes(compute_signing_bytes(receipt))
