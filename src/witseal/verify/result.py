"""Verification result type for the v0.2 receipt verifier.

A :class:`VerificationResult` is the clear VALID / INVALID answer the
verifier returns. ``valid`` is the single boolean a caller checks;
the two component booleans (``receipt_hash_valid``, ``signature_valid``)
are exposed for diagnostics and cross-track reporting.

``reason`` carries an RFC-002 § 4 reason string when, and only when, the
mapping is unambiguous in the current canon: a signature failure maps to
``INVALID_SIGNATURE``. A ``receipt_hash`` mismatch is deliberately left
unclassified here (``reason=None`` with ``receipt_hash_valid=False``):
its RFC-002 § 4 reason class is owned by the Phase C reason classifier and
not yet finalized, so this Phase B verifier surfaces the fact without
asserting a reason string the canon hasn't fixed.
"""

from __future__ import annotations

from dataclasses import dataclass

from witseal.schemas._primitives import VerifierReason


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of verifying a v0.2 receipt.

    ``valid`` is ``True`` iff BOTH the recomputed ``receipt_hash`` matches
    the stored value AND the Ed25519 signature verifies over the S1
    pre-image.
    """

    valid: bool
    receipt_hash_valid: bool
    signature_valid: bool
    reason: VerifierReason | None = None

    def __bool__(self) -> bool:
        return self.valid
