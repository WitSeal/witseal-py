"""Unified, version-discriminating verification surface — mirror of TS ``verifyArtifact``.

One entry point that, given a parsed JSON mapping, reads ``schema_version``,
decides what the artifact is, and runs the right verification:

- ``witseal.receipt.v0.1`` — schema parse + ``receipt_hash`` self-consistency.
  A standalone v0.1 receipt is unsigned and carries no companion event, so
  the self-hash is the available integrity check. No key required.
- ``witseal.receipt.v0.2`` — schema parse + Ed25519 signature +
  ``receipt_hash`` self-consistency (:func:`witseal.verify.receipt.verify_receipt`).
  Requires a public key.
- ``witseal.evidence-package.v0.1`` — schema parse + hash-chain verification +
  per-receipt integrity (:func:`witseal.verify.evidence.verify_evidence_package`).
  Requires a public key only if it contains a v0.2 receipt.

Anything else is classified ``unknown`` and rejected. Read-side only; the
Python SDK does not generate artifacts ([redacted]: generation is the Rust track).
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from witseal.integrity.hash import sha256_canonical
from witseal.schemas.receipt import ExecutionReceipt, ReceiptV02
from witseal.verify.evidence import verify_evidence_package
from witseal.verify.receipt import verify_receipt

_RECEIPT_HASH_FIELD = "receipt_hash"


@dataclass(frozen=True, slots=True)
class ArtifactVerifyResult:
    """Unified VALID / INVALID verdict from :func:`verify_artifact`.

    ``kind`` is one of ``receipt.v0.1``, ``receipt.v0.2``,
    ``evidence-package.v0.1``, or ``unknown``. ``reason`` is populated on
    failure.
    """

    valid: bool
    kind: str
    schema_version: str | None = None
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.valid


def _read_schema_version(value: Any) -> str | None:  # noqa: ANN401
    if isinstance(value, Mapping):
        sv = value.get("schema_version")
        return sv if isinstance(sv, str) else None
    return None


def _verify_receipt_v01(value: Mapping[str, Any]) -> ArtifactVerifyResult:
    """v0.1 receipt: schema parse + ``receipt_hash`` self-consistency."""
    try:
        receipt = ExecutionReceipt.model_validate(dict(value))
    except (ValidationError, ValueError) as exc:
        return ArtifactVerifyResult(
            valid=False,
            kind="receipt.v0.1",
            schema_version="witseal.receipt.v0.1",
            reason=f"schema validation failed: {exc}",
        )
    body = receipt.model_dump(by_alias=True)
    body.pop(_RECEIPT_HASH_FIELD, None)
    expected = sha256_canonical(body)
    if not hmac.compare_digest(expected, receipt.receipt_hash):
        return ArtifactVerifyResult(
            valid=False,
            kind="receipt.v0.1",
            schema_version="witseal.receipt.v0.1",
            reason="receipt_hash invalid (self-hash check failed)",
        )
    return ArtifactVerifyResult(
        valid=True, kind="receipt.v0.1", schema_version="witseal.receipt.v0.1"
    )


def _verify_receipt_v02(
    value: Mapping[str, Any], public_key: Ed25519PublicKey | None
) -> ArtifactVerifyResult:
    """v0.2 receipt: schema parse + signature + ``receipt_hash``."""
    try:
        receipt = ReceiptV02.model_validate(dict(value))
    except (ValidationError, ValueError) as exc:
        return ArtifactVerifyResult(
            valid=False,
            kind="receipt.v0.2",
            schema_version="witseal.receipt.v0.2",
            reason=f"schema validation failed: {exc}",
        )
    if public_key is None:
        return ArtifactVerifyResult(
            valid=False,
            kind="receipt.v0.2",
            schema_version="witseal.receipt.v0.2",
            reason="v0.2 receipt verification requires a public key (none supplied)",
        )
    try:
        result = verify_receipt(receipt, public_key)
    except ValueError as exc:
        return ArtifactVerifyResult(
            valid=False,
            kind="receipt.v0.2",
            schema_version="witseal.receipt.v0.2",
            reason=f"invalid receipt signature encoding: {exc}",
        )
    return ArtifactVerifyResult(
        valid=result.valid,
        kind="receipt.v0.2",
        schema_version="witseal.receipt.v0.2",
        reason=None if result.valid else (result.reason or "receipt verification failed"),
    )


def _verify_evidence(
    value: Mapping[str, Any], public_key: Ed25519PublicKey | None
) -> ArtifactVerifyResult:
    """Evidence package: delegate to the package verifier."""
    result = verify_evidence_package(value, public_key)
    return ArtifactVerifyResult(
        valid=result.valid,
        kind="evidence-package.v0.1",
        schema_version="witseal.evidence-package.v0.1",
        reason=result.reason,
    )


def verify_artifact(
    value: Mapping[str, Any],
    public_key: Ed25519PublicKey | None = None,
) -> ArtifactVerifyResult:
    """Discriminate *value* on ``schema_version`` and verify it.

    Returns ``kind='unknown'`` and ``valid=False`` for anything that is not a
    recognized WitSeal receipt or evidence package.
    """
    schema_version = _read_schema_version(value)

    if schema_version == "witseal.receipt.v0.1":
        return _verify_receipt_v01(value)
    if schema_version == "witseal.receipt.v0.2":
        return _verify_receipt_v02(value, public_key)
    if schema_version == "witseal.evidence-package.v0.1":
        return _verify_evidence(value, public_key)

    reason = (
        "no schema_version field: not a recognized WitSeal artifact"
        if schema_version is None
        else (
            f"unrecognized schema_version '{schema_version}' "
            "(expected a witseal.receipt.* or witseal.evidence-package.* artifact)"
        )
    )
    return ArtifactVerifyResult(
        valid=False,
        kind="unknown",
        schema_version=schema_version,
        reason=reason,
    )
