"""Shared scalar types used across WitSeal schemas.

Mirrors `schemas/witness-event.schema.ts` Sha256HashSchema and TimestampSchema,
plus RFC-002 wire-format v0.2 wire-format primitives.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)
_SHA256_PREFIXED_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA1_HEX_RE = re.compile(r"^[a-f0-9]{40}$")
_ED25519_SIG_PREFIXED_RE = re.compile(r"^ed25519:[A-Za-z0-9+/]{86}==$")


def _validate_sha256(value: str) -> str:
    if not _SHA256_RE.match(value):
        raise ValueError("must be a lowercase hex SHA-256 hash")
    return value


def _validate_rfc3339_utc(value: str) -> str:
    if not _RFC3339_UTC_RE.match(value):
        raise ValueError("must be RFC 3339 UTC timestamp (Z suffix, no offset)")
    return value


def _validate_sha256_prefixed(value: str) -> str:
    if not _SHA256_PREFIXED_RE.match(value):
        raise ValueError("must be 'sha256:' followed by 64 lowercase hex chars")
    return value


def _validate_sha1_hex(value: str) -> str:
    if not _SHA1_HEX_RE.match(value):
        raise ValueError("must be 40 lowercase hex chars (git SHA-1)")
    return value


def _validate_ed25519_sig_prefixed(value: str) -> str:
    if not _ED25519_SIG_PREFIXED_RE.match(value):
        raise ValueError(
            "must be 'ed25519:' followed by 86 standard-alphabet base64 chars "
            "and '==' padding (96 chars total)"
        )
    return value


Sha256Hex = Annotated[str, AfterValidator(_validate_sha256)]
"""SHA-256 hash, hex-encoded, lowercase (64 chars)."""

Rfc3339UtcTimestamp = Annotated[str, AfterValidator(_validate_rfc3339_utc)]
"""RFC 3339 timestamp, UTC (Z suffix), no offset."""

Sha256DigestPrefixed = Annotated[str, AfterValidator(_validate_sha256_prefixed)]
"""RFC-002 § 5 — `sha256:<64-lowercase-hex>` digest form."""

Sha1HexFull = Annotated[str, AfterValidator(_validate_sha1_hex)]
"""RFC-002 § 7.2 — full 40-char lowercase hex git commit hash."""

Ed25519SignaturePrefixed = Annotated[str, AfterValidator(_validate_ed25519_sig_prefixed)]
"""RFC-002 § 6 (post-2026-05-23 amendment) — `ed25519:<88-char-base64>` form
(96 chars total). The `ed25519:` prefix mirrors the `sha256:` digest prefix
from § 5; the prefix applies only to the final populated signature value.
Signing-pre-image (`compute_signing_bytes`) is unaffected — the signature
field is cleared to the empty-string sentinel `""` (and `receipt_hash` to the
64-zero placeholder) before canonicalization per the S1 interpretation
/ golden-receipt construction procedure."""

ArtifactType = Literal[
    "npm-package",
    "cargo-crate",
    "python-wheel",
    "python-sdist",
    "oci-image",
    "generic-binary",
]
"""RFC-002 § 3 — frozen `artifact_type` taxonomy."""

VerifierReason = Literal[
    "INVALID_SIGNATURE",
    "ARTIFACT_MISMATCH",
    "CHAIN_INVALID",
    "ATTESTATION_MISMATCH",
    "INVALID_SCHEMA",
    "VERIFICATION_INCOMPLETE",
]
"""RFC-002 § 4 — frozen verifier reason-string set."""
