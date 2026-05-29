"""SHA-256 hashing primitives for the evidence chain."""

from __future__ import annotations

import hashlib
from typing import Any

from witseal.integrity.canonical_json import canonicalize


def sha256_hex_of_bytes(data: bytes) -> str:
    """Return lowercase-hex SHA-256 of raw *data* bytes.

    Used by the v0.2 verifier path: ``receipt_hash`` is the SHA-256 of the
    already-canonical S1 pre-image bytes (see
    :func:`witseal.integrity.signing.compute_receipt_hash`), so the input
    must NOT be canonicalized again. Output matches the ``Sha256Hex``
    primitive (64 lowercase hex chars).
    """
    return hashlib.sha256(data).hexdigest()


def sha256_canonical(value: Any) -> str:  # noqa: ANN401
    """Return lowercase-hex SHA-256 of the RFC 8785 canonical JSON form of *value*.

    Matches the ``Sha256Hex`` primitive in :mod:`witseal.schemas._primitives`
    (64 lowercase hex chars).
    """
    return sha256_hex_of_bytes(canonicalize(value))
