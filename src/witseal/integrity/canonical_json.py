"""Canonical JSON serialization per RFC 8785 (JSON Canonicalization Scheme)."""

from __future__ import annotations

from typing import Any

import rfc8785


def canonicalize(value: Any) -> bytes:  # noqa: ANN401
    """Serialize *value* to RFC 8785 canonical JSON as UTF-8 bytes.

    Output is byte-deterministic for any JSON-compatible Python value
    (``dict`` with ``str`` keys, ``list``/``tuple``, ``str``, ``int``,
    ``float``, ``bool``, ``None``). The result is the input to evidence-chain
    hashing; see :func:`witseal.integrity.hash.sha256_canonical`.
    """
    return rfc8785.dumps(value)
