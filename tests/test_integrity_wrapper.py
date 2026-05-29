"""Smoke tests for the integrity wrapper module.

Verifies that :func:`witseal.integrity.canonicalize` is a thin pass-through to
:func:`rfc8785.dumps` and that :func:`witseal.integrity.sha256_canonical`
returns the expected ``Sha256Hex`` shape (64 lowercase hex chars matching the
schema primitive). RFC 8785 conformance itself is covered by
``test_canonical_json_vectors.py`` (parity vs. the ``jcs`` oracle).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import pytest
import rfc8785

from witseal.integrity import canonicalize, sha256_canonical
from witseal.schemas._primitives import _SHA256_RE


def test_canonicalize_passthrough_to_rfc8785() -> None:
    value: dict[str, Any] = {
        "literals": [None, True, False],
        "numbers": [1, 2.5, -3, 0],
        "nested": {"b": [1, 2], "a": "hello"},
    }
    assert canonicalize(value) == rfc8785.dumps(value)


def test_canonicalize_returns_bytes() -> None:
    out = canonicalize({"a": 1, "b": [2, 3]})
    assert isinstance(out, bytes)


def test_canonicalize_orders_keys_by_utf16() -> None:
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_sha256_canonical_returns_lowercase_hex() -> None:
    digest = sha256_canonical({"key": "value"})
    assert re.match(r"^[a-f0-9]{64}$", digest), digest


def test_sha256_canonical_matches_schema_primitive_pattern() -> None:
    digest = sha256_canonical({"nested": {"a": [1, 2, 3]}, "z": True})
    assert _SHA256_RE.match(digest)


def test_sha256_canonical_matches_manual_pipeline() -> None:
    value: dict[str, Any] = {"nested": {"a": [1, 2, 3]}, "z": True}
    expected = hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    assert sha256_canonical(value) == expected


def test_sha256_canonical_stable_across_key_order() -> None:
    a = sha256_canonical({"x": 1, "y": 2})
    b = sha256_canonical({"y": 2, "x": 1})
    assert a == b


@pytest.mark.parametrize("value", [None, True, False, 0, "", [], {}])
def test_canonicalize_handles_primitives_and_empty(value: Any) -> None:  # noqa: ANN401
    out = canonicalize(value)
    assert isinstance(out, bytes)
    assert len(out) > 0
