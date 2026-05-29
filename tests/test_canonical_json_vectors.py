"""RFC 8785 (JSON Canonicalization Scheme) parity tests.

Evaluates two PyPI candidates for the canonical-JSON dependency referenced in
``pyproject.toml`` ``[dependency-groups] canonicalize-eval``:

- ``jcs`` (Anders Rundgren, RFC 8785 author's reference implementation)
- ``rfc8785`` (Trail of Bits)

Both libraries claim full RFC 8785 conformance. These tests confirm byte-for-byte
parity on:

- The illustrative example from RFC 8785 section 3.2.3.
- Edge cases for the ECMAScript 6 Number serialization algorithm (section 3.2.2.3).
- Key ordering by UTF-16 code units (section 3.2.3).
- Unicode strings and surrogate pairs (section 3.2.2.2).
- Literals (``null`` / ``true`` / ``false``) and empty containers.

As of 2026-05-19 evaluation: both libraries agree on every vector below. Winner
selection deferred to Week 2 follow-up (criteria: streaming support, pure-Python
vs. compiled, license, maintenance freshness).
"""

from __future__ import annotations

from typing import Any

import jcs
import pytest
import rfc8785


def _both(value: Any) -> tuple[bytes, bytes]:  # noqa: ANN401
    """Return (rfc8785_output, jcs_output) as bytes for byte-exact comparison."""
    a = rfc8785.dumps(value)
    b_text = jcs.canonicalize(value)
    b = b_text.encode("utf-8") if isinstance(b_text, str) else b_text
    return a, b


# ---------------------------------------------------------------------------
# RFC 8785 section 3.2.3 illustrative example.
# ---------------------------------------------------------------------------

RFC_323_INPUT: dict[str, Any] = {
    "numbers": [
        333333333.33333329,
        1e30,
        4.50,
        2e-3,
        0.000000000000000000000000001,
    ],
    "string": "€$\u000fA'B\"\\\"/",
    "literals": [None, True, False],
}

RFC_323_EXPECTED = (
    b'{"literals":[null,true,false],'
    b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
    b'"string":"\xe2\x82\xac$\\u000fA\'B\\"\\\\\\"/"}'
)


def test_rfc8785_section_323_example() -> None:
    rfc_out, jcs_out = _both(RFC_323_INPUT)
    assert rfc_out == jcs_out, "candidates disagree on RFC section 3.2.3 example"
    assert rfc_out == RFC_323_EXPECTED, "RFC section 3.2.3 expected output mismatch"


# ---------------------------------------------------------------------------
# ECMAScript 6 Number serialization (RFC 8785 section 3.2.2.3).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, b"0"),
        (-0.0, b"0"),
        (1, b"1"),
        (-1, b"-1"),
        (1.5, b"1.5"),
        (100, b"100"),
        (1e21, b"1e+21"),
        (1e20, b"100000000000000000000"),
        (1e-6, b"0.000001"),
        (1e-7, b"1e-7"),
        (333333333.3333333, b"333333333.3333333"),
        (4.50, b"4.5"),
        (2e-3, b"0.002"),
    ],
)
def test_number_serialization_parity(value: float | int, expected: bytes) -> None:
    rfc_out, jcs_out = _both(value)
    assert rfc_out == jcs_out, f"candidates disagree on number {value!r}"
    assert rfc_out == expected, f"expected {expected!r} got {rfc_out!r}"


# ---------------------------------------------------------------------------
# Key ordering by UTF-16 code units (RFC 8785 section 3.2.3).
# ---------------------------------------------------------------------------


def test_key_ordering_ascii() -> None:
    obj = {"b": 1, "a": 2, "c": 3}
    rfc_out, jcs_out = _both(obj)
    assert rfc_out == jcs_out
    assert rfc_out == b'{"a":2,"b":1,"c":3}'


def test_key_ordering_unicode_bmp() -> None:
    obj = {"é": 1, "e": 2, "à": 3}
    rfc_out, jcs_out = _both(obj)
    assert rfc_out == jcs_out


def test_key_ordering_nested() -> None:
    obj = {"outer_b": {"inner_b": 1, "inner_a": 2}, "outer_a": [3, 1, 2]}
    rfc_out, jcs_out = _both(obj)
    assert rfc_out == jcs_out
    assert rfc_out == b'{"outer_a":[3,1,2],"outer_b":{"inner_a":2,"inner_b":1}}'


# ---------------------------------------------------------------------------
# String escaping (RFC 8785 section 3.2.2.2).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", b'""'),
        ("plain", b'"plain"'),
        ('"', b'"\\""'),
        ("\\", b'"\\\\"'),
        ("/", b'"/"'),
        ("\b", b'"\\b"'),
        ("\f", b'"\\f"'),
        ("\n", b'"\\n"'),
        ("\r", b'"\\r"'),
        ("\t", b'"\\t"'),
        ("\u0000", b'"\\u0000"'),
        ("\u001f", b'"\\u001f"'),
        (" ", b'" "'),
        ("\u007f", b'"\x7f"'),
    ],
)
def test_string_escape_parity(value: str, expected: bytes) -> None:
    rfc_out, jcs_out = _both(value)
    assert rfc_out == jcs_out, f"candidates disagree on string {value!r}"
    assert rfc_out == expected, f"expected {expected!r} got {rfc_out!r}"


def test_string_utf8_passthrough() -> None:
    rfc_out, jcs_out = _both("€")
    assert rfc_out == jcs_out
    assert rfc_out == b'"\xe2\x82\xac"'


def test_string_surrogate_pair() -> None:
    rfc_out, jcs_out = _both("\U0001f600")
    assert rfc_out == jcs_out
    assert rfc_out == b'"\xf0\x9f\x98\x80"'


# ---------------------------------------------------------------------------
# Literals and containers.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, b"null"),
        (True, b"true"),
        (False, b"false"),
        ([], b"[]"),
        ({}, b"{}"),
        ([None, True, False], b"[null,true,false]"),
    ],
)
def test_literals_parity(value: Any, expected: bytes) -> None:  # noqa: ANN401
    rfc_out, jcs_out = _both(value)
    assert rfc_out == jcs_out
    assert rfc_out == expected
