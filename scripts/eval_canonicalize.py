"""Day 0 smoke test: compare rfc8785 (Trail of Bits) and jcs (titusz) PyPI packages
against TypeScript reference implementation output for RFC 8785 edge cases.

Full cyberphone test vector run is deferred to Layer 0.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import jcs
import rfc8785

TS_REPO = Path(os.environ.get("WITSEAL_TS_REPO", "../witseal"))

CASES: list[tuple[str, Any]] = [
    ("key_sort_basic", {"b": 1, "a": 2}),
    ("nested_objects", {"z": {"b": 1, "a": 2}, "a": [3, 2, 1]}),
    ("integer_one", 1),
    ("integer_zero", 0),
    ("negative_zero_float", -0.0),
    ("negative_zero_int", -0),
    ("float_one_half", 1.5),
    ("string_ascii", "hello"),
    ("string_unicode_bmp", {"中": 1, "a": 2}),
    ("string_with_quotes", 'he said "hi"'),
    ("array_mixed", [1, "two", True, None]),
    ("null", None),
    ("bool_true", True),
    ("bool_false", False),
    ("empty_object", {}),
    ("empty_array", []),
    ("large_integer", 9007199254740991),
    ("nested_array", [[1, 2], [3, 4]]),
    # Surrogate-pair sort case: U+1F600 vs U+E000.
    # UTF-16 code unit order puts surrogate pair high half (D83D) AFTER U+E000.
    # Codepoint order puts U+1F600 AFTER U+E000.
    # Same answer either way here, but kept for documentation.
    ("emoji_keys", {"\U0001f600": 1, "": 2}),
]


def ts_reference(value: Any) -> str:  # noqa: ANN401
    js = (
        "import {canonicalize} from './src/integrity/hash-chain.ts';"
        "const v = JSON.parse(process.argv[1]);"
        "process.stdout.write(canonicalize(v));"
    )
    result = subprocess.run(
        ["npx", "tsx", "-e", js, "--", json.dumps(value)],
        cwd=TS_REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return f"<TS error: {result.stderr.strip()[:200]}>"
    return result.stdout


def py_rfc8785(value: Any) -> str:  # noqa: ANN401
    try:
        return rfc8785.dumps(value).decode("utf-8")
    except Exception as e:
        return f"<rfc8785 error: {e}>"


def py_jcs(value: Any) -> str:  # noqa: ANN401
    try:
        return jcs.canonicalize(value).decode("utf-8")
    except Exception as e:
        return f"<jcs error: {e}>"


def main() -> int:
    print(f"{'case':<28} {'ts_ref':<32} {'rfc8785':<32} {'jcs':<32} {'match':<10}")
    print("-" * 134)
    all_match = True
    ts_failures = 0
    for name, value in CASES:
        ts = ts_reference(value)
        rfc = py_rfc8785(value)
        jc = py_jcs(value)
        if ts.startswith("<TS error"):
            ts_failures += 1
        rfc_match = rfc == ts
        jcs_match = jc == ts
        if rfc_match and jcs_match:
            both = "both"
        elif rfc_match:
            both = "rfc8785"
        elif jcs_match:
            both = "jcs"
        else:
            both = "NONE"
        if not (rfc_match and jcs_match):
            all_match = False
        print(f"{name:<28} {ts[:30]!r:<32} {rfc[:30]!r:<32} {jc[:30]!r:<32} {both:<10}")
    print()
    print(f"TS reference failures: {ts_failures}/{len(CASES)}")
    print(f"All cases match all three implementations: {all_match}")
    return 0 if all_match and ts_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
