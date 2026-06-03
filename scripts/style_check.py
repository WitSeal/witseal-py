"""Vocabulary discipline check for public Markdown (see STYLE.md).

Scans tracked Markdown files for terms in the STYLE.md "Avoid" column and
exits non-zero on a match, so the category vocabulary does not drift in
public text. A justified exception is wrapped in a region:

    <!-- style-allow -->
    ... text that intentionally uses an avoided term ...
    <!-- /style-allow -->

STYLE.md itself is excluded (it necessarily names the avoided terms).
"""

from __future__ import annotations

import re
import subprocess
import sys

# Avoided terms (case-insensitive substring match). Kept to clear,
# category-diluting phrases to avoid false positives on ordinary prose.
AVOID = [
    "AI monitoring",
    "AI observability",
    "AI logging",
    "AI governance",
    "AI safety",
    "AI alignment",
    "audit log",
    "audit trail",
    "severity tagging",
    "threat scoring",
]

EXCLUDE = {"STYLE.md"}

_ALLOW_OPEN = "<!-- style-allow -->"
_ALLOW_CLOSE = "<!-- /style-allow -->"


def _tracked_markdown() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "*.md"]).decode("utf-8")
    return [f for f in out.splitlines() if f and f not in EXCLUDE]


def _scan(path: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    allowed = False
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.strip()
            if stripped == _ALLOW_OPEN:
                allowed = True
                continue
            if stripped == _ALLOW_CLOSE:
                allowed = False
                continue
            if allowed:
                continue
            for term in AVOID:
                if re.search(re.escape(term), line, re.IGNORECASE):
                    hits.append((lineno, term))
    return hits


def main() -> int:
    failed = False
    for path in _tracked_markdown():
        for lineno, term in _scan(path):
            print(f"{path}:{lineno}: avoided term '{term}' (see STYLE.md)")
            failed = True
    if failed:
        print("\nstyle-check: FAILED — rephrase per STYLE.md, or wrap a "
              "justified use in <!-- style-allow --> ... <!-- /style-allow -->")
        return 1
    print("style-check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
