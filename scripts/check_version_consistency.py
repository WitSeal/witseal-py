"""Version-consistency gate (see CONTRIBUTING.md release notes).

``pyproject.toml`` is the single source of truth for the package version.
This gate fails the build when anything that must track it drifts:

  1. The installed distribution metadata version (what ``witseal.__version__``
     surfaces via ``importlib.metadata``) must equal the ``pyproject.toml``
     version — guards against a stale build/install or a hand-edited
     ``__version__``.
  2. ``CHANGELOG.md`` must carry a ``## [<version>]`` section — guards against
     publishing a version with no changelog entry.
  3. When ``RELEASE_TAG`` is set (the release workflow exports the pushed tag),
     the tag — with an optional leading ``v`` — must equal the
     ``pyproject.toml`` version, so a tag can never publish a mismatched build.

Run locally with ``uv run python scripts/check_version_consistency.py`` after
``uv sync``; CI runs it in the quality job and the release workflow.
"""

from __future__ import annotations

import os
import sys
import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as dist_version
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DIST_NAME = "witseal"


def _pyproject_version() -> str:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text("utf-8"))
    return str(data["project"]["version"])


def check() -> list[str]:
    """Return a list of human-readable consistency errors (empty == OK)."""
    proj = _pyproject_version()
    errors: list[str] = []

    try:
        meta = dist_version(_DIST_NAME)
    except PackageNotFoundError:
        errors.append(
            f"{_DIST_NAME} is not installed; run `uv sync` before this gate"
        )
    else:
        if meta != proj:
            errors.append(
                f"installed metadata version {meta!r} != pyproject {proj!r}"
            )

    changelog = (_ROOT / "CHANGELOG.md").read_text("utf-8")
    if f"## [{proj}]" not in changelog:
        errors.append(f"CHANGELOG.md has no '## [{proj}]' section")

    tag = os.environ.get("RELEASE_TAG", "").strip()
    if tag:
        expected = tag[1:] if tag.startswith("v") else tag
        if expected != proj:
            errors.append(f"release tag {tag!r} != pyproject version {proj!r}")

    return errors


def main() -> int:
    errors = check()
    if errors:
        for err in errors:
            print(f"::error::version-consistency: {err}", file=sys.stderr)
        return 1
    print(f"version-consistency OK: {_pyproject_version()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
