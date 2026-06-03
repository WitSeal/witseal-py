"""Tests for the `witseal verify evidence`, `verify artifact`, and `inspect` CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from tests._artifact_builders import (
    make_evidence_package,
    two_event_chain,
    v01_receipt_dict,
)
from witseal.__main__ import main

_FIXTURES = Path(__file__).parent / "fixtures" / "golden-receipt"
_GOLDEN_JSON = _FIXTURES / "rust-golden.json"
_PUBLIC_KEY_HEX = "fd62f46e4e64333ef4c0693e9caf52a540cb21a3546547f016bcd0e990c91862"


def _run(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, object], str]:
    code = main(args)
    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out)) if captured.out else {}
    return code, payload, captured.err


def _write(tmp_path: Path, name: str, obj: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def test_cli_verify_evidence_valid_v01(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    pkg_path = _write(tmp_path, "pkg.json", pkg)
    code, payload, stderr = _run(["verify", "evidence", str(pkg_path)], capsys)
    assert code == 0
    assert stderr == ""
    assert payload["valid"] is True
    assert payload["kind"] == "evidence-package.v0.1"
    assert payload["chain_valid"] is True


def test_cli_verify_evidence_broken_chain(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    events = two_event_chain()
    pkg = make_evidence_package(events, [])
    pkg["events"][0]["event_hash"] = "9" * 64
    pkg_path = _write(tmp_path, "pkg.json", pkg)
    code, payload, _ = _run(["verify", "evidence", str(pkg_path)], capsys)
    assert code == 1
    assert payload["valid"] is False
    assert "chain verification failed" in cast(str, payload["reason"])


def test_cli_verify_artifact_v02_receipt_with_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, payload, stderr = _run(
        ["verify", "artifact", str(_GOLDEN_JSON), "--public-key", _PUBLIC_KEY_HEX],
        capsys,
    )
    assert code == 0
    assert stderr == ""
    assert payload["valid"] is True
    assert payload["kind"] == "receipt.v0.2"
    assert payload["schema_version"] == "witseal.receipt.v0.2"


def test_cli_verify_artifact_unknown(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = _write(tmp_path, "x.json", {"schema_version": "witseal.bogus.v9"})
    code, payload, _ = _run(["verify", "artifact", str(path)], capsys)
    assert code == 1
    assert payload["kind"] == "unknown"


def test_cli_inspect_v02_receipt_keyless(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, payload, stderr = _run(["inspect", str(_GOLDEN_JSON)], capsys)
    assert code == 0
    assert stderr == ""
    assert payload["kind"] == "receipt.v0.2"
    integrity = cast(dict[str, object], payload["integrity"])
    assert integrity["receipt_hash_self_consistent"] is True


def test_cli_inspect_evidence_package(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    pkg_path = _write(tmp_path, "pkg.json", pkg)
    code, payload, _ = _run(["inspect", str(pkg_path)], capsys)
    assert code == 0
    assert payload["kind"] == "evidence-package.v0.1"
    fields = cast(dict[str, object], payload["fields"])
    assert fields["event_count"] == 2


def test_cli_inspect_unknown_exits_one(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = _write(tmp_path, "x.json", {"foo": "bar"})
    code, payload, _ = _run(["inspect", str(path)], capsys)
    assert code == 1
    assert payload["kind"] == "unknown"


def test_cli_verify_evidence_missing_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, _, stderr = _run(
        ["verify", "evidence", str(tmp_path / "nope.json")], capsys
    )
    assert code == 2
    assert "could not read artifact" in stderr
