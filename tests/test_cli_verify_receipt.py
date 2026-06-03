"""Tests for the minimal `witseal verify receipt` CLI."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from witseal.__main__ import main

_FIXTURES = Path(__file__).parent / "fixtures" / "golden-receipt"
_GOLDEN_JSON = _FIXTURES / "rust-golden.json"
_PUBLIC_KEY_HEX = "fd62f46e4e64333ef4c0693e9caf52a540cb21a3546547f016bcd0e990c91862"


def _run_cli(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, object], str]:
    code = main(args)
    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out)) if captured.out else {}
    return code, payload, captured.err


def _write_receipt(tmp_path: Path, updates: dict[str, object]) -> Path:
    data = json.loads(_GOLDEN_JSON.read_text())
    data.update(updates)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_public_key_pem(tmp_path: Path) -> Path:
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_PUBLIC_KEY_HEX))
    pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    path = tmp_path / "golden-public.pem"
    path.write_bytes(pem)
    return path


def _tampered_signature() -> str:
    data = json.loads(_GOLDEN_JSON.read_text())
    algorithm, _, payload = data["signature"].partition(":")
    signature = base64.b64decode(payload, validate=True)
    flipped = bytes([signature[0] ^ 0x01]) + signature[1:]
    return f"{algorithm}:{base64.b64encode(flipped).decode('ascii')}"


def test_cli_verify_receipt_accepts_valid_golden_receipt_hex_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, payload, stderr = _run_cli(
        [
            "verify",
            "receipt",
            str(_GOLDEN_JSON),
            "--public-key",
            _PUBLIC_KEY_HEX,
        ],
        capsys,
    )

    assert code == 0
    assert stderr == ""
    assert payload == {
        "valid": True,
        "receipt_hash_valid": True,
        "signature_valid": True,
        "reason": None,
    }


def test_cli_verify_receipt_accepts_valid_golden_receipt_pem_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    public_key_path = _write_public_key_pem(tmp_path)

    code, payload, stderr = _run_cli(
        [
            "verify",
            "receipt",
            str(_GOLDEN_JSON),
            "--public-key",
            str(public_key_path),
        ],
        capsys,
    )

    assert code == 0
    assert stderr == ""
    assert payload["valid"] is True


def test_cli_verify_receipt_rejects_tampered_receipt_hash(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    receipt_path = _write_receipt(tmp_path, {"receipt_hash": "9" * 64})

    code, payload, stderr = _run_cli(
        ["verify", "receipt", str(receipt_path), "--public-key", _PUBLIC_KEY_HEX],
        capsys,
    )

    assert code == 1
    assert stderr == ""
    assert payload == {
        "valid": False,
        "receipt_hash_valid": False,
        "signature_valid": True,
        "reason": None,
    }


def test_cli_verify_receipt_rejects_bad_signature(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    receipt_path = _write_receipt(tmp_path, {"signature": _tampered_signature()})

    code, payload, stderr = _run_cli(
        ["verify", "receipt", str(receipt_path), "--public-key", _PUBLIC_KEY_HEX],
        capsys,
    )

    assert code == 1
    assert stderr == ""
    assert payload == {
        "valid": False,
        "receipt_hash_valid": True,
        "signature_valid": False,
        "reason": "INVALID_SIGNATURE",
    }


def test_cli_verify_receipt_requires_public_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", "receipt", str(_GOLDEN_JSON)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "--public-key" in captured.err


def test_cli_verify_receipt_rejects_malformed_public_key(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    bad_key_path = tmp_path / "bad-public.pem"
    bad_key_path.write_text("not a public key", encoding="utf-8")

    code, payload, stderr = _run_cli(
        [
            "verify",
            "receipt",
            str(_GOLDEN_JSON),
            "--public-key",
            str(bad_key_path),
        ],
        capsys,
    )

    assert code == 2
    assert payload == {}
    assert "invalid public key" in stderr
