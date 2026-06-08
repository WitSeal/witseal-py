from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from witseal_grc.pack import build_pack, verify_pack
from witseal_grc.samples import generate_keypair, write_sample_receipts

_PACK_FILES = {
    "manifest.json",
    "receipt_samples.json",
    "verification_results.json",
    "control_mapping.json",
    "redaction_report.json",
    "executive_summary.md",
    "hash_manifest.txt",
}


def _make_receipts(tmp_path: Path, count: int = 3) -> tuple[Path, Ed25519PublicKey]:
    private_key, public_key = generate_keypair()
    source = tmp_path / "receipts"
    write_sample_receipts(source, count, private_key)
    return source, public_key


def test_build_and_verify_zip(tmp_path: Path) -> None:
    source, public_key = _make_receipts(tmp_path)
    result = build_pack(
        source, "2026-06", "WIT-ENG-001", public_key=public_key, out_dir=tmp_path / "out"
    )
    assert result.pack_path.exists()
    assert result.receipt_count == 3
    assert result.verified_count == 3
    assert result.signature_checked is True

    verdict = verify_pack(result.pack_path)
    assert verdict["valid"] is True
    assert verdict["pack_id"] == result.pack_id


def test_pack_contains_expected_files(tmp_path: Path) -> None:
    source, public_key = _make_receipts(tmp_path)
    result = build_pack(
        source,
        "2026-06",
        "WIT-ENG-001",
        public_key=public_key,
        out_dir=tmp_path / "out",
        out_format="dir",
    )
    names = {p.name for p in result.pack_path.iterdir()}
    assert _PACK_FILES <= names


def test_tampered_pack_fails_verify(tmp_path: Path) -> None:
    source, public_key = _make_receipts(tmp_path)
    result = build_pack(
        source,
        "2026-06",
        "WIT-ENG-001",
        public_key=public_key,
        out_dir=tmp_path / "out",
        out_format="dir",
    )
    summary = result.pack_path / "executive_summary.md"
    summary.write_text(summary.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")

    verdict = verify_pack(result.pack_path)
    assert verdict["valid"] is False
    assert "executive_summary.md" in verdict["mismatches"]


def test_keyless_pack_marks_signature_unchecked(tmp_path: Path) -> None:
    source, _ = _make_receipts(tmp_path)
    result = build_pack(source, "2026-06", "WIT-ENG-002", out_dir=tmp_path / "out")
    assert result.signature_checked is False
    assert result.verified_count == 3


def test_unknown_control_raises(tmp_path: Path) -> None:
    source, public_key = _make_receipts(tmp_path)
    with pytest.raises(KeyError):
        build_pack(source, "2026-06", "WIT-XXX-1", public_key=public_key, out_dir=tmp_path / "o")


def test_no_receipts_raises(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no receipt"):
        build_pack(empty, "2026-06", "WIT-ENG-001", out_dir=tmp_path / "o")
