from __future__ import annotations

from pathlib import Path

import pytest
from witseal_grc.export import build_request, perform_export
from witseal_grc.pack import build_pack
from witseal_grc.samples import generate_keypair, write_sample_receipts


def _pack(tmp_path: Path) -> Path:
    private_key, public_key = generate_keypair()
    source = tmp_path / "receipts"
    write_sample_receipts(source, 2, private_key)
    result = build_pack(
        source, "2026-06", "WIT-ENG-001", public_key=public_key, out_dir=tmp_path / "out"
    )
    return result.pack_path


def test_drata_dry_run_builds_request(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    request = build_request(
        "drata",
        pack,
        "WIT-ENG-001",
        connection_id="C1",
        resource_id="R1",
        api_key="secret-token",
    )
    summary = perform_export(request, dry_run=True)
    assert summary["target"] == "drata"
    assert summary["method"] == "POST"
    assert "custom-connections/C1/resources/R1/records" in summary["url"]
    assert summary["sent"] is False
    assert summary["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert summary["body_preview"]["control_code"] == "WIT-ENG-001"
    assert summary["body_preview"]["receipt_count"] == 2


def test_vanta_dry_run_builds_request(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    request = build_request("vanta", pack, "WIT-ENG-001", document_id="D1")
    summary = perform_export(request, dry_run=True)
    assert summary["target"] == "vanta"
    assert "documents/D1/uploads" in summary["url"]
    assert summary["body_kind"] == "file"
    assert summary["sent"] is False


def test_no_key_means_not_sent_even_when_not_dry_run(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    request = build_request("drata", pack, "WIT-ENG-001")
    summary = perform_export(request, dry_run=False)
    assert summary["sent"] is False
    assert summary["authenticated"] is False


def test_unknown_target_raises(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    with pytest.raises(ValueError, match="unknown target"):
        build_request("github", pack, "WIT-ENG-001")
