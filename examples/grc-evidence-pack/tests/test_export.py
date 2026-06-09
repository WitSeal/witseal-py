from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest
from witseal_grc.export import build_request, encode_multipart, perform_export
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
    assert summary["multipart_field"] == "file"
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


def test_encode_multipart_fixed_boundary(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    body, content_type = encode_multipart(pack, boundary="BOUND123")
    assert content_type == "multipart/form-data; boundary=BOUND123"
    assert body.startswith(b"--BOUND123\r\n")
    assert b'Content-Disposition: form-data; name="file"; filename="' in body
    assert body.rstrip(b"\r\n").endswith(b"--BOUND123--")
    assert pack.read_bytes() in body


def test_vanta_live_send_uses_multipart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = _pack(tmp_path)
    captured: dict[str, object] = {}

    class _Resp:
        status = 201

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(req: urllib.request.Request) -> _Resp:
        headers = {key.lower(): value for key, value in req.header_items()}
        captured["content_type"] = headers.get("content-type")
        captured["authorization"] = headers.get("authorization")
        raw = req.data
        captured["data_head"] = bytes(raw[:16]) if isinstance(raw, (bytes, bytearray)) else b""
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    request = build_request("vanta", pack, "WIT-ENG-001", document_id="D1", api_key="tok")
    summary = perform_export(request, dry_run=False)

    assert summary["sent"] is True
    assert summary["response_status"] == 201
    content_type = captured["content_type"]
    assert isinstance(content_type, str)
    assert content_type.startswith("multipart/form-data; boundary=")
    assert captured["authorization"] == "Bearer tok"
    data_head = captured["data_head"]
    assert isinstance(data_head, bytes)
    assert data_head.startswith(b"--")
