"""Tests for `witseal.integrations.mcp` — the MCP consume/verify seam.

Two layers are exercised:

1. The pure consumer :func:`verify_witseal_artifact` — VALID / INVALID over
   v0.1 and v0.2 receipts and an evidence package, plus the input-coercion
   (mapping / JSON str / JSON bytes) and public-key resolution surface. Keys
   are minted locally with ``Ed25519PrivateKey.generate()`` (mirroring
   tests/test_verify_receipt.py); the production verifier path never sees a
   private key.
2. The optional MCP protocol surface (:func:`build_mcp_server` /
   :func:`register_witseal_tools`) — that the verify-only tool registers and
   answers — and the guarantee that importing the module works WITHOUT the
   ``mcp`` extra installed.
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from tests._artifact_builders import (
    make_evidence_package,
    two_event_chain,
    v01_receipt_dict,
    v02_receipt_dict,
)
from witseal.integrations.mcp import (
    build_mcp_server,
    register_witseal_tools,
    verify_witseal_artifact,
)
from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02

_HASH2 = "b" * 64
_HASH3 = "c" * 64
_HASH4 = "d" * 64
_HASH5 = "e" * 64
_TS = "2026-05-19T20:00:00Z"
_EVT_ID = "evt_" + "0" * 22
_RCPT_ID = "rcpt_" + "0" * 22
_DIGEST = "sha256:" + "a" * 64
_ATTEST = "sha256:" + "b" * 64
_GIT_SHA = "0" * 40
_PLACEHOLDER_SIG = "ed25519:" + "A" * 86 + "=="


def _unsigned_v02() -> ReceiptV02:
    """A standalone v0.2 receipt (mirrors tests/test_verify_receipt.py)."""
    return ReceiptV02.model_validate(
        {
            "schema_version": "witseal.receipt.v0.2",
            "receipt_id": _RCPT_ID,
            "witness_event_id": _EVT_ID,
            "chain_segment_id": "default",
            "finalized_at": _TS,
            "receipt_hash": "0" * 64,
            "policy_decision_hash": _HASH2,
            "classified_intent_hash": _HASH3,
            "execution_result_hash": _HASH4,
            "outcome": "allowed_executed",
            "artifact_digest": _DIGEST,
            "artifact_type": "generic-binary",
            "build_id": "local",
            "git_commit": _GIT_SHA,
            "attestation_digest": _ATTEST,
            "signature": _PLACEHOLDER_SIG,
            "prev_hash": _HASH5,
        }
    )


def _finalize_v02(receipt: ReceiptV02, priv: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a fully valid v0.2 receipt as a wire dict (hash + signature set)."""
    receipt_hash = compute_receipt_hash(receipt)
    sealed = receipt.model_copy(update={"receipt_hash": receipt_hash})
    sig_bytes = priv.sign(compute_signing_bytes(sealed))
    sig = "ed25519:" + base64.b64encode(sig_bytes).decode("ascii")
    return sealed.model_copy(update={"signature": sig}).model_dump(by_alias=True)


def _pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def _hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# ---------------------------------------------------------------------------
# Core consumer: verify_witseal_artifact — VALID / INVALID
# ---------------------------------------------------------------------------


def test_v01_receipt_valid_no_key() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = verify_witseal_artifact(receipt)
    assert result["valid"] is True
    assert result["kind"] == "receipt.v0.1"
    assert result["schema_version"] == "witseal.receipt.v0.1"
    assert result["reason"] is None


def test_v01_receipt_invalid_tampered_self_hash() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    receipt["receipt_hash"] = "9" * 64
    result = verify_witseal_artifact(receipt)
    assert result["valid"] is False
    assert result["kind"] == "receipt.v0.1"
    assert "self-hash" in (result["reason"] or "")


def test_v02_receipt_valid_with_minted_key() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = verify_witseal_artifact(receipt, public_key=priv.public_key())
    assert result["valid"] is True
    assert result["kind"] == "receipt.v0.2"
    assert result["schema_version"] == "witseal.receipt.v0.2"
    assert result["reason"] is None


def test_v02_receipt_invalid_wrong_key() -> None:
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = verify_witseal_artifact(receipt, public_key=other.public_key())
    assert result["valid"] is False
    assert result["kind"] == "receipt.v0.2"
    assert result["reason"] == "INVALID_SIGNATURE"


def test_v02_receipt_without_key_fails_clearly() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = verify_witseal_artifact(receipt)
    assert result["valid"] is False
    assert result["kind"] == "receipt.v0.2"
    assert "public key" in (result["reason"] or "")


def test_evidence_package_v01_valid() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    result = verify_witseal_artifact(pkg)
    assert result["valid"] is True
    assert result["kind"] == "evidence-package.v0.1"


def test_evidence_package_v02_valid_with_key() -> None:
    priv = Ed25519PrivateKey.generate()
    events = two_event_chain()
    pkg = make_evidence_package(
        events,
        [v02_receipt_dict(events[0], priv), v02_receipt_dict(events[1], priv)],
    )
    result = verify_witseal_artifact(pkg, public_key=priv.public_key())
    assert result["valid"] is True
    assert result["kind"] == "evidence-package.v0.1"


def test_evidence_package_invalid_tampered_event() -> None:
    events = two_event_chain()
    pkg = make_evidence_package(
        events, [v01_receipt_dict(events[0]), v01_receipt_dict(events[1])]
    )
    # Break the chain head so the package fails verification.
    pkg["chain_head_after_range"] = "9" * 64
    result = verify_witseal_artifact(pkg)
    assert result["valid"] is False
    assert result["kind"] == "evidence-package.v0.1"
    assert result["reason"] is not None


def test_unknown_artifact_rejected() -> None:
    result = verify_witseal_artifact({"schema_version": "witseal.bogus.v9"})
    assert result["valid"] is False
    assert result["kind"] == "unknown"


# ---------------------------------------------------------------------------
# Input coercion: mapping / JSON str / JSON bytes
# ---------------------------------------------------------------------------


def test_accepts_json_string() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = verify_witseal_artifact(json.dumps(receipt))
    assert result["valid"] is True
    assert result["kind"] == "receipt.v0.1"


def test_accepts_json_bytes() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = verify_witseal_artifact(json.dumps(receipt).encode("utf-8"))
    assert result["valid"] is True
    assert result["kind"] == "receipt.v0.1"


def test_mapping_str_bytes_agree() -> None:
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    as_map = verify_witseal_artifact(receipt)
    as_str = verify_witseal_artifact(json.dumps(receipt))
    as_bytes = verify_witseal_artifact(json.dumps(receipt).encode("utf-8"))
    assert as_map == as_str == as_bytes


def test_invalid_json_raises_value_error() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        verify_witseal_artifact("{not json")


def test_non_object_json_raises_value_error() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        verify_witseal_artifact("[1, 2, 3]")


def test_non_mapping_value_raises_value_error() -> None:
    with pytest.raises(ValueError, match="must be a mapping or JSON"):
        verify_witseal_artifact(12345)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Public-key resolution forms (PEM bytes, PEM path, hex, loaded key)
# ---------------------------------------------------------------------------


def test_key_as_pem_bytes(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = verify_witseal_artifact(receipt, public_key=_pem(priv))
    assert result["valid"] is True


def test_key_as_pem_path(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    pem_file = tmp_path / "pub.pem"
    pem_file.write_bytes(_pem(priv))
    result = verify_witseal_artifact(receipt, public_key=str(pem_file))
    assert result["valid"] is True


def test_key_as_hex_string() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = verify_witseal_artifact(receipt, public_key=_hex(priv))
    assert result["valid"] is True


def test_malformed_key_raises() -> None:
    priv = Ed25519PrivateKey.generate()
    receipt = _finalize_v02(_unsigned_v02(), priv)
    with pytest.raises(ValueError):
        verify_witseal_artifact(receipt, public_key="not-a-key")


# ---------------------------------------------------------------------------
# No-extra import guard: importing the module must NOT require `mcp`
# ---------------------------------------------------------------------------


def test_import_without_mcp_extra() -> None:
    """`import witseal.integrations.mcp` and the core verifier must work even
    when the `mcp` SDK is absent. Runs in a fresh interpreter with `mcp` (and
    its top-level submodules) blocked from import, so the dev group having
    `mcp` installed cannot mask a regression."""
    script = (
        "import builtins\n"
        "_real_import = builtins.__import__\n"
        "def _blocked(name, *a, **k):\n"
        "    if name == 'mcp' or name.startswith('mcp.'):\n"
        "        raise ModuleNotFoundError(\"No module named 'mcp'\")\n"
        "    return _real_import(name, *a, **k)\n"
        "builtins.__import__ = _blocked\n"
        "import sys\n"
        "assert 'mcp' not in sys.modules, 'mcp pre-imported'\n"
        "import witseal.integrations.mcp as m\n"
        "assert 'mcp' not in sys.modules, 'importing the module pulled in mcp'\n"
        "r = m.verify_witseal_artifact({'schema_version': 'witseal.bogus.v9'})\n"
        "assert r['kind'] == 'unknown' and r['valid'] is False\n"
        "print('NO_EXTRA_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "NO_EXTRA_OK" in proc.stdout


def test_build_mcp_server_reports_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the `mcp` SDK cannot be imported, build_mcp_server raises an
    actionable ModuleNotFoundError that names the extra (the core verifier
    stays usable)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        if name == "mcp.server.fastmcp" or name.startswith("mcp."):
            raise ModuleNotFoundError("No module named 'mcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ModuleNotFoundError, match=r"witseal\[mcp\]"):
        build_mcp_server()


# ---------------------------------------------------------------------------
# MCP protocol surface (requires the `mcp` extra — present in the dev group)
# ---------------------------------------------------------------------------

pytest.importorskip("mcp.server.fastmcp")


def _tool_text(result: Any) -> dict[str, Any]:  # noqa: ANN401
    """Extract the JSON dict from a FastMCP call_tool result, tolerant of the
    list-of-content and (content, structured) return shapes across mcp
    versions."""
    content = result[0] if isinstance(result, tuple) else result
    # Prefer the structured payload when the tuple form provides one.
    if isinstance(result, tuple) and len(result) > 1 and isinstance(result[1], dict):
        structured = result[1]
        # FastMCP wraps a bare dict return under a "result" key in some
        # versions; unwrap when present.
        return structured.get("result", structured)
    text = content[0].text
    parsed = json.loads(text)
    assert isinstance(parsed, dict)
    return parsed


def test_build_mcp_server_registers_only_verify_tool() -> None:
    server = build_mcp_server()
    tools = asyncio.run(server.list_tools())
    names = [t.name for t in tools]
    assert names == ["witseal.verify_artifact"]


def test_register_on_existing_server_returns_it() -> None:
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("host")
    returned = register_witseal_tools(server)
    assert returned is server
    tools = asyncio.run(server.list_tools())
    assert "witseal.verify_artifact" in [t.name for t in tools]


def test_tool_verifies_valid_v01_receipt() -> None:
    server = build_mcp_server()
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = asyncio.run(
        server.call_tool("witseal.verify_artifact", {"artifact": receipt})
    )
    verdict = _tool_text(result)
    assert verdict["valid"] is True
    assert verdict["kind"] == "receipt.v0.1"


def test_tool_verifies_valid_v02_with_server_default_key() -> None:
    priv = Ed25519PrivateKey.generate()
    server = build_mcp_server(public_key=priv.public_key())
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = asyncio.run(
        server.call_tool("witseal.verify_artifact", {"artifact": receipt})
    )
    verdict = _tool_text(result)
    assert verdict["valid"] is True
    assert verdict["kind"] == "receipt.v0.2"


def test_tool_accepts_per_call_key_hex() -> None:
    priv = Ed25519PrivateKey.generate()
    server = build_mcp_server()  # no default key
    receipt = _finalize_v02(_unsigned_v02(), priv)
    result = asyncio.run(
        server.call_tool(
            "witseal.verify_artifact",
            {"artifact": receipt, "public_key_pem_or_hex": _hex(priv)},
        )
    )
    verdict = _tool_text(result)
    assert verdict["valid"] is True


def test_tool_accepts_json_string_artifact() -> None:
    server = build_mcp_server()
    events = two_event_chain()
    receipt = v01_receipt_dict(events[0])
    result = asyncio.run(
        server.call_tool(
            "witseal.verify_artifact", {"artifact": json.dumps(receipt)}
        )
    )
    verdict = _tool_text(result)
    assert verdict["valid"] is True
