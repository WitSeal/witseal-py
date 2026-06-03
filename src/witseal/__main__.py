"""Verifier / SDK CLI for the Python track ([redacted] role B: consume/verify).

Scope is intentionally narrow: schema + read-side verification + keyless
inspection. No runtime execution, subprocess mediation, policy evaluation,
artifact generation, or implicit public-key discovery — generation is the
Rust track ([redacted]).

Commands:

  witseal verify receipt  <path> --public-key <path-or-hex>
  witseal verify evidence <path> [--public-key <path-or-hex>]
  witseal verify artifact <path> [--public-key <path-or-hex>]   (auto-discriminate)
  witseal inspect         <path>                                 (keyless)

All commands print a single JSON object to stdout (sorted keys); exit code
is 0 for VALID, 1 for INVALID, 2 for an input/usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from witseal.inspect import inspect_artifact
from witseal.schemas.receipt import ReceiptV02
from witseal.verify import (
    load_public_key_pem,
    verify_artifact,
    verify_evidence_package,
    verify_receipt,
)
from witseal.verify.result import VerificationResult


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="witseal",
        description=(
            "WitSeal Python verifier / SDK CLI "
            "(schema + read-side verification + keyless inspection only)."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify WitSeal artifacts")
    verify_subparsers = verify_parser.add_subparsers(
        dest="verify_command", required=True
    )

    receipt_parser = verify_subparsers.add_parser(
        "receipt",
        help="Verify a v0.2 receipt with an explicit Ed25519 public key",
    )
    receipt_parser.add_argument("receipt_path", type=Path, metavar="path")
    receipt_parser.add_argument(
        "--public-key",
        required=True,
        metavar="path-or-hex",
        help="Ed25519 public key as a PEM file path or 32-byte raw hex string",
    )

    evidence_parser = verify_subparsers.add_parser(
        "evidence",
        help="Verify an evidence package (chain + per-receipt integrity)",
    )
    evidence_parser.add_argument("artifact_path", type=Path, metavar="path")
    evidence_parser.add_argument(
        "--public-key",
        required=False,
        default=None,
        metavar="path-or-hex",
        help="Ed25519 public key (required only if the package holds a v0.2 receipt)",
    )

    artifact_parser = verify_subparsers.add_parser(
        "artifact",
        help="Verify any WitSeal artifact (auto-discriminate on schema_version)",
    )
    artifact_parser.add_argument("artifact_path", type=Path, metavar="path")
    artifact_parser.add_argument(
        "--public-key",
        required=False,
        default=None,
        metavar="path-or-hex",
        help="Ed25519 public key (required for v0.2 receipts / packages with one)",
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Keyless inspection of a WitSeal artifact (no signature check)",
    )
    inspect_parser.add_argument("artifact_path", type=Path, metavar="path")

    return parser


def _load_receipt(path: Path) -> ReceiptV02:
    return ReceiptV02.model_validate_json(path.read_bytes())


def _load_json_mapping(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("artifact must be a JSON object")
    return value


def _load_public_key_hex(value: str) -> Ed25519PublicKey:
    normalized = value.strip()
    if normalized.startswith(("0x", "0X")):
        normalized = normalized[2:]

    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            "public key must be an existing PEM path or 32-byte Ed25519 public key hex"
        ) from exc

    if len(raw) != 32:
        raise ValueError("public key hex must decode to exactly 32 bytes")

    return Ed25519PublicKey.from_public_bytes(raw)


def _load_public_key(value: str) -> Ed25519PublicKey:
    path = Path(value).expanduser()
    if path.is_file():
        return load_public_key_pem(path.read_bytes())
    return _load_public_key_hex(value)


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _print_result(result: VerificationResult) -> None:
    _emit(
        {
            "valid": result.valid,
            "receipt_hash_valid": result.receipt_hash_valid,
            "signature_valid": result.signature_valid,
            "reason": result.reason,
        }
    )


def _input_error(message: str) -> int:
    sys.stderr.write(f"witseal: {message}\n")
    return 2


def _resolve_optional_key(value: str | None) -> Ed25519PublicKey | None:
    if value is None:
        return None
    return _load_public_key(value)


def _verify_receipt_command(args: argparse.Namespace) -> int:
    try:
        receipt = _load_receipt(args.receipt_path)
    except OSError as exc:
        return _input_error(f"could not read receipt '{args.receipt_path}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid receipt '{args.receipt_path}': {exc}")

    try:
        public_key = _load_public_key(args.public_key)
    except OSError as exc:
        return _input_error(f"could not read public key '{args.public_key}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid public key: {exc}")

    try:
        result = verify_receipt(receipt, public_key)
    except ValueError as exc:
        return _input_error(f"invalid receipt signature encoding: {exc}")

    _print_result(result)
    return 0 if result.valid else 1


def _verify_evidence_command(args: argparse.Namespace) -> int:
    try:
        artifact = _load_json_mapping(args.artifact_path)
    except OSError as exc:
        return _input_error(f"could not read artifact '{args.artifact_path}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid artifact '{args.artifact_path}': {exc}")

    try:
        public_key = _resolve_optional_key(args.public_key)
    except OSError as exc:
        return _input_error(f"could not read public key '{args.public_key}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid public key: {exc}")

    result = verify_evidence_package(artifact, public_key)
    _emit(
        {
            "valid": result.valid,
            "kind": result.kind,
            "reason": result.reason,
            "chain_valid": result.chain_valid,
            "receipt_results": [
                {"index": r.index, "valid": r.valid, "reason": r.reason}
                for r in result.receipt_results
            ],
        }
    )
    return 0 if result.valid else 1


def _verify_artifact_command(args: argparse.Namespace) -> int:
    try:
        artifact = _load_json_mapping(args.artifact_path)
    except OSError as exc:
        return _input_error(f"could not read artifact '{args.artifact_path}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid artifact '{args.artifact_path}': {exc}")

    try:
        public_key = _resolve_optional_key(args.public_key)
    except OSError as exc:
        return _input_error(f"could not read public key '{args.public_key}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid public key: {exc}")

    result = verify_artifact(artifact, public_key)
    _emit(
        {
            "valid": result.valid,
            "kind": result.kind,
            "schema_version": result.schema_version,
            "reason": result.reason,
        }
    )
    return 0 if result.valid else 1


def _inspect_command(args: argparse.Namespace) -> int:
    try:
        artifact = _load_json_mapping(args.artifact_path)
    except OSError as exc:
        return _input_error(f"could not read artifact '{args.artifact_path}': {exc}")
    except ValueError as exc:
        return _input_error(f"invalid artifact '{args.artifact_path}': {exc}")

    inspection = inspect_artifact(artifact)
    _emit(
        {
            "kind": inspection.kind,
            "schema_version": inspection.schema_version,
            "fields": inspection.fields,
            "integrity": inspection.integrity,
            "notes": list(inspection.notes),
            "reason": inspection.reason,
        }
    )
    # Inspection is descriptive, not a pass/fail gate: exit 0 unless the
    # artifact was unrecognized / unparseable (kind == 'unknown' or a parse
    # reason was set).
    if inspection.kind == "unknown" or inspection.reason is not None:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        if args.verify_command == "receipt":
            return _verify_receipt_command(args)
        if args.verify_command == "evidence":
            return _verify_evidence_command(args)
        if args.verify_command == "artifact":
            return _verify_artifact_command(args)
    elif args.command == "inspect":
        return _inspect_command(args)

    parser.error("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
