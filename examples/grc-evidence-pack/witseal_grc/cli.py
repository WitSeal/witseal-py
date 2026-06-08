"""CLI for the GRC evidence-pack example: ``evidence {pack,verify,export}``.

Mirrors the SDK CLI conventions: every command prints a single JSON object to
stdout (sorted keys); exit code is 0 on success, 1 on a verification failure,
2 on an input/usage error.

    python -m witseal_grc evidence pack   --source ./receipts --period 2026-06 \
                                          --control WIT-ENG-001 --public-key ./pubkey.pem
    python -m witseal_grc evidence verify --pack ./witseal-evidence-WIT-ENG-001-2026-06.zip
    python -m witseal_grc evidence export --target drata --control-code WIT-ENG-001 \
                                          --file ./witseal-evidence-WIT-ENG-001-2026-06.zip

This is an example built on the published ``witseal`` SDK. The ``evidence``
group is the GRC export surface and is distinct from the SDK's
``witseal verify evidence`` (which verifies a WitSeal evidence *package*).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from witseal.verify import load_public_key_pem

from .controls import known_controls
from .export import TARGETS, build_request, perform_export
from .pack import build_pack, verify_pack


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _input_error(message: str) -> int:
    sys.stderr.write(f"witseal-grc: {message}\n")
    return 2


def _load_public_key(value: str) -> Ed25519PublicKey:
    path = Path(value).expanduser()
    if path.is_file():
        return load_public_key_pem(path.read_bytes())
    normalized = value.strip()
    if normalized.startswith(("0x", "0X")):
        normalized = normalized[2:]
    raw = bytes.fromhex(normalized)
    if len(raw) != 32:
        raise ValueError("public key hex must decode to exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="witseal_grc",
        description="GRC evidence-pack example (build, verify, export).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    evidence = sub.add_parser("evidence", help="GRC evidence-pack commands")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)

    pack = evidence_sub.add_parser("pack", help="Build a control-mapped evidence pack")
    pack.add_argument("--source", type=Path, required=True, metavar="dir")
    pack.add_argument("--period", required=True, metavar="YYYY-MM")
    pack.add_argument(
        "--control",
        required=True,
        metavar="code",
        help=f"control code; known: {', '.join(known_controls())}",
    )
    pack.add_argument("--public-key", default=None, metavar="path-or-hex")
    pack.add_argument("--out", type=Path, default=None, metavar="dir")
    pack.add_argument("--format", dest="out_format", choices=("zip", "dir"), default="zip")
    pack.add_argument("--max-samples", type=int, default=5)

    verify = evidence_sub.add_parser("verify", help="Verify a pack's integrity offline")
    verify.add_argument("--pack", type=Path, required=True, metavar="path")

    export = evidence_sub.add_parser("export", help="Build (or send) a GRC export request")
    export.add_argument("--target", required=True, choices=TARGETS)
    export.add_argument("--control-code", required=True, metavar="code")
    export.add_argument("--file", type=Path, required=True, metavar="pack")
    export.add_argument("--api-key", default=None, metavar="token")
    export.add_argument("--connection-id", default="<DRATA_CONNECTION_ID>")
    export.add_argument("--resource-id", default="<DRATA_RESOURCE_ID>")
    export.add_argument("--document-id", default="<VANTA_DOCUMENT_ID>")
    export.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="actually send the request (requires --api-key and a real tenant)",
    )
    export.set_defaults(dry_run=True)

    return parser


def _pack_command(args: argparse.Namespace) -> int:
    public_key = None
    if args.public_key is not None:
        try:
            public_key = _load_public_key(args.public_key)
        except (OSError, ValueError) as exc:
            return _input_error(f"invalid public key: {exc}")
    try:
        result = build_pack(
            args.source,
            args.period,
            args.control,
            public_key=public_key,
            out_dir=args.out,
            out_format=args.out_format,
            max_samples=args.max_samples,
        )
    except KeyError as exc:
        return _input_error(f"unknown control: {exc}")
    except (OSError, ValueError) as exc:
        return _input_error(str(exc))

    _emit(
        {
            "pack_path": str(result.pack_path),
            "pack_id": result.pack_id,
            "control_code": result.control_code,
            "receipt_count": result.receipt_count,
            "verified_count": result.verified_count,
            "signature_checked": result.signature_checked,
            "redaction_count": len(result.redactions),
            "all_verified": result.verified_count == result.receipt_count,
        }
    )
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    verdict = verify_pack(args.pack)
    _emit(verdict)
    return 0 if verdict.get("valid") else 1


def _export_command(args: argparse.Namespace) -> int:
    try:
        request = build_request(
            args.target,
            args.file,
            args.control_code,
            connection_id=args.connection_id,
            resource_id=args.resource_id,
            document_id=args.document_id,
            api_key=args.api_key,
        )
    except (OSError, ValueError) as exc:
        return _input_error(str(exc))

    try:
        summary = perform_export(request, dry_run=args.dry_run)
    except OSError as exc:
        return _input_error(f"send failed: {exc}")

    _emit(summary)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "evidence":
        if args.evidence_command == "pack":
            return _pack_command(args)
        if args.evidence_command == "verify":
            return _verify_command(args)
        if args.evidence_command == "export":
            return _export_command(args)
    parser.error("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
