"""Demo scaffolding: mint sample signed v0.2 receipts to drive the example.

This mirrors ``tests/_artifact_builders.py`` in the SDK: it builds sample
artifacts ONLY so the read-side example has something to consume. It is not
a runtime generator — canonical generation is the Rust trust core. Use it to
produce a folder of receipts plus the matching public key, then run
``python -m witseal_grc pack`` against them.

    python -m witseal_grc.samples ./receipts --count 4 --key-out ./pubkey.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02

_FINALIZED_AT = "2026-06-08T12:00:00Z"


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """A throwaway Ed25519 keypair for the demo."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    """PEM (SubjectPublicKeyInfo) bytes for *public_key*."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_signed_receipt(
    index: int,
    private_key: Ed25519PrivateKey,
    *,
    prev_hash: str | None = None,
) -> dict[str, Any]:
    """A self-consistent, correctly-signed sample v0.2 receipt.

    Hash fields carry illustrative (fixed) digests; ``receipt_hash`` and
    ``signature`` are computed for real via the SDK integrity helpers, so the
    receipt verifies under the matching public key.
    """
    suffix = f"{index:022d}"
    base: dict[str, Any] = {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": "rcpt_" + suffix,
        "witness_event_id": "evt_" + suffix,
        "chain_segment_id": "seg-demo",
        "finalized_at": _FINALIZED_AT,
        "receipt_hash": "0" * 64,
        "policy_decision_hash": "a" * 64,
        "classified_intent_hash": "b" * 64,
        "execution_result_hash": "c" * 64,
        "outcome": "allowed_executed",
        "artifact_digest": "sha256:" + "e" * 64,
        "artifact_type": "generic-binary",
        "build_id": f"demo-build-{index:04d}",
        "git_commit": "0" * 40,
        "attestation_digest": "sha256:" + "f" * 64,
        "signature": "ed25519:" + "A" * 86 + "==",
        "prev_hash": prev_hash,
    }
    receipt = ReceiptV02.model_validate(base)
    receipt = receipt.model_copy(update={"receipt_hash": compute_receipt_hash(receipt)})
    signature = private_key.sign(compute_signing_bytes(receipt))
    signed = "ed25519:" + base64.b64encode(signature).decode("ascii")
    receipt = receipt.model_copy(update={"signature": signed})
    dumped: dict[str, Any] = receipt.model_dump(by_alias=True)
    return dumped


def write_sample_receipts(
    out_dir: Path,
    count: int,
    private_key: Ed25519PrivateKey,
) -> list[Path]:
    """Write *count* signed receipts as JSON files into *out_dir*."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for index in range(count):
        receipt = build_signed_receipt(index, private_key)
        path = out_dir / f"receipt-{index:04d}.json"
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="witseal_grc.samples",
        description="Mint sample signed v0.2 receipts + the matching public key.",
    )
    parser.add_argument("out_dir", type=Path, metavar="dir")
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--key-out", type=Path, default=Path("pubkey.pem"))
    args = parser.parse_args(argv)

    private_key, public_key = generate_keypair()
    paths = write_sample_receipts(args.out_dir, args.count, private_key)
    args.key_out.write_bytes(public_key_pem(public_key))

    sys.stdout.write(
        json.dumps(
            {
                "receipts_written": len(paths),
                "out_dir": str(args.out_dir),
                "public_key": str(args.key_out),
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
