"""Ed25519 signature verification for v0.2 receipts.

Reads a public key supplied externally (D5 T10: no bundled keys, no
env-var fallback, no network fetch). Verifies the algorithm-prefixed
signature on a :class:`~witseal.schemas.receipt.ReceiptV02` against the
canonical signing-bytes.

Signature wire format per RFC-002 § 6 (post-2026-05-23 amendment):
``ed25519:<88-char-base64>``. The prefix mirrors the ``sha256:`` digest
prefix of § 5; in schema version 0.2 the only permitted algorithm is
``ed25519``.

Returns ``bool`` rather than raising on invalid signature — caller (Phase C
reason classifier) maps to ``INVALID_SIGNATURE`` per RFC-002 § 4.
Malformed inputs (non-Ed25519 PEM, unrecognized algorithm tag,
undecodable base64) propagate as ``ValueError``: those are schema-level
errors, not signature-level errors, and the caller maps them to
``INVALID_SCHEMA`` per RFC-002 § 4 (`VerifierReason.INVALID_SCHEMA`).
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from witseal.integrity.signing import compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02

_SIGNATURE_ALGORITHM_V02: str = "ed25519"

# The externally-supplied verifier key, in any of the forms a caller already
# has on hand. NOT a network handle / key id: resolution is purely local
# (D5 T10 — no bundled keys, no env-var fallback, no network fetch).
PublicKeyInput = Ed25519PublicKey | str | bytes | os.PathLike[str]


def load_public_key_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes.

    Raises ``ValueError`` if the PEM does not decode to an Ed25519 key.
    """
    key = load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"expected Ed25519 public key, got {type(key).__name__}")
    return key


def _load_public_key_hex(value: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a 32-byte raw hex string.

    Accepts an optional ``0x`` / ``0X`` prefix. Raises ``ValueError`` if the
    string is not hex or does not decode to exactly 32 bytes.
    """
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


def resolve_public_key(value: PublicKeyInput) -> Ed25519PublicKey:
    """Resolve a caller-supplied public key in any of its on-hand forms.

    Accepts:

    - an already-loaded :class:`Ed25519PublicKey` (returned unchanged);
    - a filesystem path (``str`` / :class:`os.PathLike`) to a PEM file —
      read and loaded via :func:`load_public_key_pem`;
    - a 32-byte raw Ed25519 public key as a hex ``str`` (optional ``0x``
      prefix);
    - PEM ``bytes`` (a ``-----BEGIN PUBLIC KEY-----`` block).

    A ``str`` that names an existing file is read as PEM; otherwise it is
    parsed as hex. Resolution is purely local — no network fetch, no
    environment-variable fallback, no bundled key (D5 T10): the key is
    always an explicit verifier input.

    Raises ``ValueError`` for an unparseable key and ``OSError`` for an
    unreadable PEM path.
    """
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, bytes):
        return load_public_key_pem(value)
    if isinstance(value, os.PathLike):
        return load_public_key_pem(Path(value).expanduser().read_bytes())
    # ``str``: an existing file is a PEM path; anything else is raw hex.
    path = Path(value).expanduser()
    if path.is_file():
        return load_public_key_pem(path.read_bytes())
    return _load_public_key_hex(value)


def _split_signature_value(signature_value: str) -> bytes:
    """Split a v0.2 signature value into raw bytes for cryptographic verify.

    Per RFC-002 § 6 amendment 2026-05-23, the wire value is
    ``<algorithm>:<base64-payload>``. In schema version 0.2 the only
    permitted algorithm is ``ed25519``; any other tag is a schema-level
    malformation and raises ``ValueError`` (caller maps to ``INVALID_SCHEMA``).

    The schema-layer ``Ed25519SignaturePrefixed`` validator catches malformed
    values at parse time; this helper is a defensive split for callers that
    construct receipts by hand or pass a raw dict, and to keep the verifier
    self-contained.
    """
    if ":" not in signature_value:
        raise ValueError(
            "signature value missing '<algorithm>:' prefix; "
            f"v0.2 schema requires '{_SIGNATURE_ALGORITHM_V02}:' prefix"
        )
    algorithm, _, payload = signature_value.partition(":")
    if algorithm != _SIGNATURE_ALGORITHM_V02:
        raise ValueError(
            f"unsupported signature algorithm '{algorithm}' in v0.2 receipt; "
            f"only '{_SIGNATURE_ALGORITHM_V02}' is permitted "
            "(future algorithms reserved for v0.3+ per RFC-002 § 6 amendment)"
        )
    return base64.b64decode(payload, validate=True)


def verify_receipt_signature(
    receipt: ReceiptV02, public_key: Ed25519PublicKey
) -> bool:
    """Return ``True`` iff the receipt's signature is valid under ``public_key``.

    Does not raise on invalid signature — returns ``False``. Malformed
    ``signature`` (missing or wrong algorithm prefix, undecodable base64)
    propagates as ``ValueError``; caller maps to ``INVALID_SCHEMA``.
    """
    signature_bytes = _split_signature_value(receipt.signature)
    canonical_bytes = compute_signing_bytes(receipt)
    try:
        public_key.verify(signature_bytes, canonical_bytes)
        return True
    except InvalidSignature:
        return False
