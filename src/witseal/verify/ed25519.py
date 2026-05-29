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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from witseal.integrity.signing import compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02

_SIGNATURE_ALGORITHM_V02: str = "ed25519"


def load_public_key_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes.

    Raises ``ValueError`` if the PEM does not decode to an Ed25519 key.
    """
    key = load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"expected Ed25519 public key, got {type(key).__name__}")
    return key


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
