"""Cross-track golden v0.2 receipt verification (independent cross-check / D6 § 8.1).

Proves the Python track *independently* validates the canonical v0.2
``receipt`` produced by the Rust track:

- the Python schema parses the 17-field v0.2 receipt;
- Python re-derives the test public key from the documented seed and gets
  the same bytes as the canon;
- Python's S1 pre-image (``receipt_hash`` -> 64 zeros, ``signature`` ->
  ``""``, RFC 8785 canonical) hashes to the *stored* ``receipt_hash``;
- the stored Ed25519 signature verifies over that pre-image;
- Python's canonical bytes of the final wire receipt are byte-identical to
  ``rust-golden.canonical`` (the cross-track source of truth, 1050 bytes,
  ``SHA-256 = 8fc29592...``).

Fixtures are vendored under ``tests/fixtures/golden-receipt/`` (see that
directory's README); the test is hermetic.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from witseal.integrity.canonical_json import canonicalize
from witseal.integrity.hash import sha256_hex_of_bytes
from witseal.integrity.signing import compute_receipt_hash, compute_signing_bytes
from witseal.schemas.receipt import ReceiptV02
from witseal.verify import load_public_key_pem, verify_receipt, verify_receipt_signature

_FIXTURES = Path(__file__).parent / "fixtures" / "golden-receipt"
_GOLDEN_JSON = _FIXTURES / "rust-golden.json"
_GOLDEN_CANONICAL = _FIXTURES / "rust-golden.canonical"
_GOLDEN_SIG = _FIXTURES / "rust-golden.sig"
_KEY_JSON = _FIXTURES / "test-only-do-not-use-in-prod.key.json"

# Reference values asserted independently of the fixture files so a silently
# corrupted/swapped fixture cannot make the suite pass vacuously.
_REF_CANONICAL_SHA256 = (
    "8fc29592fd3317e48caccc9b5c64d01cfa32d5e27846c50f233829e1bb17ef1b"
)
_REF_CANONICAL_LEN = 1050
_REF_RECEIPT_HASH = (
    "199304f0ba3c8260f40fa6d7358ec6ff7b5c1d3c1c97a49e2f729f022eca9651"
)
_REF_PUBLIC_KEY_HEX = (
    "fd62f46e4e64333ef4c0693e9caf52a540cb21a3546547f016bcd0e990c91862"
)
_KEY_SEED_STRING = b"witseal-v0.2-golden-receipt-test-key-0001"


def _golden_receipt() -> ReceiptV02:
    return ReceiptV02.model_validate(json.loads(_GOLDEN_JSON.read_text()))


def _derive_test_public_key() -> Ed25519PrivateKey:
    """Re-derive the deterministic test signing key per key.json `derivation`.

    seed_bytes_32 = sha256(utf8(seed_string)); SigningKey::from_bytes(seed).
    The *private* key is reconstructed only to obtain its public key — the
    production verifier path never touches a private key (D5 T10).
    """
    seed = hashlib.sha256(_KEY_SEED_STRING).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def test_golden_fixture_integrity() -> None:
    """Guard: the vendored canonical fixture is the expected 1050 bytes with
    the expected digest. If this fails, the fixture was corrupted or the
    wrong file vendored — every downstream golden assertion is suspect."""
    canonical = _GOLDEN_CANONICAL.read_bytes()
    assert len(canonical) == _REF_CANONICAL_LEN
    assert sha256_hex_of_bytes(canonical) == _REF_CANONICAL_SHA256


def test_golden_key_derivation_matches_canon() -> None:
    """Python re-derives the same Ed25519 public key bytes as the canon."""
    pub = _derive_test_public_key().public_key()
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert pub_hex == _REF_PUBLIC_KEY_HEX
    # The key.json fixture must also document that value.
    key_doc = json.loads(_KEY_JSON.read_text())
    assert key_doc["derivation"]["public_key_bytes_hex"] == _REF_PUBLIC_KEY_HEX


def test_golden_receipt_parses_as_v0_2_with_17_fields() -> None:
    receipt = _golden_receipt()
    assert receipt.schema_version == "witseal.receipt.v0.2"
    # 17 v0.2 wire fields, incl. artifact_type + build_id.
    assert len(receipt.model_dump()) == 17
    assert receipt.artifact_type == "generic-binary"
    assert receipt.build_id == "witseal-golden-build-0001"
    assert receipt.prev_hash is None  # chain-genesis, explicit null


def test_golden_wire_bytes_byte_identical() -> None:
    """Python's RFC 8785 canonical bytes of the final wire receipt are
    byte-identical to the cross-track source-of-truth blob."""
    receipt = _golden_receipt()
    wire = canonicalize(receipt.model_dump(by_alias=True))
    expected = _GOLDEN_CANONICAL.read_bytes()
    assert wire == expected, "Python wire bytes diverge from rust-golden.canonical"
    assert sha256_hex_of_bytes(wire) == _REF_CANONICAL_SHA256


def test_golden_receipt_hash_recomputed_independently() -> None:
    """receipt_hash = SHA-256(S1 pre-image). Python recomputes it from the
    receipt body alone and matches the stored value."""
    receipt = _golden_receipt()
    recomputed = compute_receipt_hash(receipt)
    assert recomputed == _REF_RECEIPT_HASH
    assert recomputed == receipt.receipt_hash


def test_golden_s1_preimage_is_954_bytes_not_empty_string_form() -> None:
    """Regression guard against the pre-2026-05 empty-string sentinel.

    The correct S1 pre-image (receipt_hash -> 64 zeros) hashes to the
    stored receipt_hash. The old empty-string form does NOT — assert the
    correct form matches and the old form would not."""
    receipt = _golden_receipt()
    preimage = compute_signing_bytes(receipt)
    assert sha256_hex_of_bytes(preimage) == _REF_RECEIPT_HASH

    # Old (incorrect) form: receipt_hash cleared to "".
    body = receipt.model_dump(by_alias=True)
    body["receipt_hash"] = ""
    body["signature"] = ""
    old_form = canonicalize(body)
    assert sha256_hex_of_bytes(old_form) != _REF_RECEIPT_HASH, (
        "empty-string receipt_hash sentinel must NOT reproduce the golden "
        "receipt_hash — confirms the 64-zero placeholder is the reconciled S1"
    )


def test_golden_signature_verifies_over_preimage() -> None:
    """The stored Ed25519 signature verifies over Python's S1 pre-image."""
    receipt = _golden_receipt()
    pub = _derive_test_public_key().public_key()
    assert verify_receipt_signature(receipt, pub) is True


def test_golden_signature_matches_detached_sig_fixture() -> None:
    """The receipt's signature field equals the detached rust-golden.sig and
    decodes to the 64-byte raw Ed25519 signature."""
    receipt = _golden_receipt()
    detached = _GOLDEN_SIG.read_text().strip()
    assert receipt.signature == detached
    _, _, payload = receipt.signature.partition(":")
    assert len(base64.b64decode(payload, validate=True)) == 64


def test_golden_receipt_verifies_valid_via_load_pem_round_trip() -> None:
    """End-to-end: load the public key as PEM (production shape — key
    arrives externally), then `verify_receipt` returns VALID with both
    component checks passing."""
    pub = _derive_test_public_key().public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    loaded = load_public_key_pem(pem)

    result = verify_receipt(_golden_receipt(), loaded)
    assert result.valid is True
    assert result.receipt_hash_valid is True
    assert result.signature_valid is True
    assert result.reason is None
    assert bool(result) is True


def test_golden_receipt_invalid_under_wrong_key() -> None:
    """A different key fails signature verification -> INVALID, even though
    receipt_hash still matches (receipt_hash is key-independent)."""
    wrong = Ed25519PrivateKey.generate().public_key()
    result = verify_receipt(_golden_receipt(), wrong)
    assert result.valid is False
    assert result.receipt_hash_valid is True
    assert result.signature_valid is False
    assert result.reason == "INVALID_SIGNATURE"


def test_golden_receipt_invalid_when_body_tampered() -> None:
    """Tampering a signed field breaks BOTH receipt_hash and signature."""
    pub = _derive_test_public_key().public_key()
    tampered = _golden_receipt().model_copy(update={"build_id": "tampered"})
    result = verify_receipt(tampered, pub)
    assert result.valid is False
    assert result.receipt_hash_valid is False
    assert result.signature_valid is False
