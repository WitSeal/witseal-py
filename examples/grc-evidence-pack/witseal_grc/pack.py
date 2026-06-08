"""Build and verify a control-mapped evidence pack from WitSeal receipts.

Read-side only. ``build_pack`` consumes a folder of already-generated
receipts, verifies each one through the published SDK (``witseal.verify``
when a public key is supplied, else keyless ``witseal.inspect``), and bundles
a set of report files. The pack is a bundle of reports — it mints no WitSeal
canonical artifact, and its ``hash_manifest.txt`` is integrity over the pack's
own files, not a WitSeal chain hash.

Pack files:

  manifest.json · receipt_samples.json · verification_results.json
  control_mapping.json · redaction_report.json · executive_summary.md
  hash_manifest.txt   (SHA-256 of every other file, for offline integrity)
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from witseal.inspect import inspect_artifact
from witseal.verify import verify_artifact

from .controls import CONTROL_CATALOG, control_mapping
from .redaction import DEFAULT_REDACT_FIELDS, RedactionEntry, redact_receipt

#: Report files a pack always contains, besides the hash manifest.
_CONTENT_FILES = (
    "manifest.json",
    "receipt_samples.json",
    "verification_results.json",
    "control_mapping.json",
    "redaction_report.json",
    "executive_summary.md",
)
_HASH_MANIFEST = "hash_manifest.txt"


@dataclass(frozen=True, slots=True)
class ReceiptVerification:
    """Independent verification outcome for one source receipt."""

    receipt_id: str | None
    source_file: str
    valid: bool
    signature_checked: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class PackResult:
    """Summary of a built pack."""

    pack_path: Path
    pack_id: str
    control_code: str
    receipt_count: int
    verified_count: int
    signature_checked: bool
    verifications: tuple[ReceiptVerification, ...]
    redactions: tuple[RedactionEntry, ...]
    file_hashes: dict[str, str]


def _dumps(obj: object) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load_receipt(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(f"{path.name}: receipt must be a JSON object")
    return value


def _discover_receipts(source: Path) -> list[tuple[str, Mapping[str, Any]]]:
    if not source.is_dir():
        raise ValueError(f"source '{source.name}' is not a directory")
    receipts: list[tuple[str, Mapping[str, Any]]] = []
    for path in sorted(source.glob("*.json")):
        receipts.append((path.name, _load_receipt(path)))
    return receipts


def _verify_one(
    receipt: Mapping[str, Any], public_key: Ed25519PublicKey | None
) -> tuple[bool, bool, str | None]:
    """Return ``(valid, signature_checked, reason)`` for one receipt."""
    if public_key is not None:
        result = verify_artifact(receipt, public_key)
        return result.valid, True, result.reason
    inspection = inspect_artifact(receipt)
    self_hash_ok = inspection.integrity.get("receipt_hash_self_consistent", False)
    reason = inspection.reason or "signature not checked (no public key supplied)"
    return self_hash_ok, False, reason


def _pack_id(control_code: str, period: str, receipt_ids: Sequence[str]) -> str:
    seed = "|".join([control_code, period, *receipt_ids]).encode("utf-8")
    # 'evp_' (evidence-pack) prefix — deliberately distinct from a WitSeal
    # canonical 'pkg_' package id; this is a GRC bundle id, not a chain object.
    return "evp_" + hashlib.sha256(seed).hexdigest()[:24]


def _frameworks_line(frameworks: Mapping[str, list[str]]) -> str:
    return "; ".join(f"{name}: {', '.join(codes)}" for name, codes in frameworks.items())


def _summary_md(
    control_code: str,
    period: str,
    generated_at: str,
    receipt_count: int,
    verified_count: int,
    signature_checked: bool,
    frameworks: Mapping[str, list[str]],
) -> str:
    spec = CONTROL_CATALOG[control_code]
    checked = (
        "signature-checked" if signature_checked else "keyless self-hash only"
    )
    return (
        f"# WitSeal evidence pack — {control_code}\n\n"
        f"- Control: {control_code} — {spec['title']}\n"
        f"- Frameworks: {_frameworks_line(frameworks)}\n"
        f"- Period: {period}\n"
        f"- Generated: {generated_at}\n"
        f"- Receipts: {receipt_count} (verified: {verified_count}, {checked})\n\n"
        "## What this pack shows\n\n"
        "This pack bundles signed WitSeal execution receipts for AI-assisted "
        "engineering actions in the period above and maps them to the control "
        "named above. For each receipt it records an independent verification "
        "result, and it includes a redaction report and a per-file hash "
        "manifest so a reviewer can confirm pack integrity offline, without "
        "contacting WitSeal.\n\n"
        "Receipts are hash-based by design: intent, policy decision and result "
        "are carried as SHA-256 digests, so sharing this pack discloses no "
        "source content.\n"
    )


def build_pack(
    source: Path,
    period: str,
    control_code: str,
    *,
    public_key: Ed25519PublicKey | None = None,
    out_dir: Path | None = None,
    out_format: str = "zip",
    generated_at: str | None = None,
    redact_fields: Sequence[str] = DEFAULT_REDACT_FIELDS,
    max_samples: int = 5,
) -> PackResult:
    """Build an evidence pack for *control_code* from receipts in *source*.

    *public_key* (optional) enables full signature verification; without it,
    receipts are checked keyless (self-hash only) and the pack records that
    signatures were not checked. Raises :class:`KeyError` for an unknown
    control and :class:`ValueError` if no receipts are found.
    """
    if control_code not in CONTROL_CATALOG:
        raise KeyError(f"unknown control '{control_code}'")

    discovered = _discover_receipts(source)
    if not discovered:
        raise ValueError(f"no receipt JSON files found in '{source.name}'")

    generated = generated_at or datetime.now(UTC).isoformat()

    verifications: list[ReceiptVerification] = []
    redactions: list[RedactionEntry] = []
    samples: list[dict[str, Any]] = []
    receipt_ids: list[str] = []

    for index, (filename, receipt) in enumerate(discovered):
        rid_raw = receipt.get("receipt_id")
        rid = rid_raw if isinstance(rid_raw, str) else None
        receipt_ids.append(rid or filename)

        valid, signature_checked, reason = _verify_one(receipt, public_key)
        verifications.append(
            ReceiptVerification(rid, filename, valid, signature_checked, reason)
        )

        if index < max_samples:
            redacted, entries = redact_receipt(index, receipt, redact_fields)
            samples.append(redacted)
            redactions.extend(entries)

    verified_count = sum(1 for v in verifications if v.valid)
    signature_checked = public_key is not None
    pack_id = _pack_id(control_code, period, receipt_ids)
    mapping = control_mapping(control_code, receipt_ids)
    frameworks_obj = mapping["frameworks"]
    assert isinstance(frameworks_obj, dict)

    content: dict[str, bytes] = {
        "manifest.json": _dumps(
            {
                "tool": "witseal-grc-evidence-pack (example)",
                "pack_id": pack_id,
                "control_code": control_code,
                "period": period,
                "generated_at": generated,
                "receipt_count": len(discovered),
                "verified_count": verified_count,
                "signature_checked": signature_checked,
                "source": source.resolve().name or "receipts",
                "pack_files": sorted([*_CONTENT_FILES, _HASH_MANIFEST]),
                "schema_note": (
                    "Read-side evidence pack over verified WitSeal receipts; "
                    "not a WitSeal canonical artifact."
                ),
            }
        ),
        "receipt_samples.json": _dumps(samples),
        "verification_results.json": _dumps(
            {
                "signature_checked": signature_checked,
                "receipt_count": len(discovered),
                "verified_count": verified_count,
                "results": [
                    {
                        "receipt_id": v.receipt_id,
                        "source_file": v.source_file,
                        "valid": v.valid,
                        "signature_checked": v.signature_checked,
                        "reason": v.reason,
                    }
                    for v in verifications
                ],
            }
        ),
        "control_mapping.json": _dumps(mapping),
        "redaction_report.json": _dumps(
            {
                "policy": {
                    "redact_fields": list(redact_fields),
                    "note": (
                        "Receipts are hash-based; redaction applies to "
                        "shareable copies only. Verification is performed on "
                        "originals."
                    ),
                },
                "redaction_count": len(redactions),
                "redactions": [
                    {
                        "receipt_index": r.receipt_index,
                        "receipt_id": r.receipt_id,
                        "field": r.field,
                        "rule": r.rule,
                    }
                    for r in redactions
                ],
            }
        ),
        "executive_summary.md": _summary_md(
            control_code,
            period,
            generated,
            len(discovered),
            verified_count,
            signature_checked,
            frameworks_obj,
        ).encode("utf-8"),
    }

    file_hashes = {
        name: hashlib.sha256(data).hexdigest() for name, data in sorted(content.items())
    }
    hash_manifest = "".join(
        f"{file_hashes[name]}  {name}\n" for name in sorted(file_hashes)
    ).encode("utf-8")

    all_files = {**content, _HASH_MANIFEST: hash_manifest}

    target_dir = out_dir or Path.cwd()
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = f"witseal-evidence-{control_code}-{period}"

    if out_format == "zip":
        pack_path = target_dir / f"{stem}.zip"
        with zipfile.ZipFile(pack_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(all_files):
                archive.writestr(name, all_files[name])
    elif out_format == "dir":
        pack_path = target_dir / stem
        pack_path.mkdir(parents=True, exist_ok=True)
        for name, data in all_files.items():
            (pack_path / name).write_bytes(data)
    else:
        raise ValueError(f"unknown out_format '{out_format}' (use 'zip' or 'dir')")

    return PackResult(
        pack_path=pack_path,
        pack_id=pack_id,
        control_code=control_code,
        receipt_count=len(discovered),
        verified_count=verified_count,
        signature_checked=signature_checked,
        verifications=tuple(verifications),
        redactions=tuple(redactions),
        file_hashes=file_hashes,
    )


def _read_pack_files(pack_path: Path) -> dict[str, bytes]:
    """Read every member of a pack (zip file or directory) into memory."""
    if pack_path.is_dir():
        return {p.name: p.read_bytes() for p in sorted(pack_path.iterdir()) if p.is_file()}
    if zipfile.is_zipfile(pack_path):
        with zipfile.ZipFile(pack_path) as archive:
            return {name: archive.read(name) for name in sorted(archive.namelist())}
    raise ValueError(f"'{pack_path.name}' is neither a directory nor a zip pack")


def verify_pack(pack_path: Path) -> dict[str, Any]:
    """Re-verify a pack's integrity offline against its ``hash_manifest.txt``.

    Recomputes the SHA-256 of every covered file and compares it to the
    manifest. Returns a verdict dict (``valid`` plus diagnostics); never
    raises on a tampered pack — it reports the mismatch.
    """
    try:
        files = _read_pack_files(pack_path)
    except (OSError, ValueError) as exc:
        return {"valid": False, "reason": str(exc)}

    manifest_raw = files.get(_HASH_MANIFEST)
    if manifest_raw is None:
        return {"valid": False, "reason": f"missing {_HASH_MANIFEST}"}

    expected: dict[str, str] = {}
    for line in manifest_raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        expected[name] = digest

    mismatches: list[str] = []
    missing: list[str] = []
    for name, digest in expected.items():
        data = files.get(name)
        if data is None:
            missing.append(name)
        elif hashlib.sha256(data).hexdigest() != digest:
            mismatches.append(name)

    missing_content = [n for n in _CONTENT_FILES if n not in expected]

    pack_id: str | None = None
    manifest_json = files.get("manifest.json")
    if manifest_json is not None:
        try:
            parsed = json.loads(manifest_json)
            if isinstance(parsed, Mapping):
                pid = parsed.get("pack_id")
                pack_id = pid if isinstance(pid, str) else None
        except json.JSONDecodeError:
            pack_id = None

    valid = not mismatches and not missing and not missing_content
    reason = None
    if not valid:
        reason = (
            f"integrity check failed: {len(mismatches)} mismatched, "
            f"{len(missing)} missing, {len(missing_content)} content files absent"
        )
    return {
        "valid": valid,
        "pack_id": pack_id,
        "files_checked": len(expected),
        "mismatches": mismatches,
        "missing": missing + missing_content,
        "reason": reason,
    }
