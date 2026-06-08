"""Build (and optionally send) a GRC export request for a finished pack.

Two targets, both reachable by a customer without a partnership:

- **Drata** — push a structured record to a Custom Connection (native JSON).
- **Vanta** — upload the pack as a document.

Endpoints are taken from the platforms' public developer docs. By default
this only BUILDS the request (``dry_run=True``) and never sends it, so the
flow runs with no credentials. A live send is opt-in and operator-run with a
real tenant + token; the API key is never echoed back (it is redacted in the
returned summary).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pack import _read_pack_files

TARGETS = ("drata", "vanta")

_DRATA_URL = (
    "https://public-api.drata.com/public/custom-connections/"
    "{connection_id}/resources/{resource_id}/records"
)
_VANTA_URL = "https://api.vanta.com/v1/documents/{document_id}/uploads"


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """A fully-formed request, ready to inspect (dry-run) or send."""

    target: str
    method: str
    url: str
    headers: dict[str, str]
    content_type: str
    body_kind: str  # "json" | "file"
    json_body: dict[str, Any] | None = None
    file_path: Path | None = None


def _pack_manifest(pack_path: Path) -> dict[str, Any]:
    files = _read_pack_files(pack_path)
    raw = files.get("manifest.json")
    if raw is None:
        raise ValueError(f"'{pack_path.name}' has no manifest.json")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("manifest.json is not a JSON object")
    return parsed


def build_drata_request(
    pack_path: Path,
    control_code: str,
    *,
    connection_id: str,
    resource_id: str,
    api_key: str | None = None,
) -> ExportRequest:
    """A Drata Custom Connection record (native JSON) summarizing the pack."""
    manifest = _pack_manifest(pack_path)
    body = {
        "control_code": control_code,
        "pack_id": manifest.get("pack_id"),
        "period": manifest.get("period"),
        "receipt_count": manifest.get("receipt_count"),
        "verified_count": manifest.get("verified_count"),
        "signature_checked": manifest.get("signature_checked"),
        "generated_at": manifest.get("generated_at"),
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return ExportRequest(
        target="drata",
        method="POST",
        url=_DRATA_URL.format(connection_id=connection_id, resource_id=resource_id),
        headers=headers,
        content_type="application/json",
        body_kind="json",
        json_body=body,
    )


def build_vanta_request(
    pack_path: Path,
    control_code: str,
    *,
    document_id: str,
    api_key: str | None = None,
) -> ExportRequest:
    """A Vanta document upload of the pack file (control_code for context)."""
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return ExportRequest(
        target="vanta",
        method="POST",
        url=_VANTA_URL.format(document_id=document_id),
        headers=headers,
        content_type="multipart/form-data",
        body_kind="file",
        file_path=pack_path,
    )


def build_request(
    target: str,
    pack_path: Path,
    control_code: str,
    *,
    connection_id: str = "<DRATA_CONNECTION_ID>",
    resource_id: str = "<DRATA_RESOURCE_ID>",
    document_id: str = "<VANTA_DOCUMENT_ID>",
    api_key: str | None = None,
) -> ExportRequest:
    """Dispatch to the target-specific builder."""
    if target == "drata":
        return build_drata_request(
            pack_path,
            control_code,
            connection_id=connection_id,
            resource_id=resource_id,
            api_key=api_key,
        )
    if target == "vanta":
        return build_vanta_request(
            pack_path, control_code, document_id=document_id, api_key=api_key
        )
    raise ValueError(f"unknown target '{target}' (use one of {', '.join(TARGETS)})")


def _redacted_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = dict(headers)
    if "Authorization" in redacted:
        redacted["Authorization"] = "Bearer [REDACTED]"
    return redacted


def _send(request: ExportRequest) -> int:
    if request.body_kind == "json":
        data = json.dumps(request.json_body).encode("utf-8")
        req = urllib.request.Request(
            request.url, data=data, method=request.method, headers=request.headers
        )
    else:
        file_path = request.file_path
        if file_path is None:
            raise ValueError("file export has no file_path")
        # A real Vanta upload is multipart/form-data; this best-effort live path
        # sends the zip bytes. Adapt to the documented multipart field for a real
        # tenant. The supported demo path is dry-run.
        data = file_path.read_bytes()
        headers = {**request.headers, "Content-Type": "application/zip"}
        req = urllib.request.Request(
            request.url, data=data, method=request.method, headers=headers
        )
    with urllib.request.urlopen(req) as response:
        return int(response.status)


def perform_export(request: ExportRequest, *, dry_run: bool = True) -> dict[str, Any]:
    """Inspect (dry-run) or send *request*; returns a summary with the key redacted."""
    has_auth = "Authorization" in request.headers
    summary: dict[str, Any] = {
        "target": request.target,
        "method": request.method,
        "url": request.url,
        "content_type": request.content_type,
        "headers": _redacted_headers(request.headers),
        "body_kind": request.body_kind,
        "authenticated": has_auth,
    }
    if request.body_kind == "json":
        summary["body_preview"] = request.json_body
    else:
        file_path = request.file_path
        summary["file"] = file_path.name if file_path else None
        summary["file_bytes"] = (
            file_path.stat().st_size if file_path and file_path.is_file() else None
        )

    if dry_run or not has_auth:
        summary["sent"] = False
        if not has_auth and not dry_run:
            summary["note"] = "no api key supplied; not sent"
        return summary

    summary["sent"] = True
    summary["response_status"] = _send(request)
    return summary
