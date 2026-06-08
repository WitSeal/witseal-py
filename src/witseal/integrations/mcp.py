"""MCP integration — verify a WitSeal artifact handed to an MCP client/server.

The Model Context Protocol (MCP) is a universal seam between agents and the
tools/servers they call. This module gives that seam exactly one WitSeal
capability: **verify an execution receipt or evidence package that is
presented to it**, returning a VALID / INVALID verdict.

Two surfaces, one job:

- :func:`verify_witseal_artifact` — the pure consumer. Accepts an artifact
  as a parsed mapping or as raw JSON (``str`` / ``bytes``), parses it if
  needed, and delegates to the existing :func:`witseal.verify.verify_artifact`
  path. It performs no cryptography of its own — it is a thin adapter over
  the frozen wire-format verifier. Depends only on the base package, so it
  works with or without the ``mcp`` extra installed.
- :func:`register_witseal_tools` / :func:`build_mcp_server` — an optional MCP
  protocol surface that exposes the verifier as an MCP *tool*. The ``mcp``
  SDK is imported **lazily**, inside these functions, so that simply
  ``import witseal.integrations.mcp`` (and calling
  :func:`verify_witseal_artifact`) never requires the extra. Installing the
  protocol surface is opt-in: ``pip install witseal[mcp]``.

Scope discipline (identity guard). This integration verifies artifacts that
are *explicitly handed to it* and nothing else. It is NOT a logger, a proxy,
a recorder, or a mediator: it does not observe, intercept, wrap, or capture
the surrounding MCP traffic, tool calls, or messages to *produce* execution
evidence. Generation and observation are out of scope by design (canonical
generation is the Rust trust core); the only thing on offer here is
consume-side verification of evidence another track produced.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from witseal.verify import PublicKeyInput, resolve_public_key, verify_artifact

if TYPE_CHECKING:  # pragma: no cover - import-time typing only, never at runtime
    from mcp.server.fastmcp import FastMCP

__all__ = [
    "build_mcp_server",
    "register_witseal_tools",
    "verify_witseal_artifact",
]

# The tool/server identity, kept as constants so the protocol surface and any
# docs stay in sync. Namespaced under ``witseal.`` so it does not collide with
# a host server's own tools.
_TOOL_NAME = "witseal.verify_artifact"
_SERVER_NAME = "witseal-verify"


def _coerce_to_mapping(artifact: Mapping[str, Any] | str | bytes) -> Mapping[str, Any]:
    """Return *artifact* as a JSON object mapping.

    ``str`` / ``bytes`` are parsed as JSON (``bytes`` are decoded as UTF-8 by
    :func:`json.loads`). A mapping is taken as already-parsed. Anything that
    is not a JSON object — a JSON array/scalar, or a non-mapping Python value
    — raises ``ValueError``; the wire-format verifier only ever verifies a
    single artifact object.
    """
    if isinstance(artifact, Mapping):
        return artifact
    if isinstance(artifact, (str, bytes)):
        try:
            parsed = json.loads(artifact)
        except json.JSONDecodeError as exc:
            raise ValueError(f"artifact is not valid JSON: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise ValueError("artifact JSON must be an object (a WitSeal artifact)")
        return parsed
    raise ValueError(
        "artifact must be a mapping or JSON text/bytes, "
        f"got {type(artifact).__name__}"
    )


def verify_witseal_artifact(
    artifact: Mapping[str, Any] | str | bytes,
    *,
    public_key: PublicKeyInput | None = None,
) -> dict[str, Any]:
    """Verify a single WitSeal artifact and return a JSON-serializable verdict.

    *artifact* is an execution receipt (v0.1 or v0.2) or an evidence package,
    supplied either as an already-parsed mapping or as raw JSON ``str`` /
    ``bytes`` (parsed here). The artifact's ``schema_version`` selects the
    verification path; this function is a pure consumer of the frozen wire
    format and delegates to :func:`witseal.verify.verify_artifact` — it does
    no cryptography of its own.

    *public_key* is the externally-supplied Ed25519 verifier key in any
    on-hand form accepted by :func:`witseal.verify.resolve_public_key` (a PEM
    file path, a 32-byte hex string, PEM bytes, or an already-loaded key). It
    is required only for a v0.2 receipt (or an evidence package containing
    one); a v0.1 receipt or a v0.1-only package verifies without one. There
    is no implicit key discovery — no env var, no bundled key, no network
    fetch.

    Returns a plain ``dict`` (suitable as an MCP tool result) with:

    - ``valid`` (bool) — the single VALID / INVALID answer;
    - ``kind`` (str) — ``receipt.v0.1`` / ``receipt.v0.2`` /
      ``evidence-package.v0.1`` / ``unknown``;
    - ``schema_version`` (str | None) — the artifact's declared version;
    - ``reason`` (str | None) — why it failed, when it failed.

    Raises ``ValueError`` for input that is not a JSON object, and the same
    key-resolution errors as :func:`witseal.verify.resolve_public_key` for a
    malformed key. A cryptographically *invalid* artifact is reported via
    ``valid=False`` (it does not raise).
    """
    value = _coerce_to_mapping(artifact)
    resolved = resolve_public_key(public_key) if public_key is not None else None
    result = verify_artifact(value, resolved)
    return {
        "valid": result.valid,
        "kind": result.kind,
        "schema_version": result.schema_version,
        "reason": result.reason,
    }


def register_witseal_tools(
    server: FastMCP,
    *,
    public_key: PublicKeyInput | None = None,
) -> FastMCP:
    """Register the WitSeal verify-only tool on an existing FastMCP *server*.

    Adds a single MCP tool, ``witseal.verify_artifact``, that wraps
    :func:`verify_witseal_artifact`: a caller hands it a WitSeal artifact (as
    a mapping or JSON text) and gets back the VALID / INVALID verdict dict.
    The tool verifies only the artifact it is given — it does not observe,
    wrap, or record any other MCP traffic (see this module's identity guard).

    The ``mcp`` SDK is imported by the caller that constructed *server*; this
    function adds no further import. If *public_key* is given it is resolved
    once here (eagerly, so a bad key fails fast) and used as the default
    verifier key for every call; a per-call ``public_key`` argument overrides
    it. Returns *server* for chaining.

    Requires the ``mcp`` extra (``pip install witseal[mcp]``) at the point a
    FastMCP server is constructed — importing this module does not.
    """
    default_key = resolve_public_key(public_key) if public_key is not None else None

    @server.tool(name=_TOOL_NAME)
    def witseal_verify_artifact(
        artifact: dict[str, Any] | str,
        public_key_pem_or_hex: str | None = None,
    ) -> dict[str, Any]:
        """Verify a WitSeal execution receipt or evidence package.

        Returns whether the supplied artifact is genuine. ``artifact`` is the
        receipt/package as a JSON object or JSON string. ``public_key_pem_or_hex``
        is the Ed25519 verifier key (PEM text or 32-byte hex); it is required
        only for a v0.2 receipt and overrides any server default. This tool
        verifies ONLY the artifact handed to it; it does not record or inspect
        other activity.
        """
        key: PublicKeyInput | None = public_key_pem_or_hex or default_key
        return verify_witseal_artifact(artifact, public_key=key)

    return server


def build_mcp_server(
    *,
    public_key: PublicKeyInput | None = None,
    name: str = _SERVER_NAME,
) -> FastMCP:
    """Build a ready-to-run FastMCP server exposing only the WitSeal verifier.

    Constructs a :class:`mcp.server.fastmcp.FastMCP` instance (the ``mcp`` SDK
    is imported lazily *here*, so importing this module without the extra is
    fine) and registers the single verify-only tool via
    :func:`register_witseal_tools`. The returned server can be run with
    ``server.run(...)``. *public_key*, if given, becomes the default verifier
    key (see :func:`register_witseal_tools`).

    Raises ``ModuleNotFoundError`` with an actionable message if the ``mcp``
    extra is not installed.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ModuleNotFoundError(
            "the MCP protocol surface requires the 'mcp' extra; "
            "install it with `pip install witseal[mcp]` "
            "(witseal.integrations.mcp.verify_witseal_artifact works without it)"
        ) from exc

    server = FastMCP(name)
    return register_witseal_tools(server, public_key=public_key)
