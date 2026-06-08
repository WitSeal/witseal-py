# `witseal.integrations`

Framework integration helpers for the WitSeal Python SDK. Every helper here
is a **consume / verify** seam and nothing more: hand it a WitSeal artifact —
an execution receipt or an evidence package — and it returns a VALID /
INVALID verdict by delegating to the same verification path as the CLI
(`witseal.verify.verify_artifact`).

What these helpers are **not**: generators, runtimes, or recorders. An
integration verifies only the artifact explicitly handed to it. It does not
observe, intercept, wrap, or capture the surrounding framework's activity to
produce execution evidence — generation is the Rust trust core, and is out of
scope for the Python line by design.

> **Provisional (pre-1.0).** The `witseal.integrations` namespace and the
> signatures below are not yet frozen and may change before 1.0.

## MCP — `witseal.integrations.mcp`

The [Model Context Protocol](https://modelcontextprotocol.io) is a universal
seam between agents and the tools/servers they call. This module gives that
seam one WitSeal capability: verify an artifact that is presented to it.

It has two layers, with different dependencies:

| Surface | Needs the `mcp` extra? | What it does |
|---|---|---|
| `verify_witseal_artifact(...)` | No — base package only | Pure consumer: parse (if needed) and verify one artifact. |
| `register_witseal_tools(...)` / `build_mcp_server(...)` | Yes (`pip install "witseal[mcp]"`) | Expose the verifier as an MCP tool / server. |

Importing the module (`import witseal.integrations.mcp`) never requires the
extra — the `mcp` SDK is imported lazily, only when a server is constructed.

### Core verifier

```python
from witseal.integrations.mcp import verify_witseal_artifact

verdict = verify_witseal_artifact(artifact, public_key="ed25519-public.pem")
```

`artifact` is a v0.1 / v0.2 execution receipt or an evidence package, given
as an already-parsed mapping or as raw JSON (`str` / `bytes`, parsed for
you). The artifact's `schema_version` selects the verification path.

`public_key` is the externally-supplied Ed25519 verifier key in any on-hand
form — a PEM file path, a 32-byte hex string, PEM bytes, or an already-loaded
`Ed25519PublicKey`. It is required only for a v0.2 receipt (or an evidence
package containing one); a v0.1 receipt or v0.1-only package verifies without
one. There is no implicit key discovery: no environment variable, no bundled
key, no network fetch — the key is always an explicit input.

The return value is a plain JSON-serializable `dict`:

```python
{
    "valid": True,                              # the single VALID / INVALID answer
    "kind": "receipt.v0.2",                     # receipt.v0.1 | receipt.v0.2 |
                                                #   evidence-package.v0.1 | unknown
    "schema_version": "witseal.receipt.v0.2",
    "reason": None,                             # populated on failure
}
```

A cryptographically invalid artifact is reported via `valid=False` (it does
not raise). `verify_witseal_artifact` raises `ValueError` only for input that
is not a JSON object, or for a malformed `public_key`.

### MCP tool / server (optional)

With the `mcp` extra installed:

```python
from witseal.integrations.mcp import build_mcp_server, register_witseal_tools

# A standalone server exposing only the verify-only tool:
server = build_mcp_server(public_key="ed25519-public.pem")
server.run()  # choose a transport, e.g. server.run(transport="stdio")

# …or register the tool on a FastMCP server you already have:
register_witseal_tools(existing_server, public_key="ed25519-public.pem")
```

Both register a single MCP tool, **`witseal.verify_artifact`**, that wraps
`verify_witseal_artifact`. A caller hands it an artifact (a JSON object or
JSON string) and an optional per-call `public_key_pem_or_hex`; a server-level
default key (the `public_key` argument above) is used when a call omits one.

If the `mcp` extra is not installed, `build_mcp_server` raises
`ModuleNotFoundError` with an actionable message naming the extra; the core
`verify_witseal_artifact` keeps working regardless.

### Scope discipline

The MCP tool verifies the artifact it is given and returns the verdict. It is
deliberately not a recorder of MCP traffic, a tool-call interceptor, or a
mediator: it never reads, captures, or derives evidence from the host's other
messages or tool calls. If you need evidence *generated*, that is the Rust
trust core's job, not this seam's.
