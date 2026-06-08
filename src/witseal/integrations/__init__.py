"""Framework integration helpers — the SDK *consume / verify* seam.

WitSeal's Python line is the read-side SDK: it verifies and inspects
artifacts, it does not generate them or run anything (canonical generation
is the Rust trust core). The integrations under this package carry that same
posture into specific ecosystems: each one is a thin adapter that hands a
WitSeal artifact (an execution receipt or an evidence package) to the
existing verification path and surfaces a VALID / INVALID verdict — nothing
more.

What an integration here IS:

- a verifier seam — accept an artifact, return whether it is genuine.

What an integration here is explicitly NOT:

- a runtime, a wrapper, a mediator, or any kind of traffic recorder. An
  integration never observes, intercepts, or logs the host framework's
  activity to *produce* execution evidence. Generation is out of scope by
  design; these helpers only consume what another track produced.

Currently provided:

- :mod:`witseal.integrations.mcp` — verify a WitSeal artifact handed to an
  MCP client/server, with an optional MCP protocol surface (a verify-only
  tool) behind the ``mcp`` extra.

Provisional, pre-1.0: the ``witseal.integrations`` namespace and its
signatures are not yet frozen.
"""

from __future__ import annotations

__all__: list[str] = []
