"""WitSeal GRC evidence-pack — example/prototype (NOT part of the published SDK).

A read-side bridge that turns already-generated, independently-verified
WitSeal receipts into a control-mapped evidence pack a compliance team can
hand to a reviewer or push into a GRC system (Drata / Vanta).

It is built ON TOP of the published ``witseal`` SDK and uses only its
read-side surface (``witseal.verify`` / ``witseal.inspect``). It mints no
WitSeal canonical artifact: a "pack" is a bundle of reports (manifest,
control mapping, verification results, redaction report, per-file hash
manifest, summary) over receipts that were generated elsewhere — the
canonical trust core is the Rust track, and the Python line does not
generate artifacts.

Scope: example/demo. Not published on PyPI, not part of the SDK's public
API surface.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.1-example"
