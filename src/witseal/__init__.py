"""WitSeal Python — the Ecosystem SDK: consume, verify, and inspect WitSeal artifacts.

The Python line is the **SDK / verifier** layer. It provides
RFC 8785 canonicalization, SHA-256 hashing, Pydantic v2 wire-format
schemas, Ed25519 receipt verification, witness-event hash-chain and
evidence-package verification, a unified ``verify_artifact`` discriminator,
and keyless ``inspect``.

It does NOT generate artifacts or run a runtime: no signing/receipt
generation, no subprocess mediation, no policy evaluation, no witness
event-log append, no approval flow, no ``witseal exec``. Canonical
generation is the Rust trust core. Public API surface is not yet
frozen.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    # Single source of truth: the version declared in pyproject.toml, surfaced
    # through the installed distribution metadata, so __version__ can never
    # drift from the packaged version.
    __version__ = _version("witseal")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.1.0"

__all__ = ["__version__"]
