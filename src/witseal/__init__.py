"""WitSeal Python: wire-format types and read-side verifier for the WitSeal runtime ecosystem.

Phase 1 scope is **verifier + schema only**: this package provides
RFC 8785 canonicalization, SHA-256 hashing, Pydantic v2 wire-format
schemas, and Ed25519 signature verification for v0.2 receipts. It does
NOT provide subprocess mediation, policy evaluation, witness event-log
append, approval flow, or `witseal exec`; those are future-phase work.
Public API surface is not yet defined.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
