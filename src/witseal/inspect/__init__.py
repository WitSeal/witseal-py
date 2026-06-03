"""Keyless artifact inspection — the SDK *consume* surface.

Exposes :func:`inspect_artifact`, which summarizes a WitSeal receipt or
evidence package and reports the integrity checks that require no public key.
Signature verification (key-requiring) lives in :mod:`witseal.verify`.
"""

from witseal.inspect._inspect import ArtifactInspection, inspect_artifact

__all__ = ["ArtifactInspection", "inspect_artifact"]
