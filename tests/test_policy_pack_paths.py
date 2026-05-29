"""PolicyPack `allow_paths` / `deny_paths` wire-format invariants.

Per the v0.2 schema delta:
- Both fields are optional `list[str]`, default empty list.
- Empty list MUST be omitted from JSON entirely — never serialized as
  `[]` or `null`.
- Populated list serializes inline as a JSON array of strings.

These tests pin the Python side of the cross-language byte-parity invariant.
Compat-corpus parity with Rust + TS is verified separately (Week 1 Day 4).
"""

from __future__ import annotations

from witseal.schemas import PolicyPack, PolicyRule, RiskClass, RuleMatch


def _minimal_pack(**overrides: object) -> PolicyPack:
    base: dict[str, object] = {
        "schema_version": "witseal.policy.v0.1",
        "pack_id": "default-pack",
        "version": "0.1.0",
        "description": "default",
        "rules": [
            PolicyRule(
                id="r1",
                match=RuleMatch(risk_class=RiskClass.C4),
                decision="deny",
                reason="dangerous",
            )
        ],
    }
    base.update(overrides)
    return PolicyPack.model_validate(base)


def _dump(pack: PolicyPack) -> dict[str, object]:
    """Canonical dump shape matching the rest of the schemas (by_alias for
    the `not_`/`not` rename, exclude_none for required-nullable fields)."""
    return pack.model_dump(by_alias=True, exclude_none=True)


def test_empty_allow_paths_omitted_from_dump() -> None:
    pack = _minimal_pack()
    dumped = _dump(pack)
    assert "allow_paths" not in dumped, (
        "empty allow_paths must be omitted, not serialized as [] or null"
    )
    assert "deny_paths" not in dumped, (
        "empty deny_paths must be omitted, not serialized as [] or null"
    )


def test_empty_paths_bytes_identical_to_predelta() -> None:
    """§ 5 mitigation: empty new fields produce bytes identical to pre-delta v0.1."""
    pack = _minimal_pack()
    dumped_explicit = _dump(_minimal_pack(allow_paths=[], deny_paths=[]))
    assert _dump(pack) == dumped_explicit
    assert "allow_paths" not in dumped_explicit
    assert "deny_paths" not in dumped_explicit


def test_populated_allow_paths_serialized() -> None:
    pack = _minimal_pack(allow_paths=["/tmp/agent-*", "/etc/**"])
    dumped = _dump(pack)
    assert dumped["allow_paths"] == ["/tmp/agent-*", "/etc/**"]
    assert "deny_paths" not in dumped


def test_populated_deny_paths_serialized() -> None:
    pack = _minimal_pack(deny_paths=["/etc/passwd", "/secrets/**"])
    dumped = _dump(pack)
    assert dumped["deny_paths"] == ["/etc/passwd", "/secrets/**"]
    assert "allow_paths" not in dumped


def test_both_paths_populated() -> None:
    pack = _minimal_pack(allow_paths=["/tmp/**"], deny_paths=["/etc/passwd"])
    dumped = _dump(pack)
    assert dumped["allow_paths"] == ["/tmp/**"]
    assert dumped["deny_paths"] == ["/etc/passwd"]


def test_roundtrip_with_paths() -> None:
    pack = _minimal_pack(
        allow_paths=["/tmp/**"],
        deny_paths=["/etc/passwd"],
    )
    restored = PolicyPack.model_validate(_dump(pack))
    assert restored == pack
    assert restored.allow_paths == ["/tmp/**"]
    assert restored.deny_paths == ["/etc/passwd"]


def test_roundtrip_empty_paths() -> None:
    """Round-trip across the skip-empty boundary preserves equality."""
    pack = _minimal_pack()
    restored = PolicyPack.model_validate(_dump(pack))
    assert restored == pack
    assert restored.allow_paths == []
    assert restored.deny_paths == []


def test_deserialize_legacy_predelta_payload() -> None:
    """v0.1 payloads without the new fields parse cleanly (default empty)."""
    legacy = {
        "schema_version": "witseal.policy.v0.1",
        "pack_id": "legacy",
        "version": "0.1.0",
        "description": "legacy v0.1 pack with no path fields",
        "rules": [],
    }
    pack = PolicyPack.model_validate(legacy)
    assert pack.allow_paths == []
    assert pack.deny_paths == []


def test_explicit_empty_lists_accepted() -> None:
    """Wire payloads with explicit `[]` (e.g. from non-skipping emitters)
    still validate — the skip-empty invariant is an emitter contract; the
    parser is tolerant per Postel."""
    payload = {
        "schema_version": "witseal.policy.v0.1",
        "pack_id": "tolerant",
        "version": "0.1.0",
        "description": "tolerant parse",
        "rules": [],
        "allow_paths": [],
        "deny_paths": [],
    }
    pack = PolicyPack.model_validate(payload)
    # On re-serialize, our emitter still omits empties.
    redumped = _dump(pack)
    assert "allow_paths" not in redumped
    assert "deny_paths" not in redumped
