"""Policy schemas — mirror of TS `schemas/policy.schema.ts`.

Schema version: `witseal.policy.v0.1`.

the v0.2 schema delta added two optional
PolicyPack fields (`allow_paths`, `deny_paths`) for file-mediation.
Empty fields produce byte-identical output to pre-delta
v0.1, so the formal `witseal.policy.v0.2` literal bump is deferred until the
TS canonical reference increments (the TS byte-parity reference byte-parity with TS).
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

from ._primitives import Sha256Hex
from .intent import ActionType, RiskClass

_PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[a-z0-9.-]+)?$")


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: ActionType | None = None
    risk_class: RiskClass | None = None
    risk_class_in: list[RiskClass] | None = None
    executable_matches: str | None = None
    command_matches: str | None = None
    path_matches: str | None = None
    all_of: list[RuleMatch] | None = None
    any_of: list[RuleMatch] | None = None
    not_: RuleMatch | None = Field(default=None, alias="not")


RuleMatch.model_rebuild()


class PolicyRuleExamples(BaseModel):
    model_config = ConfigDict(extra="forbid")

    should_match: list[Any] | None = None
    should_not_match: list[Any] | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    match: RuleMatch
    decision: Literal["allow", "deny", "require-approval"]
    reason: str = Field(min_length=1)
    examples: PolicyRuleExamples | None = None


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.policy.v0.1"]
    pack_id: str
    version: str
    description: str = Field(min_length=1)
    rules: list[PolicyRule]
    default_decision: Literal["allow", "deny", "require-approval"] = "allow"
    allow_paths: list[str] = Field(default_factory=list)
    deny_paths: list[str] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _serialize(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # Cross-track wire-format invariant (the cross-track invariant):
        # empty `allow_paths` / `deny_paths` MUST be omitted from JSON, not
        # serialized as `[]` or `null`. Mirrors Rust serde
        # `skip_serializing_if = "Vec::is_empty"` and TS omit-if-empty.
        if not data.get("allow_paths"):
            data.pop("allow_paths", None)
        if not data.get("deny_paths"):
            data.pop("deny_paths", None)
        return data

    def model_post_init(self, _: object) -> None:
        if not _PACK_ID_RE.match(self.pack_id):
            raise ValueError("pack_id must be kebab-case [a-z0-9][a-z0-9-]*")
        if not _SEMVER_RE.match(self.version):
            raise ValueError("version must be semver")


class MatchedRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str
    pack_version: str
    rule_id: str


class ActivePackHash(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str
    version: str
    content_hash: Sha256Hex


class PolicyDecision(BaseModel):
    """A single evaluation outcome emitted by the policy engine.

    Per RFC-002 §7.1 (rev2 ratified 2026-05-26), the `outcome` enum carries
    the evaluation-outcome value set. Includes `no_policy_configured` —
    distinct from `allow` — for runtimes that emit a receipt when no policy
    is loaded (must fail closed per the binding decision).

    Placement guard: `no_policy_configured` is valid ONLY as an evaluation
    outcome on `PolicyDecision`. It is NOT a valid configuration value on
    `PolicyPack.default_decision` (which lists rule-defined fallbacks for
    when no rule matches — itself a configured policy state, not the
    no-policy-loaded state). The guard is enforced by separate Literal
    types: `PolicyDecision.outcome` and `PolicyPack.default_decision` carry
    different value sets.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.policy.v0.1"]
    outcome: Literal["allow", "deny", "require-approval", "no_policy_configured"]
    matched_rule: MatchedRule | None
    reason: str
    active_pack_hashes: list[ActivePackHash]
