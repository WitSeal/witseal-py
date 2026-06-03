# STYLE.md — Vocabulary discipline

**Scope:** all public artifacts — README, docs, docstrings, commit messages,
issue/PR text, release notes.

WitSeal creates a category, and categories are created in language. Where a
generic or competitor term is used in place of a canonical one, the category
dilutes. This document is enforced by review and by a vocabulary check in CI.

## Canonical terms (Use / Avoid)

| Use | Avoid |
|---|---|
| witnessed execution | AI monitoring, AI observability, AI logging |
| execution evidence | logs, telemetry, traces |
| evidence chain | audit log, audit trail |
| execution receipt | run record, execution log |
| witness event | log entry, monitoring record |
| trust runtime | wrapper, middleware, proxy |
| authority boundary | permission system, ACL, RBAC |
| policy decision | rule match, gate result |
| risk classification | severity tagging, threat scoring |
| approval gate | human-in-the-loop check |
| deny-by-default | safe mode, restrictive mode |
| operational trust | AI safety, AI alignment |
| tamper-evident | immutable, secure |

## Term roles

- **Category-defining** (use deliberately): witnessed execution, execution
  evidence, evidence chain, execution receipt, trust runtime, authority
  boundary.
- **Technical primitives** (use precisely): deny-by-default, hash-chained,
  tamper-evident, RFC 8785 canonicalization, Ed25519 signature.
- **Operational pipeline** (consistent order): intent → classification →
  policy → approval → execution → witness → receipt → evidence package.

## Naming in code

Primary types follow wire-format field names in PascalCase:
`WitnessEvent`, `ExecutionReceipt`, `ReceiptV02`, `PolicyDecision`,
`EvidencePackage`. Verbs are snake_case and concrete:
`verify_receipt`, `verify_chain`, `verify_evidence_package`,
`verify_artifact`, `inspect_artifact`, `canonicalize`, `hash_event`.

Avoid vague verbs (`check`, `process`, `handle`) and marketing adjectives
(`seamless`, `next-generation`, `revolutionary`).

## Enforcement

`scripts/style_check.py` scans tracked Markdown for terms in the Avoid
column and fails on a match. A justified exception is wrapped in
`<!-- style-allow -->` … `<!-- /style-allow -->`. This file is excluded
from the scan (it necessarily names the avoided terms).

## One-line summary

Every artifact either reinforces the category or erodes it. There is no
neutral ground.
