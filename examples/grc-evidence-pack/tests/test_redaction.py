from __future__ import annotations

from witseal_grc.redaction import redact_receipt


def test_non_canonical_field_is_redacted() -> None:
    receipt = {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": "rcpt_demo",
        "extra_secret": "value",
    }
    redacted, entries = redact_receipt(0, receipt)
    assert redacted["extra_secret"] == "[REDACTED]"
    assert redacted["receipt_id"] == "rcpt_demo"
    assert any(e.field == "extra_secret" and e.rule == "non_canonical_field" for e in entries)


def test_configured_fields_are_masked() -> None:
    receipt = {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": "rcpt_demo",
        "git_commit": "a" * 40,
        "build_id": "build-1",
    }
    redacted, entries = redact_receipt(0, receipt)
    assert redacted["git_commit"] == "[REDACTED]"
    assert redacted["build_id"] == "[REDACTED]"
    masked = {e.field for e in entries}
    assert {"git_commit", "build_id"} <= masked


def test_canonical_hash_fields_preserved() -> None:
    receipt = {
        "schema_version": "witseal.receipt.v0.2",
        "receipt_id": "rcpt_demo",
        "policy_decision_hash": "a" * 64,
    }
    redacted, _ = redact_receipt(0, receipt)
    assert redacted["policy_decision_hash"] == "a" * 64
