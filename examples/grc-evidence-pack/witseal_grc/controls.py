"""Control catalog + mapping for the evidence-pack example.

Maps already-verified WitSeal receipts to compliance controls. The catalog
starts with engineering / change-management controls (concrete and
reviewable) and can later extend to broader runtime controls. Read-side
only: nothing here mints a WitSeal canonical artifact.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypedDict


class ControlSpec(TypedDict):
    title: str
    frameworks: dict[str, list[str]]
    assertion: str


# Engineering / change-management controls (first wedge). Framework mappings
# are the demo defaults; a real deployment tunes them per the customer's
# control set.
CONTROL_CATALOG: dict[str, ControlSpec] = {
    "WIT-ENG-001": {
        "title": "AI-Assisted Code Changes Are Witnessed",
        "frameworks": {
            "SOC2": ["CC8.1", "CC6.1"],
            "ISO_27001_2022": ["A.8.15", "A.8.32"],
            "ISO_42001": ["A.6.2.8"],
        },
        "assertion": (
            "Every AI-assisted code change in the period produced a signed, "
            "independently-verifiable receipt linking actor, action, policy "
            "decision and result."
        ),
    },
    "WIT-ENG-002": {
        "title": "AI-Agent CI/CD Actions Are Recorded and Verified",
        "frameworks": {
            "SOC2": ["CC8.1", "CC7.2"],
            "ISO_27001_2022": ["A.8.15", "A.8.16"],
        },
        "assertion": (
            "AI-agent CI/CD actions in the period are recorded as receipts "
            "and independently verified."
        ),
    },
    "WIT-ENG-003": {
        "title": "Production-Relevant AI Actions Are Linked to Human Approval",
        "frameworks": {
            "SOC2": ["CC8.1"],
            "ISO_27001_2022": ["A.8.32"],
        },
        "assertion": (
            "Production-relevant AI actions in the period carry a receipt "
            "linking the action to the human approval that authorized it."
        ),
    },
    "WIT-ENG-004": {
        "title": "AI-Generated Engineering Evidence Is Tamper-Evident",
        "frameworks": {
            "SOC2": ["CC7.2"],
            "ISO_27001_2022": ["A.8.15"],
            "ISO_42001": ["A.6.2.8"],
        },
        "assertion": (
            "Engineering evidence for the period is hash-chained and "
            "signed, so any change is detectable by an independent verifier."
        ),
    },
    "WIT-ENG-005": {
        "title": "AI-Agent Change Evidence Is Retained for Audit",
        "frameworks": {
            "SOC2": ["CC8.1"],
            "ISO_27001_2022": ["A.8.15"],
            "ISO_42001": ["A.6.2.8"],
        },
        "assertion": (
            "Change evidence for the period is retained and re-verifiable "
            "for a reviewer."
        ),
    },
}


def known_controls() -> list[str]:
    """Sorted list of control codes the catalog can map."""
    return sorted(CONTROL_CATALOG)


def control_mapping(control_code: str, receipt_refs: Sequence[str]) -> dict[str, object]:
    """Build the ``control_mapping.json`` body for *control_code*.

    Raises :class:`KeyError` if *control_code* is not in the catalog.
    """
    spec = CONTROL_CATALOG.get(control_code)
    if spec is None:
        raise KeyError(
            f"unknown control '{control_code}'; known: {', '.join(known_controls())}"
        )
    return {
        "control_code": control_code,
        "control_title": spec["title"],
        "frameworks": spec["frameworks"],
        "assertion": spec["assertion"],
        "receipt_refs": list(receipt_refs),
    }
