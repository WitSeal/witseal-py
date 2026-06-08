from __future__ import annotations

import pytest
from witseal_grc.controls import control_mapping, known_controls


def test_known_controls_sorted_and_includes_eng_family() -> None:
    controls = known_controls()
    assert "WIT-ENG-001" in controls
    assert controls == sorted(controls)


def test_control_mapping_shape() -> None:
    mapping = control_mapping("WIT-ENG-001", ["rcpt_x", "rcpt_y"])
    assert mapping["control_code"] == "WIT-ENG-001"
    frameworks = mapping["frameworks"]
    assert isinstance(frameworks, dict)
    assert "SOC2" in frameworks
    assert mapping["receipt_refs"] == ["rcpt_x", "rcpt_y"]


def test_unknown_control_raises() -> None:
    with pytest.raises(KeyError):
        control_mapping("WIT-XXX-999", [])
