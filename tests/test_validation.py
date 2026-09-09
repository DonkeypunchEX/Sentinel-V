"""Item 6: the purple-team validation suite must be green (detections fire)."""
from __future__ import annotations

from sentinel_v.validation.harness import load_scenarios, run_all


def test_scenarios_exist():
    scenarios = load_scenarios()
    assert len(scenarios) >= 2
    assert all(s.attack_technique for s in scenarios)


def test_all_scenarios_pass():
    results = run_all()
    assert results, "no scenarios found"
    failed = [(r.scenario.id, r.reason) for r in results if not r.passed]
    assert not failed, f"detection gaps: {failed}"
