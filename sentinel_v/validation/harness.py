"""Validation harness: load attack scenarios, replay them, assert detections."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel_v.config import ResponseCfg, Settings
from sentinel_v.models import Alert, Event, Incident, Severity
from sentinel_v.pipeline import build_pipeline
from sentinel_v.storage import Store

_SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}

DEFAULT_SCENARIOS_DIR = Path("validation/scenarios")


@dataclass
class Scenario:
    id: str
    name: str
    attack_technique: str | None
    atomic_ref: str
    events: list[dict[str, Any]]
    expect: dict[str, Any]

    def expand_events(self) -> list[Event]:
        out: list[Event] = []
        for spec in self.events:
            spec = dict(spec)
            repeat = int(spec.pop("repeat", 1))
            for _ in range(repeat):
                out.append(Event(**spec))
        return out


@dataclass
class ScenarioResult:
    scenario: Scenario
    passed: bool
    reason: str
    fired: list[str] = field(default_factory=list)


def load_scenarios(scenarios_dir: str | Path = DEFAULT_SCENARIOS_DIR) -> list[Scenario]:
    path = Path(scenarios_dir)
    scenarios: list[Scenario] = []
    if not path.exists():
        return scenarios
    for f in sorted(path.rglob("*")):
        if f.suffix.lower() not in {".yml", ".yaml"}:
            continue
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        scenarios.append(
            Scenario(
                id=str(doc.get("id", f.stem)),
                name=str(doc.get("name", f.stem)),
                attack_technique=doc.get("attack_technique"),
                atomic_ref=str(doc.get("atomic_ref", "")),
                events=list(doc.get("events") or []),
                expect=dict(doc.get("expect") or {}),
            )
        )
    return scenarios


def run_scenario(scenario: Scenario, *, rules_dir: str = "rules",
                 playbooks_dir: str = "playbooks") -> ScenarioResult:
    """Replay one scenario through a fresh, isolated pipeline and check expectations."""
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            db_url="sqlite://",
            rules_dir=Path(rules_dir),
            response=ResponseCfg(
                playbooks_dir=Path(playbooks_dir),
                block_list_path=Path(tmp) / "b.nft",
            ),
        )
        store = Store(settings.db_url)
        pipeline = build_pipeline(settings, store)
        for event in scenario.expand_events():
            pipeline.ingest_full(event)

        alerts = store.get_alerts(limit=1000)
        incidents = store.get_incidents(limit=1000)
        fired = [f"alert:{a.detector}" for a in alerts] + [
            f"incident:{i.attack_technique or i.severity}" for i in incidents
        ]
        return _check(scenario, alerts, incidents, fired)


def _check(
    scenario: Scenario, alerts: list[Alert], incidents: list[Incident], fired: list[str]
) -> ScenarioResult:
    exp = scenario.expect
    want_min = _SEV_ORDER.get(Severity(str(exp.get("min_severity", "low")).lower()), 0)

    if "incident_technique" in exp:
        tech = exp["incident_technique"]
        hits = [
            i for i in incidents
            if i.attack_technique == tech and _SEV_ORDER.get(i.severity, 0) >= want_min
        ]
        if not hits:
            sev = exp.get("min_severity")
            return ScenarioResult(
                scenario, False, f"no incident with technique {tech} at >={sev}", fired
            )

    if "alert_detector" in exp:
        det = exp["alert_detector"]
        tech = exp.get("alert_technique")
        alert_hits = [
            a for a in alerts
            if a.detector == det and (tech is None or a.attack_technique == tech)
        ]
        if not alert_hits:
            return ScenarioResult(scenario, False,
                                  f"no alert from {det}"
                                  + (f" tagged {tech}" if tech else ""), fired)

    return ScenarioResult(scenario, True, "expected detection fired", fired)


def run_all(scenarios_dir: str | Path = DEFAULT_SCENARIOS_DIR) -> list[ScenarioResult]:
    return [run_scenario(s) for s in load_scenarios(scenarios_dir)]
