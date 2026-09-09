"""YAML playbook runner: Incident → matched playbook → gated Actions.

Phase 3. NIST SP 800-61 lifecycle (Detection & Analysis → Containment). A
playbook is declarative: a *trigger* that matches Incidents and an ordered list
of *steps*, each an action with its gating flags. The runner builds Actions from
the steps and feeds them through the Orchestrator, which enforces the approval
gate. Nothing destructive fires without approval unless a step is explicitly
``auto: true`` AND ``reversible: true``.

Playbook YAML shape (see playbooks/brute_force.yml):

    name: brute-force
    description: ...
    trigger:
      attack_technique: T1110      # optional
      min_severity: high           # optional (info<low<medium<high<critical)
      source: cowrie               # optional, matches incident.detail.source
    steps:
      - action: notify
        params: { channel: log }
      - action: block_ip
        destructive: true
        reversible: true
        auto: false                # gated (default for destructive)
        params: { duration_seconds: 3600 }
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sentinel_v.config import Settings
from sentinel_v.models import Action, Incident, Severity
from sentinel_v.response.actions import make_block_ip, notify
from sentinel_v.response.orchestrator import Orchestrator
from sentinel_v.storage import Store

log = logging.getLogger(__name__)

_SEVERITY_ORDER = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}


@dataclass
class Playbook:
    name: str
    description: str
    trigger: dict[str, Any]
    steps: list[dict[str, Any]]

    def matches(self, incident: Incident) -> bool:
        tech = self.trigger.get("attack_technique")
        if tech is not None and incident.attack_technique != tech:
            return False
        src = self.trigger.get("source")
        if src is not None and incident.detail.get("source") != src:
            return False
        min_sev = self.trigger.get("min_severity")
        if min_sev is not None:
            try:
                want = _SEVERITY_ORDER[Severity(str(min_sev).lower())]
            except ValueError:
                return False  # tolerate a bad value at match time (also rejected at load)
            if _SEVERITY_ORDER.get(incident.severity, 0) < want:
                return False
        return True


def _valid_min_severity(trigger: dict[str, Any]) -> bool:
    min_sev = trigger.get("min_severity")
    if min_sev is None:
        return True
    try:
        Severity(str(min_sev).lower())
        return True
    except ValueError:
        return False


def _valid_steps(steps: list[Any]) -> bool:
    return all(isinstance(s, dict) and s.get("action") for s in steps)


def load_playbooks(playbooks_dir: str | Path) -> list[Playbook]:
    path = Path(playbooks_dir)
    playbooks: list[Playbook] = []
    if not path.exists():
        return playbooks
    for f in sorted(path.rglob("*")):
        if f.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if not (isinstance(doc, dict) and doc.get("name") and isinstance(doc.get("steps"), list)):
            continue
        trigger = dict(doc.get("trigger") or {})
        steps = list(doc["steps"])
        # Reject a misconfigured playbook once, loudly — rather than letting it
        # raise inside run_for_incident, where the pipeline would swallow it and
        # silently skip containment for every incident.
        if not _valid_min_severity(trigger):
            log.warning("playbook %s: invalid trigger.min_severity; skipping", doc["name"])
            continue
        if not _valid_steps(steps):
            log.warning("playbook %s: a step is not a mapping with an 'action'; skipping",
                        doc["name"])
            continue
        playbooks.append(
            Playbook(
                name=str(doc["name"]),
                description=str(doc.get("description", "")),
                trigger=trigger,
                steps=steps,
            )
        )
    return playbooks


class PlaybookRunner:
    """Holds the Orchestrator + registered handlers and runs playbooks on incidents."""

    def __init__(self, store: Store, settings: Settings) -> None:
        self.store = store
        self.settings = settings
        self.orchestrator = Orchestrator(store)
        self.orchestrator.register("notify", notify)
        self.orchestrator.register("block_ip", make_block_ip(settings.response.block_list_path))
        self.playbooks = load_playbooks(settings.response.playbooks_dir)

    def run_for_incident(self, incident: Incident) -> list[Action]:
        """Run every matching playbook; return the Actions newly created this call.

        Idempotent per incident: a (playbook, action) step already proposed or
        executed for this incident is skipped, so re-correlation of the same
        incident on later events does not spam duplicate blocks/notifies.
        """
        require_gate = self.settings.response.require_approval_for_destructive
        already = {
            (a.playbook, a.name) for a in self.store.get_actions_for_incident(incident.id)
        }
        actions: list[Action] = []
        for pb in self.playbooks:
            if not pb.matches(incident):
                continue
            for step in pb.steps:
                key = (pb.name, str(step["action"]))
                if key in already:
                    continue
                actions.append(self._run_step(pb, step, incident, require_gate))
                already.add(key)
        return actions

    def _run_step(
        self, pb: Playbook, step: dict[str, Any], incident: Incident, require_gate: bool
    ) -> Action:
        destructive = bool(step.get("destructive", False))
        # A destructive step may only run un-gated if the playbook opts in AND the
        # global switch permits it; otherwise force the gate on.
        auto = bool(step.get("auto", False)) and not (destructive and require_gate)
        params = dict(step.get("params") or {})
        params.setdefault("src_ip", incident.detail.get("src_ip"))
        action = Action(
            playbook=pb.name,
            name=str(step["action"]),
            destructive=destructive,
            auto=auto,
            reversible=bool(step.get("reversible", True)),
            incident_id=incident.id,
            detail=params,
        )
        return self.orchestrator.run(action, incident)


def build_response(settings: Settings, store: Store) -> PlaybookRunner:
    return PlaybookRunner(store, settings)


def iter_incident_actions(runner: PlaybookRunner, incidents: Iterable[Incident]) -> list[Action]:
    out: list[Action] = []
    for inc in incidents:
        out.extend(runner.run_for_incident(inc))
    return out
