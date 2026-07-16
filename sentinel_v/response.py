"""Autonomous response engine — proportional, auditable, simulation-safe.

Maps threat assessments to graduated response plans. Execution is
deliberately non-destructive: plans are recorded and logged so an
operator (or an integration layer) can act on them; this module never
touches firewalls, sockets, or processes itself.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List

# Graduated playbook: escalation step -> ordered actions.
PLAYBOOK: Dict[int, List[str]] = {
    0: ["log_event"],
    1: ["log_event", "raise_alert"],
    2: ["log_event", "raise_alert", "recommend_rate_limit"],
    3: ["log_event", "raise_alert", "recommend_rate_limit", "recommend_isolation"],
}
MAX_PLAYBOOK_STEP = max(PLAYBOOK)


class AutonomousResponseEngine:
    """Evaluates threats and produces bounded, proportional responses."""

    def __init__(self, max_escalation: int = 3, autonomous_mode: bool = True):
        self.max_escalation = max(0, min(MAX_PLAYBOOK_STEP, max_escalation))
        self.autonomous = autonomous_mode
        self.response_history: List[Dict[str, Any]] = []

    def evaluate_threat(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Build a response plan proportional to the assessed threat.

        Decoy interactions escalate one step — anything touching the
        deception network has no legitimate reason to be there.
        """
        level_name = str(assessment.get("threat_level", "BENIGN"))
        base_step = {
            "BENIGN": 0,
            "SUSPICIOUS": 1,
            "MALICIOUS": 2,
            "CRITICAL": 3,
        }.get(level_name, 0)

        if assessment.get("is_decoy_interaction"):
            base_step += 1

        step = max(0, min(base_step, self.max_escalation))

        return {
            "threat_id": assessment.get("threat_id", ""),
            "threat_level": level_name,
            "escalation_step": step,
            "actions": list(PLAYBOOK[step]),
            "target": assessment.get("event", {}).get("source_ip", ""),
            "created_at": datetime.now().isoformat(),
        }

    def execute_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Record and log the plan's actions; never mutate the host.

        Returns an execution receipt listing every action taken (all
        actions here are log/recommend semantics by design).
        """
        executed: List[str] = []
        for action in response.get("actions", []):
            logging.info(
                "response action=%s target=%s threat=%s",
                action,
                response.get("target", ""),
                response.get("threat_id", ""),
            )
            executed.append(action)

        receipt = {
            "threat_id": response.get("threat_id", ""),
            "executed_actions": executed,
            "simulated": True,
            "executed_at": datetime.now().isoformat(),
        }
        self.response_history.append(receipt)

        # Bound the history so a threat flood cannot exhaust memory.
        if len(self.response_history) > 5000:
            self.response_history = self.response_history[-2500:]

        return receipt
