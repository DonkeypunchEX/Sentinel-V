"""SOAR-lite playbook runner. The safety-critical component.

Rule: destructive actions are GATED (queued for human approval) unless the
playbook marks them auto AND reversible. Every executed action records how to
undo itself and lands in the audit log. See docs/PLAYBOOKS.md.
"""
from __future__ import annotations

from collections.abc import Callable

from sentinel_v.models import Action, Incident

# An action handler performs the side effect and returns undo info.
ActionHandler = Callable[[Action, Incident], dict[str, object]]


class PendingApproval(Exception):
    """Raised/queued when a destructive action needs a human before it runs."""


class Orchestrator:
    def __init__(self) -> None:
        self._handlers: dict[str, ActionHandler] = {}
        self._pending: list[Action] = []
        self._audit: list[Action] = []

    def register(self, name: str, handler: ActionHandler) -> None:
        self._handlers[name] = handler

    def run(self, action: Action, incident: Incident) -> Action:
        """Execute an action, or queue it for approval if it requires a gate."""
        if action.requires_gate() and not action.approved:
            self._pending.append(action)
            return action  # caller notifies; /approve resumes via approve()
        handler = self._handlers.get(action.name)
        if handler is None:
            raise KeyError(f"No handler registered for action '{action.name}'")
        action.undo = handler(action, incident)
        self._audit.append(action)
        return action

    def approve(self, action_id: str, approver: str, incident: Incident) -> Action:
        for i, a in enumerate(self._pending):
            if a.id == action_id:
                a.approved = True
                a.approver = approver
                self._pending.pop(i)
                return self.run(a, incident)
        raise KeyError(f"No pending action {action_id}")

    @property
    def pending(self) -> list[Action]:
        return list(self._pending)

    @property
    def audit(self) -> list[Action]:
        return list(self._audit)
