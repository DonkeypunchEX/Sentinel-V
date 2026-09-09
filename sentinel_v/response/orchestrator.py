"""SOAR-lite playbook runner core. The safety-critical component.

Rule: destructive actions are GATED (queued for human approval) unless the
playbook marks them auto AND reversible. Every executed action records how to
undo itself and lands in the audit log. See docs/PLAYBOOKS.md.

Durability: when constructed with a Store, both queued (pending) and executed
actions are persisted to the ``audit`` table, so a restart does not silently
drop a destructive action awaiting approval or lose the audit trail — the audit
being non-negotiable is a core project principle. Without a Store it falls back
to in-memory lists (fine for unit tests).
"""
from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from sentinel_v.models import Action, Incident
from sentinel_v.storage import Store

# An action handler performs the side effect and returns undo info.
ActionHandler = Callable[[Action, Incident], dict[str, object]]


class PendingApproval(Exception):
    """Raised/queued when a destructive action needs a human before it runs."""


class Orchestrator:
    def __init__(self, store: Store | None = None) -> None:
        self._handlers: dict[str, ActionHandler] = {}
        self._store = store
        self._pending: list[Action] = []  # in-memory fallback when no store
        self._audit: list[Action] = []
        self._approve_lock = Lock()  # serialize approvals within this process

    def register(self, name: str, handler: ActionHandler) -> None:
        self._handlers[name] = handler

    def run(self, action: Action, incident: Incident) -> Action:
        """Execute an action, or queue it for approval if it requires a gate."""
        if action.requires_gate() and not action.approved:
            action.executed = False
            self._persist(action)
            return action  # caller notifies; /approve resumes via approve()
        handler = self._handlers.get(action.name)
        if handler is None:
            raise KeyError(f"No handler registered for action '{action.name}'")
        action.undo = handler(action, incident)
        action.executed = True
        self._persist(action)
        return action

    def approve(self, action_id: str, approver: str, incident: Incident) -> Action:
        # Serialize approvals in-process so two concurrent requests can't both
        # read the same pending action and double-execute the handler. A full
        # cross-process claim (a transactional in-progress state in the store)
        # is the next step for a multi-worker deployment.
        with self._approve_lock:
            action = self._get_pending(action_id)
            if action is None:
                raise KeyError(f"No pending action {action_id}")
            action.approved = True
            action.approver = approver
            return self.run(action, incident)

    # ------------------------------------------------------------------ #
    def _persist(self, action: Action) -> None:
        if self._store is not None:
            self._store.record_action(action)  # upsert by id
            return
        # in-memory fallback
        self._pending = [a for a in self._pending if a.id != action.id]
        self._audit = [a for a in self._audit if a.id != action.id]
        (self._audit if action.executed else self._pending).append(action)

    def _get_pending(self, action_id: str) -> Action | None:
        if self._store is not None:
            action = self._store.get_action(action_id)
            return action if action is not None and not action.executed else None
        for a in self._pending:
            if a.id == action_id:
                return a
        return None

    @property
    def pending(self) -> list[Action]:
        if self._store is not None:
            return self._store.get_pending_actions()
        return list(self._pending)

    @property
    def audit(self) -> list[Action]:
        if self._store is not None:
            return self._store.get_audit(executed=True)
        return list(self._audit)
