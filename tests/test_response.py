"""P0 item 2: gated, durable, reversible response orchestration."""
from __future__ import annotations

import pytest

from sentinel_v.models import Action, Incident, Severity
from sentinel_v.response.actions import make_block_ip, notify
from sentinel_v.response.orchestrator import Orchestrator
from sentinel_v.storage import Store


def _incident(src_ip="9.9.9.9"):
    return Incident(title="Brute-force", severity=Severity.HIGH, attack_technique="T1110",
                    detail={"src_ip": src_ip})


def _orch(store, tmp_path):
    o = Orchestrator(store)
    o.register("notify", notify)
    o.register("block_ip", make_block_ip(tmp_path / "blocked.nft"))
    return o


def test_notify_executes_immediately(tmp_path):
    store = Store("sqlite://")
    o = _orch(store, tmp_path)
    inc = _incident()
    a = o.run(Action(playbook="p", name="notify", detail={"src_ip": inc.detail["src_ip"]}), inc)
    assert a.executed is True
    assert store.get_pending_actions() == []


def test_destructive_action_is_gated_then_approved(tmp_path):
    store = Store("sqlite://")
    o = _orch(store, tmp_path)
    inc = _incident()
    blocklist = tmp_path / "blocked.nft"

    queued = o.run(
        Action(playbook="p", name="block_ip", destructive=True, reversible=True,
               incident_id=inc.id, detail={"src_ip": "9.9.9.9"}),
        inc,
    )
    # Nothing fired: it's pending, and the firewall file was not written.
    assert queued.executed is False
    assert not blocklist.exists()
    assert [a.id for a in store.get_pending_actions()] == [queued.id]

    done = o.approve(queued.id, "analyst@corp", inc)
    assert done.executed is True
    assert done.approver == "analyst@corp"
    assert done.undo and done.undo["reversible"] is True
    assert "9.9.9.9" in blocklist.read_text()
    assert store.get_pending_actions() == []  # no longer pending
    assert any(a.name == "block_ip" and a.executed for a in store.get_audit(executed=True))


def test_pending_survives_restart(tmp_path):
    store = Store("sqlite:///" + str(tmp_path / "s.db"))  # file-backed = real persistence
    o1 = _orch(store, tmp_path)
    inc = _incident()
    store.add_incident(inc)
    q = o1.run(
        Action(playbook="p", name="block_ip", destructive=True, incident_id=inc.id,
               detail={"src_ip": "9.9.9.9"}),
        inc,
    )
    # Fresh orchestrator + fresh Store on the same DB = simulated process restart.
    store2 = Store("sqlite:///" + str(tmp_path / "s.db"))
    o2 = _orch(store2, tmp_path)
    assert [a.id for a in o2.pending] == [q.id]
    done = o2.approve(q.id, "analyst@corp", store2.get_incident(inc.id))
    assert done.executed is True


def test_block_ip_requires_resolved_ip(tmp_path):
    store = Store("sqlite://")
    o = _orch(store, tmp_path)
    inc = _incident(src_ip="unknown")
    a = Action(playbook="p", name="block_ip", destructive=True, approved=True,
               incident_id=inc.id, detail={"src_ip": "unknown"})
    with pytest.raises(ValueError):
        o.run(a, inc)
