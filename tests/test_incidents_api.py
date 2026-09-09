"""P0 acceptance (ROADMAP Phase 3): brute-force runs end-to-end through the API —
alert → correlated incident → proposed block (gated) → /approve → audited block
with an undo. Nothing destructive fires before approval.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel_v.api.app import create_app
from sentinel_v.config import Settings


def _client(tmp_path) -> TestClient:
    settings = Settings(
        db_url="sqlite://",
        rules_dir="rules",
        response={"block_list_path": str(tmp_path / "blocked.nft"), "playbooks_dir": "playbooks"},
        correlation={"window_seconds": 300, "brute_force_threshold": 5},
    )
    return TestClient(create_app(settings))


def _post_fail(client, ip="9.9.9.9"):
    return client.post("/events", json={
        "source": "auth.log", "kind": "auth_fail", "src_ip": ip,
        "fields": {"service": "sshd", "user": "admin"},
    })


def test_bruteforce_incident_and_gated_block_flow(tmp_path):
    c = _client(tmp_path)
    blocklist = tmp_path / "blocked.nft"

    last = None
    for _ in range(5):
        last = _post_fail(c).json()

    # The 5th ingest surfaced a T1110 incident and a proposed (gated) block.
    assert any(i["attack_technique"] == "T1110" for i in last["incidents"])
    assert any(a["name"] == "block_ip" and not a["executed"] for a in last["actions"])

    incidents = c.get("/incidents").json()
    assert len(incidents) == 1 and incidents[0]["severity"] == "high"

    pending = c.get("/actions/pending").json()
    assert len(pending) == 1 and pending[0]["name"] == "block_ip"
    # Gate held: nothing was written to the firewall file yet.
    assert not blocklist.exists()

    # Approve → the handler runs, the block is recorded with an undo.
    approved = c.post("/approve", json={"action_id": pending[0]["id"], "approver": "soc@corp"})
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["executed"] is True and body["approver"] == "soc@corp"
    assert body["undo"]["undo_rule"].startswith("delete element")
    assert "9.9.9.9" in blocklist.read_text()
    assert c.get("/actions/pending").json() == []


def test_approve_unknown_action_404(tmp_path):
    c = _client(tmp_path)
    r = c.post("/approve", json={"action_id": "does-not-exist", "approver": "x"})
    assert r.status_code == 404


def test_metrics_reports_playbooks(tmp_path):
    m = _client(tmp_path).get("/metrics").json()
    assert m["playbooks_loaded"] >= 1
