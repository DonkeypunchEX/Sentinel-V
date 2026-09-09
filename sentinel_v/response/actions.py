"""Response action handlers. Each returns an ``undo`` record for the audit log.

Simulation-safe by design (README): handlers record *intent* and how to reverse
it; they do not themselves reach out and touch production infrastructure. The
``block_ip`` handler writes an nftables-style rule to a file you control — wire
that file into your firewall out-of-band if and when you trust the automation.

D3FEND: block_ip → Network Traffic Filtering; notify → alerting/handoff.
"""
from __future__ import annotations

import logging
from ipaddress import ip_address
from pathlib import Path

from sentinel_v.models import Action, Incident

log = logging.getLogger(__name__)


def notify(action: Action, incident: Incident) -> dict[str, object]:
    """Non-destructive handoff. Records the notification; nothing to undo."""
    channel = str(action.detail.get("channel", "log"))
    log.warning(
        "NOTIFY[%s] incident=%s severity=%s: %s",
        channel, incident.id, incident.severity, incident.title,
    )
    return {"reversible": False, "channel": channel, "incident_id": incident.id}


def make_block_ip(block_list_path: str | Path):
    """Build a reversible, simulation-safe block_ip handler bound to a file.

    Writes ``add element inet filter blocklist { <ip> }`` to the block list and
    returns an undo record with the exact line to remove. Idempotent: an IP
    already present is not appended twice.
    """
    path = Path(block_list_path)

    def block_ip(action: Action, incident: Incident) -> dict[str, object]:
        ip = str(action.detail.get("src_ip") or incident.detail.get("src_ip") or "").strip()
        if not ip or ip == "unknown":
            raise ValueError("block_ip requires a resolved src_ip on the incident")
        # Never interpolate an unvalidated token into a firewall rule.
        try:
            ip = str(ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"block_ip refuses a non-IP src_ip: {ip!r}") from exc
        rule = f"add element inet filter blocklist {{ {ip} }}"
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        if rule not in existing:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(rule + "\n")
        log.warning("BLOCK_IP (simulated) %s → %s", ip, path)
        return {
            "reversible": True,
            "ip": ip,
            "path": str(path),
            "rule": rule,
            "undo_rule": f"delete element inet filter blocklist {{ {ip} }}",
        }

    return block_ip
