"""Federated defense node — local-first threat intelligence sharing.

Maintains an outbox of threat intelligence destined for peer nodes.
Network transport is intentionally out of scope for the core package:
``share_threat_intelligence`` queues sanitized records, and an
integration layer decides how (and whether) to deliver them.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

# Only these assessment fields ever leave the node; raw events stay local.
SHARED_FIELDS = ("threat_id", "threat_level", "anomaly_score", "timestamp")


class FederatedDefenseNode:
    """Tracks federation membership and queues outbound intelligence."""

    def __init__(self, node_id: str, discovery_url: Optional[str] = None):
        self.node_id = node_id
        self.discovery_url = discovery_url
        self.joined = False
        self.connected_nodes: List[str] = []
        self.outbox: List[Dict[str, Any]] = []

    def join_network(self) -> bool:
        """Mark this node as participating in the federation."""
        self.joined = True
        logging.info("federation join node=%s via=%s", self.node_id, self.discovery_url)
        return True

    def leave_network(self) -> None:
        """Leave the federation and drop peer state."""
        self.joined = False
        self.connected_nodes.clear()
        logging.info("federation leave node=%s", self.node_id)

    def share_threat_intelligence(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Queue a minimized copy of an assessment for peers.

        Strips everything except the fields in ``SHARED_FIELDS`` so raw
        event payloads (which may contain internal addresses) never
        leave the node.
        """
        record = {k: assessment.get(k) for k in SHARED_FIELDS}
        record["origin_node"] = self.node_id
        record["queued_at"] = datetime.now().isoformat()
        self.outbox.append(record)

        if len(self.outbox) > 1000:
            self.outbox = self.outbox[-500:]

        return record
