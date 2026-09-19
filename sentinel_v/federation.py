"""Federated defense node \u2014 local-first threat intelligence sharing.

Maintains an outbox of threat intelligence destined for peer nodes.
Network transport is intentionally out of scope for the core package:
``share_threat_intelligence`` queues sanitized records, and an
integration layer decides how (and whether) to deliver them.

Enhanced capabilities:
- Auto-share IoCs (IPs, domains, hashes) with peers
- Receive and apply IoCs from peers
- Track peer reputation
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .paths import state_dir

# Only these assessment fields ever leave the node; raw events stay local.
SHARED_FIELDS = ("threat_id", "threat_level", "anomaly_score", "timestamp")

# IoC types that can be shared
IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256")


class FederatedDefenseNode:
    """Tracks federation membership and queues outbound intelligence.
    
    Enhanced to support:
    - Sharing threat assessments with peers
    - Sharing extracted IoCs (IPs, domains, hashes)
    - Receiving and applying IoCs from peers
    - Tracking peer reputation and trust
    """

    def __init__(self, node_id: str, discovery_url: Optional[str] = None):
        self.node_id = node_id
        self.discovery_url = discovery_url
        self.joined = False
        self.connected_nodes: List[str] = []
        self.outbox: List[Dict[str, Any]] = []
        
        # Enhanced federation state
        self.shared_iocs: Set[str] = set()  # Track IoCs we've shared (ioc_type:value)
        self.received_iocs: Set[str] = set()  # Track IoCs received from peers
        self.peer_trust: Dict[str, float] = {}  # node_id -> trust score (0.0 to 1.0)
        self.peer_ioc_counts: Dict[str, int] = {}  # node_id -> number of IoCs shared
        
        # Local IoC storage for federation
        self.local_iocs: List[Dict[str, Any]] = []
        
        # State directory for persistence
        self.state_dir = Path(str(state_dir())) / "federation"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        logging.info(
            f"FederatedDefenseNode initialized (node_id={self.node_id}, "
            f"discovery_url={self.discovery_url})"
        )

    def join_network(self) -> bool:
        """Mark this node as participating in the federation."""
        self.joined = True
        logging.info("federation join node=%s via=%s", self.node_id, self.discovery_url)
        return True

    def leave_network(self) -> None:
        """Leave the federation and drop peer state."""
        self.joined = False
        self.connected_nodes.clear()
        self.peer_trust.clear()
        self.peer_ioc_counts.clear()
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

    def share_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str,
        confidence: float,
        source: str = "local",
    ) -> bool:
        """Share an IoC with federation peers.
        
        Args:
            ioc_type: Type of IoC (ip, domain, url, md5, sha1, sha256)
            value: IoC value
            description: Description of the IoC
            confidence: Confidence level (0.0 to 1.0)
            source: Source of the IoC
            
        Returns:
            True if IoC was queued for sharing, False otherwise
        """
        if ioc_type not in IOC_TYPES:
            logging.warning(f"Cannot share IoC type {ioc_type} - not in allowed types")
            return False
        
        # Create IoC record
        ioc_key = f"{ioc_type}:{value}"
        if ioc_key in self.shared_iocs:
            # Already shared this IoC
            return False
        
        ioc_record = {
            "type": "ioc",
            "ioc_type": ioc_type,
            "value": value,
            "description": description,
            "confidence": confidence,
            "source": source,
            "origin_node": self.node_id,
            "shared_at": datetime.now().isoformat(),
        }
        
        # Add to outbox
        self.outbox.append(ioc_record)
        self.shared_iocs.add(ioc_key)
        
        # Add to local IoC storage
        self.local_iocs.append(ioc_record)
        
        # Limit outbox size
        if len(self.outbox) > 1000:
            self.outbox = self.outbox[-500:]
        
        # Limit local IoC storage
        if len(self.local_iocs) > 10000:
            self.local_iocs = self.local_iocs[-5000:]
        
        logging.info(f"Shared IoC: {ioc_type}={value} (confidence={confidence})")
        
        return True

    def share_iocs_batch(self, iocs: List[Dict[str, Any]]) -> int:
        """Share multiple IoCs with federation peers.
        
        Args:
            iocs: List of IoC dictionaries with keys: ioc_type, value, description, confidence
            
        Returns:
            Number of IoCs successfully queued for sharing
        """
        count = 0
        for ioc in iocs:
            if self.share_ioc(
                ioc_type=ioc.get("ioc_type", ""),
                value=ioc.get("value", ""),
                description=ioc.get("description", ""),
                confidence=ioc.get("confidence", 0.5),
                source=ioc.get("source", "batch"),
            ):
                count += 1
        
        return count

    def receive_ioc(self, ioc: Dict[str, Any]) -> bool:
        """Receive an IoC from a peer node.
        
        Args:
            ioc: IoC dictionary with keys: ioc_type, value, description, confidence, origin_node
            
        Returns:
            True if IoC was accepted, False otherwise
        """
        ioc_type = ioc.get("ioc_type", "")
        value = ioc.get("value", "")
        origin_node = ioc.get("origin_node", "unknown")
        
        # Validate IoC
        if ioc_type not in IOC_TYPES:
            logging.warning(f"Received invalid IoC type {ioc_type} from {origin_node}")
            return False
        
        if not value:
            logging.warning(f"Received empty IoC value from {origin_node}")
            return False
        
        # Check if we already have this IoC
        ioc_key = f"{ioc_type}:{value}"
        if ioc_key in self.received_iocs:
            # Already have this IoC
            return False
        
        # Add to received IoCs
        self.received_iocs.add(ioc_key)
        
        # Update peer trust
        self._update_peer_trust(origin_node, ioc)
        
        # Store the IoC
        self.local_iocs.append(ioc)
        
        # Limit storage
        if len(self.local_iocs) > 10000:
            self.local_iocs = self.local_iocs[-5000:]
        
        logging.info(
            f"Received IoC from {origin_node}: {ioc_type}={value} "
            f"(confidence={ioc.get('confidence', 0.0)})"
        )
        
        return True

    def _update_peer_trust(self, node_id: str, ioc: Dict[str, Any]) -> None:
        """Update trust score for a peer node based on shared IoC."""
        if node_id not in self.peer_trust:
            self.peer_trust[node_id] = 0.5  # Default trust
            self.peer_ioc_counts[node_id] = 0
        
        # Increase trust based on IoC confidence
        confidence = ioc.get("confidence", 0.5)
        current_trust = self.peer_trust[node_id]
        
        # Simple trust update: move towards confidence
        self.peer_trust[node_id] = 0.9 * current_trust + 0.1 * confidence
        self.peer_ioc_counts[node_id] += 1

    def get_peer_trust(self, node_id: str) -> float:
        """Get the trust score for a peer node.
        
        Args:
            node_id: Node ID to check
            
        Returns:
            Trust score (0.0 to 1.0), or 0.0 if node not known
        """
        return self.peer_trust.get(node_id, 0.0)

    def get_shared_iocs(self) -> List[Dict[str, Any]]:
        """Get all IoCs that have been shared with peers.
        
        Returns:
            List of shared IoC dictionaries
        """
        return [ioc for ioc in self.outbox if ioc.get("type") == "ioc"]

    def get_received_iocs(self) -> List[Dict[str, Any]]:
        """Get all IoCs that have been received from peers.
        
        Returns:
            List of received IoC dictionaries
        """
        return [ioc for ioc in self.local_iocs if ioc.get("origin_node") != self.node_id]

    def get_all_iocs(self) -> List[Dict[str, Any]]:
        """Get all IoCs (both shared and received).
        
        Returns:
            List of all IoC dictionaries
        """
        return list(self.local_iocs)

    def get_peer_statistics(self) -> Dict[str, Any]:
        """Get statistics about connected peers.
        
        Returns:
            Dictionary with peer statistics
        """
        return {
            "connected_nodes": len(self.connected_nodes),
            "peer_trust_scores": self.peer_trust,
            "peer_ioc_counts": self.peer_ioc_counts,
            "total_shared_iocs": len(self.shared_iocs),
            "total_received_iocs": len(self.received_iocs),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive federation statistics.
        
        Returns:
            Dictionary with federation statistics
        """
        return {
            "joined": self.joined,
            "node_id": self.node_id,
            "connected_nodes": len(self.connected_nodes),
            "outbox_size": len(self.outbox),
            "shared_iocs_count": len(self.shared_iocs),
            "received_iocs_count": len(self.received_iocs),
            "local_iocs_count": len(self.local_iocs),
            "peer_trust_scores": self.peer_trust,
        }

    def sync_with_peer(self, peer_node: "FederatedDefenseNode") -> int:
        """Synchronize IoCs with a peer node.
        
        Args:
            peer_node: Peer node to sync with
            
        Returns:
            Number of IoCs exchanged
        """
        if not self.joined or not peer_node.joined:
            return 0
        
        count = 0
        
        # Share our IoCs with peer
        for ioc in self.local_iocs:
            if ioc.get("origin_node") == self.node_id:
                if peer_node.receive_ioc(ioc):
                    count += 1
        
        # Receive peer's IoCs
        for ioc in peer_node.local_iocs:
            if ioc.get("origin_node") == peer_node.node_id:
                if self.receive_ioc(ioc):
                    count += 1
        
        return count

    def save_state(self) -> bool:
        """Save federation state to disk.
        
        Returns:
            True if state was saved successfully, False otherwise
        """
        try:
            state = {
                "shared_iocs": list(self.shared_iocs),
                "received_iocs": list(self.received_iocs),
                "peer_trust": self.peer_trust,
                "peer_ioc_counts": self.peer_ioc_counts,
            }
            
            state_file = self.state_dir / "federation_state.json"
            state_file.write_text(json.dumps(state, indent=2))
            return True
        except Exception as e:
            logging.error(f"Failed to save federation state: {e}")
            return False

    def load_state(self) -> bool:
        """Load federation state from disk.
        
        Returns:
            True if state was loaded successfully, False otherwise
        """
        try:
            state_file = self.state_dir / "federation_state.json"
            if not state_file.exists():
                return False
            
            state = json.loads(state_file.read_text())
            self.shared_iocs = set(state.get("shared_iocs", []))
            self.received_iocs = set(state.get("received_iocs", []))
            self.peer_trust = state.get("peer_trust", {})
            self.peer_ioc_counts = state.get("peer_ioc_counts", {})
            return True
        except Exception as e:
            logging.error(f"Failed to load federation state: {e}")
            return False

    def reset(self) -> None:
        """Reset all federation state (for testing)."""
        self.joined = False
        self.connected_nodes.clear()
        self.outbox.clear()
        self.shared_iocs.clear()
        self.received_iocs.clear()
        self.peer_trust.clear()
        self.peer_ioc_counts.clear()
        self.local_iocs.clear()
        logging.info("FederatedDefenseNode reset")
