#!/usr/bin/env python3
"""
Sentinel-V Core System
Main orchestrator for the autonomous defense framework
"""

import ipaddress
import json
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, Deque
from enum import Enum
from datetime import datetime
from collections import deque

from .deception import DeceptionNetwork
from .crypto import QuantumResistantCrypto
from .response import AutonomousResponseEngine
from .monitoring import AdaptiveThreatMatrix
from .federation import FederatedDefenseNode
from .active_defense import ActiveDefenseEngine
from .forensics import ForensicCapture
from .paths import status_file


class SystemMode(Enum):
    """System operational modes"""

    DEVELOPMENT = "dev"
    TESTING = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class DefenseLevel(Enum):
    """Defense intensity levels"""

    PASSIVE = "passive"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    PARANOID = "paranoid"


@dataclass
class SystemMetrics:
    """System performance and health metrics"""

    events_processed: int = 0
    threats_detected: int = 0
    false_positives: int = 0
    avg_processing_time: float = 0.0
    system_uptime: float = 0.0
    resource_usage: Dict[str, float] = field(
        default_factory=lambda: {
            "cpu": 0.0,
            "memory": 0.0,
            "bandwidth": 0.0,
            "disk": 0.0,
        }
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "events_processed": self.events_processed,
            "threats_detected": self.threats_detected,
            "false_positives": self.false_positives,
            "avg_processing_time": self.avg_processing_time,
            "system_uptime": self.system_uptime,
            "resource_usage": self.resource_usage,
        }


class SentinelVSystem:
    """
    Main orchestrator for the Sentinel-V defense system
    Coordinates all components and provides unified interface
    """

    # Address ranges treated as "internal" when classifying an event's
    # source IP. Deliberately narrower than ipaddress's built-in
    # is_private, which also lumps in documentation/test-net ranges
    # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) — this codebase's
    # tests use those ranges to stand in for real external attacker IPs.
    _INTERNAL_NETWORKS = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # link-local
        ipaddress.ip_network("100.64.0.0/10"),  # CGNAT shared space (RFC 6598)
        ipaddress.ip_network("::1/128"),  # loopback
        ipaddress.ip_network("fc00::/7"),  # unique local address
        ipaddress.ip_network("fe80::/10"),  # link-local
    )

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        write_status_file: bool = False,
    ):
        self.config = config or self._load_default_config()
        self._write_status_file = write_status_file
        self.system_id = self._generate_system_id()

        # Initialize components
        self.threat_matrix = AdaptiveThreatMatrix(
            learning_rate=self.config.get("ml_learning_rate", 0.1),
            memory_size=self.config.get("ml_memory_size", 10000),
        )

        self.deception_net = DeceptionNetwork(
            network_range=self.config.get("deception_network", "10.0.0.0/24"),
            decoy_count=self.config.get("decoy_count", 5),
        )

        self.crypto = QuantumResistantCrypto(
            algorithm=self.config.get("crypto_algorithm", "lattice")
        )

        self.response_engine = AutonomousResponseEngine(
            max_escalation=self.config.get("max_escalation", 3),
            autonomous_mode=self.config.get("autonomous_response", True),
        )

        # Active Defense capabilities
        self.active_defense_enabled = self.config.get("active_defense_enabled", False)
        self.active_defense = ActiveDefenseEngine(
            enforce_mode=self.config.get("active_defense_enforce", False),
            auto_block=self.config.get("active_defense_auto_block", True),
            auto_isolate=self.config.get("active_defense_auto_isolate", False),
            auto_rate_limit=self.config.get("active_defense_auto_rate_limit", True),
            block_duration=self.config.get("active_defense_block_duration"),
        )

        # Forensic capture
        self.forensics_enabled = self.config.get("forensics_enabled", False)
        self.forensics = ForensicCapture(
            max_payload_size=self.config.get(
                "forensics_max_payload_size", 100 * 1024 * 1024
            ),
            extract_iocs=self.config.get("forensics_extract_iocs", True),
        )

        # Federation capabilities
        self.federation_enabled = self.config.get("federation_enabled", False)
        if self.federation_enabled:
            self.federation = FederatedDefenseNode(
                node_id=self.system_id,
                discovery_url=self.config.get("federation_discovery_url"),
            )

        # System state
        self.mode = SystemMode(self.config.get("system_mode", "production"))
        self.defense_level = DefenseLevel(self.config.get("defense_level", "standard"))
        # The configured level is the floor: resource pressure never takes the
        # system below it, and elevated levels relax back to it.
        self.baseline_defense_level = self.defense_level
        self.resource_warning_active = False
        self.status = "initializing"
        self.start_time = datetime.now()

        # Metrics and logging
        self.metrics = SystemMetrics()
        self.event_log: Deque[Dict[str, Any]] = deque(maxlen=10000)
        self.threat_log: Deque[Dict[str, Any]] = deque(maxlen=5000)

        # Resource management
        self.resource_budget = self.config.get(
            "resource_budget", {"cpu": 0.3, "memory": 0.5, "bandwidth": 0.2}
        )

        # Initialize monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.shutdown_flag = threading.Event()

        # Initialize defenses
        self._initialize_system()

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "system_mode": "production",
            "defense_level": "standard",
            "deception_network": "10.0.0.0/24",
            "decoy_count": 5,
            "ml_learning_rate": 0.1,
            "ml_memory_size": 10000,
            "crypto_algorithm": "lattice",
            "max_escalation": 3,
            "autonomous_response": True,
            "federation_enabled": False,
            "resource_budget": {"cpu": 0.3, "memory": 0.5, "bandwidth": 0.2},
        }

    def _generate_system_id(self) -> str:
        """Generate unique system identifier"""
        import hashlib
        import socket
        import uuid

        hostname = socket.gethostname()
        mac = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 8 * 6, 8)
            ][::-1]
        )

        identifier = f"{hostname}-{mac}-{datetime.now().timestamp()}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def _initialize_system(self) -> None:
        """Initialize all system components"""
        logging.info(f"Initializing Sentinel-V System [{self.system_id}]")

        # Activate base defenses based on mode
        if self.mode == SystemMode.PRODUCTION:
            self._activate_production_defenses()
        elif self.mode == SystemMode.TESTING:
            self._activate_testing_defenses()

        # Start monitoring
        self.monitor_thread.start()

        # Join federation if enabled
        if self.federation_enabled:
            self.federation.join_network()

        self.status = "operational"
        logging.info(
            "Sentinel-V System ready (Mode: %s, Level: %s)",
            self.mode.value,
            self.defense_level.value,
        )

    def _activate_production_defenses(self) -> None:
        """Activate defenses for production mode"""
        # High-priority defenses always active
        logging.info("Activating production defenses")

        # Set aggressive monitoring
        self.threat_matrix.threshold_multiplier = 0.8

        # Activate deception network
        self.deception_net.active = True

        # Enable autonomous response
        self.response_engine.autonomous = True

    def _activate_testing_defenses(self) -> None:
        """Activate defenses for testing mode"""
        logging.info("Activating testing defenses")

        # Lower thresholds for testing
        self.threat_matrix.threshold_multiplier = 0.5

        # Limited deception
        self.deception_net.active = True

        # No autonomous response
        self.response_engine.autonomous = False

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a security event through the defense pipeline

        Args:
            event: Security event dictionary

        Returns:
            Threat assessment and response information
        """
        start_time = time.time()

        try:
            # 1. Validate event
            validated_event = self._validate_event(event)

            # 2. Check deception network (if source is external)
            is_decoy = False
            if self._is_external_ip(validated_event.get("source_ip", "")):
                is_decoy = self.deception_net.detect_interaction(
                    source_ip=validated_event.get("source_ip", ""),
                    target_ip=validated_event.get("dest_ip", ""),
                    port=validated_event.get("dest_port", 0),
                    protocol=validated_event.get("protocol", "tcp"),
                )

            # 3. Analyze with threat matrix
            anomaly_score, threat_level = self.threat_matrix.analyze(validated_event)

            # 4. Create threat assessment
            threat_id = self._generate_threat_id(validated_event)
            assessment = {
                "threat_id": threat_id,
                "event": validated_event,
                "anomaly_score": anomaly_score,
                "threat_level": threat_level.name,
                "is_decoy_interaction": is_decoy,
                "timestamp": datetime.now().isoformat(),
                "processing_time": time.time() - start_time,
            }

            # 5. Log assessment
            self.event_log.append(assessment)

            # 6. If threat detected, handle response
            # Decoy contact always warrants a response, even when the
            # underlying feature score alone reads BENIGN/SUSPICIOUS —
            # legitimate traffic has no reason to touch a decoy.
            if threat_level.value >= 2 or is_decoy:  # MALICIOUS+ or decoy hit
                self.threat_log.append(assessment)
                self.metrics.threats_detected += 1

                # Generate response
                response = self.response_engine.evaluate_threat(assessment)

                # Execute if autonomous mode enabled
                if self.response_engine.autonomous:
                    execution_result = self.response_engine.execute_response(response)
                    assessment["response_executed"] = execution_result
                    assessment["response_details"] = response

                # Active defense: block IP, isolate host, or rate limit
                if self.active_defense_enabled:
                    self._apply_active_defense(assessment, response, is_decoy)

                # Forensic capture: save payloads and extract IoCs
                if self.forensics_enabled:
                    self._apply_forensic_capture(assessment, event)

                # Share with federation if enabled
                if self.federation_enabled and threat_level.value >= 3:
                    self.federation.share_threat_intelligence(assessment)

            # Update metrics
            self.metrics.events_processed += 1
            processing_time = time.time() - start_time
            self.metrics.avg_processing_time = (
                self.metrics.avg_processing_time * (self.metrics.events_processed - 1)
                + processing_time
            ) / self.metrics.events_processed

            return assessment

        except Exception as e:
            logging.error(f"Error processing event: {e}")
            return {
                "error": str(e),
                "event": event,
                "timestamp": datetime.now().isoformat(),
            }

    def _validate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize security event"""
        validated = event.copy()

        # Ensure required fields
        validated["timestamp"] = (
            validated.get("timestamp") or datetime.now().isoformat()
        )
        validated["event_id"] = validated.get("event_id") or self._generate_event_id()

        # Normalize IP addresses
        for ip_field in ["source_ip", "dest_ip"]:
            if ip_field in validated:
                validated[ip_field] = self._normalize_ip(validated[ip_field])

        return validated

    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address to its canonical string form.

        Unparseable input (including "" and non-IP hostnames other than
        "localhost") is passed through unchanged rather than raising, since
        the caller must not let a malformed event field crash the pipeline.
        """
        if ip == "localhost":
            return "127.0.0.1"
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (outside the trusted/internal address space).

        Unparseable input is treated as external so it still passes through
        the deception-network and threat-matrix checks rather than being
        silently trusted.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True

        if addr.is_multicast:
            return False

        return not any(addr in network for network in self._INTERNAL_NETWORKS)

    def _apply_active_defense(
        self,
        assessment: Dict[str, Any],
        response: Dict[str, Any],
        is_decoy: bool,
    ) -> None:
        """Apply active defense measures based on threat assessment."""
        event = assessment.get("event", {})
        source_ip = event.get("source_ip", "")
        threat_level = assessment.get("threat_level", "BENIGN")
        escalation_step = response.get("escalation_step", 0)

        # Always block on decoy interaction or CRITICAL threats
        if is_decoy or threat_level == "CRITICAL" or escalation_step >= 3:
            self.active_defense.block_ip(
                ip=source_ip,
                reason=f"Threat detected: {threat_level} (decoy={is_decoy})",
            )

        # Rate limit on MALICIOUS threats
        if threat_level == "MALICIOUS" or escalation_step >= 2:
            dest_port = event.get("dest_port", 0)
            if dest_port > 0:
                self.active_defense.rate_limit(
                    source=source_ip,
                    port=dest_port,
                    protocol=event.get("protocol", "tcp"),
                    rate="10/min",
                    reason=f"Suspicious activity: {threat_level}",
                )

        # Isolate internal hosts that are compromised
        dest_ip = event.get("dest_ip", "")
        if threat_level == "CRITICAL" and self._is_external_ip(dest_ip):
            self.active_defense.isolate_host(
                ip=dest_ip,
                reason=f"Critical threat detected: {threat_level}",
            )

    def _apply_forensic_capture(
        self,
        assessment: Dict[str, Any],
        event: Dict[str, Any],
    ) -> None:
        """Capture forensic data from threat events."""
        threat_id = assessment.get("threat_id", "")
        source_ip = event.get("source_ip", "")
        threat_level = assessment.get("threat_level", "BENIGN")

        # Capture payloads if present
        if "payload" in event:
            payload = event["payload"]
            if isinstance(payload, bytes):
                self.forensics.dump_payload(
                    threat_id=threat_id,
                    payload=payload,
                    source_ip=source_ip,
                    metadata={
                        "threat_level": threat_level,
                        "event_type": event.get("event_type", "unknown"),
                    },
                )

        # For CRITICAL threats, start a session log
        if threat_level == "CRITICAL":
            session_id = self.forensics.start_session(
                threat_id=threat_id,
                source_ip=source_ip,
                metadata={
                    "threat_level": threat_level,
                    "event_type": event.get("event_type", "unknown"),
                },
            )
            assessment["forensic_session_id"] = session_id

    def _generate_event_id(self) -> str:
        """Generate unique event identifier"""
        import hashlib
        import secrets

        random_data = secrets.token_bytes(16)
        timestamp = datetime.now().isoformat().encode()

        return hashlib.sha256(random_data + timestamp).hexdigest()[:16]

    def _generate_threat_id(self, event: Dict[str, Any]) -> str:
        """Generate unique threat identifier"""
        import hashlib

        event_str = json.dumps(event, sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()[:16]

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        uptime = (datetime.now() - self.start_time).total_seconds()

        return {
            "system_id": self.system_id,
            "status": self.status,
            "mode": self.mode.value,
            "defense_level": self.defense_level.value,
            "uptime": uptime,
            "metrics": self.metrics.to_dict(),
            "components": {
                "threat_matrix": {
                    "patterns_learned": len(self.threat_matrix.patterns),
                    "memory_usage": len(self.threat_matrix.attack_memory),
                },
                "deception_network": self.deception_net.get_statistics(),
                "response_engine": {
                    "responses_executed": len(self.response_engine.response_history),
                    "autonomous": self.response_engine.autonomous,
                },
                "federation": {
                    "enabled": self.federation_enabled,
                    "nodes_connected": (
                        len(self.federation.connected_nodes)
                        if self.federation_enabled
                        else 0
                    ),
                },
            },
            "event_counts": {
                "total_processed": self.metrics.events_processed,
                "threats_detected": self.metrics.threats_detected,
                "false_positives": self.metrics.false_positives,
                "active_decoys": self.deception_net.get_statistics()["active_decoys"],
            },
        }

    def _monitor_system(self) -> None:
        """Monitor system health and adjust defenses"""
        while not self.shutdown_flag.is_set():
            try:
                # Update resource usage
                self._update_resource_metrics()

                # Check system health
                health_status = self._check_health()

                # Adjust defenses based on load and health
                self._adjust_defenses(health_status)

                # Clean up old data
                self._cleanup_old_data()

                # Publish a heartbeat so `sentinel-v status` (run from a
                # separate process) can read live state off disk
                if self._write_status_file:
                    self._write_heartbeat()

                # Sleep before next check, but wake immediately during shutdown.
                self.shutdown_flag.wait(30)

            except Exception as e:
                logging.error(f"Error in system monitor: {e}")
                self.shutdown_flag.wait(60)

    def _write_heartbeat(self) -> None:
        """Persist current status to the heartbeat file, atomically.

        The temp file name includes the pid and thread id so concurrent
        writers (the monitor thread and an explicit call, or two system
        instances sharing a state dir) never collide on the same path.
        """
        import os

        payload = self.get_system_status()
        payload["pid"] = os.getpid()
        payload["last_updated"] = datetime.now().isoformat()

        target = status_file()
        tmp = target.with_name(
            f"{target.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            tmp.write_text(json.dumps(payload))
            tmp.replace(target)
        except OSError as e:
            logging.error(f"Failed to write status heartbeat: {e}")

    def _remove_heartbeat(self) -> None:
        """Best-effort removal of the heartbeat file on shutdown."""
        try:
            status_file().unlink(missing_ok=True)
        except OSError:
            pass

    def _update_resource_metrics(self) -> None:
        """Update resource usage metrics from the host"""
        try:
            import psutil

            self.metrics.resource_usage = {
                "cpu": psutil.cpu_percent(interval=None) / 100.0,
                "memory": psutil.virtual_memory().percent / 100.0,
                "bandwidth": 0.0,  # needs a baseline interval; left to integrations
                "disk": psutil.disk_usage("/").percent / 100.0,
            }
        except (ImportError, OSError):
            # psutil unavailable on this platform — leave last known values
            pass

    def _check_health(self) -> Dict[str, Any]:
        """Check system health status"""
        health: Dict[str, Any] = {"overall": "healthy", "components": {}, "issues": []}

        # Check resource usage against budget
        for resource, usage in self.metrics.resource_usage.items():
            budget = self.resource_budget.get(resource, 1.0)
            if usage > budget:
                health["issues"].append(f"{resource}_over_budget")
                health["overall"] = "warning"

        # Check component health
        # (In production, would check actual component health)

        return health

    def _adjust_defenses(self, health_status: Dict[str, Any]) -> None:
        """Adjust defense levels based on health and threat load"""

        # Resource pressure is reported, never used to lower defenses: an
        # attacker who can exhaust host memory must not be able to make the
        # defense system stand itself down. Shed optional work instead.
        over_budget = health_status["overall"] == "warning"
        if over_budget and not self.resource_warning_active:
            logging.warning(
                "Host over resource budget (%s); defense level unchanged",
                ", ".join(health_status.get("issues", [])),
            )
        self.resource_warning_active = over_budget

        # Adjust based on threat volume. total_seconds(), not .seconds:
        # .seconds drops the days component, so day-old threats counted as recent.
        now = datetime.now()
        recent_threats = sum(
            1
            for t in self.threat_log
            if (now - datetime.fromisoformat(t["timestamp"])).total_seconds() < 300
        )

        if recent_threats > 20:
            if self.defense_level != DefenseLevel.PARANOID:
                self.defense_level = DefenseLevel.PARANOID
                logging.warning("Elevated defense level due to high threat volume")
        elif self.defense_level != self.baseline_defense_level:
            self.defense_level = self.baseline_defense_level
            logging.info(
                "Threat volume normal; defense level restored to %s",
                self.defense_level.value,
            )

    def _cleanup_old_data(self) -> None:
        """Clean up old data to prevent memory exhaustion"""
        # Threat matrix self-cleans based on its memory size

        # Clean old events (keep last 24 hours)
        cutoff = datetime.now().timestamp() - (24 * 3600)
        self.event_log = deque(
            [
                e
                for e in self.event_log
                if datetime.fromisoformat(e["timestamp"]).timestamp() > cutoff
            ],
            maxlen=10000,
        )

    def shutdown(self) -> None:
        """Gracefully shutdown the system"""
        logging.info("Shutting down Sentinel-V system")

        self.shutdown_flag.set()
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)

        if self.federation_enabled:
            self.federation.leave_network()

        if self._write_status_file:
            self._remove_heartbeat()

        self.status = "shutdown"
        logging.info("Sentinel-V system shutdown complete")


# Convenience function for quick initialization
def create_sentinel_system(
    config_file: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
    write_status_file: bool = False,
) -> SentinelVSystem:
    """
    Create a Sentinel-V system with optional configuration file

    Args:
        config_file: Path to configuration file (YAML or JSON)
        overrides: Config keys that take precedence over the file
        write_status_file: Publish a heartbeat file for `sentinel-v status`
            to read. Only the long-running daemon (`sentinel-v start`)
            should set this - short-lived instances (analyze, status
            itself, ...) must not overwrite a real daemon's heartbeat.

    Returns:
        Initialized SentinelVSystem instance
    """
    config: Dict[str, Any] = {}

    if config_file:
        import yaml

        with open(config_file, "r") as f:
            if config_file.endswith(".yaml") or config_file.endswith(".yml"):
                config = yaml.safe_load(f) or {}
            elif config_file.endswith(".json"):
                config = json.load(f)

    if overrides:
        config.update(overrides)

    return SentinelVSystem(config or None, write_status_file=write_status_file)
