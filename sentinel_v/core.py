#!/usr/bin/env python3
"""
Sentinel-V Core System
Main orchestrator for the autonomous defense framework
"""

import json
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Deque
from enum import Enum
from datetime import datetime
from collections import defaultdict, deque

from .deception import DeceptionNetwork
from .crypto import QuantumResistantCrypto
from .response import AutonomousResponseEngine
from .monitoring import AdaptiveThreatMatrix
from .federation import FederatedDefenseNode

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
    resource_usage: Dict[str, float] = field(default_factory=lambda: {
        "cpu": 0.0,
        "memory": 0.0,
        "bandwidth": 0.0,
        "disk": 0.0
    })
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "events_processed": self.events_processed,
            "threats_detected": self.threats_detected,
            "false_positives": self.false_positives,
            "avg_processing_time": self.avg_processing_time,
            "system_uptime": self.system_uptime,
            "resource_usage": self.resource_usage
        }

class SentinelVSystem:
    """
    Main orchestrator for the Sentinel-V defense system
    Coordinates all components and provides unified interface
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._load_default_config()
        self.system_id = self._generate_system_id()
        
        # Initialize components
        self.threat_matrix = AdaptiveThreatMatrix(
            learning_rate=self.config.get("ml_learning_rate", 0.1),
            memory_size=self.config.get("ml_memory_size", 10000)
        )
        
        self.deception_net = DeceptionNetwork(
            network_range=self.config.get("deception_network", "10.0.0.0/24"),
            decoy_count=self.config.get("decoy_count", 5)
        )
        
        self.crypto = QuantumResistantCrypto(
            algorithm=self.config.get("crypto_algorithm", "lattice")
        )
        
        self.response_engine = AutonomousResponseEngine(
            max_escalation=self.config.get("max_escalation", 3),
            autonomous_mode=self.config.get("autonomous_response", True)
        )
        
        # Federation capabilities
        self.federation_enabled = self.config.get("federation_enabled", False)
        if self.federation_enabled:
            self.federation = FederatedDefenseNode(
                node_id=self.system_id,
                discovery_url=self.config.get("federation_discovery_url")
            )
        
        # System state
        self.mode = SystemMode(self.config.get("system_mode", "production"))
        self.defense_level = DefenseLevel(self.config.get("defense_level", "standard"))
        self.status = "initializing"
        self.start_time = datetime.now()
        
        # Metrics and logging
        self.metrics = SystemMetrics()
        self.event_log: Deque[Dict[str, Any]] = deque(maxlen=10000)
        self.threat_log: Deque[Dict[str, Any]] = deque(maxlen=5000)
        
        # Resource management
        self.resource_budget = self.config.get("resource_budget", {
            "cpu": 0.3,
            "memory": 0.5,
            "bandwidth": 0.2
        })
        
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
            "resource_budget": {
                "cpu": 0.3,
                "memory": 0.5,
                "bandwidth": 0.2
            }
        }
    
    def _generate_system_id(self) -> str:
        """Generate unique system identifier"""
        import hashlib
        import socket
        import uuid
        
        hostname = socket.gethostname()
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0, 8*6, 8)][::-1])
        
        identifier = f"{hostname}-{mac}-{datetime.now().timestamp()}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]
    
    def _initialize_system(self):
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
        logging.info(f"Sentinel-V System ready (Mode: {self.mode.value}, Level: {self.defense_level.value})")
    
    def _activate_production_defenses(self):
        """Activate defenses for production mode"""
        # High-priority defenses always active
        logging.info("Activating production defenses")
        
        # Set aggressive monitoring
        self.threat_matrix.threshold_multiplier = 0.8
        
        # Activate deception network
        self.deception_net.active = True
        
        # Enable autonomous response
        self.response_engine.autonomous = True
        
    def _activate_testing_defenses(self):
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
                    source_ip=validated_event.get("source_ip"),
                    target_ip=validated_event.get("dest_ip"),
                    port=validated_event.get("dest_port", 0),
                    protocol=validated_event.get("protocol", "tcp")
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
                "processing_time": time.time() - start_time
            }
            
            # 5. Log assessment
            self.event_log.append(assessment)
            
            # 6. If threat detected, handle response
            if threat_level.value >= 2:  # MALICIOUS or higher
                self.threat_log.append(assessment)
                self.metrics.threats_detected += 1
                
                # Generate response
                response = self.response_engine.evaluate_threat(assessment)
                
                # Execute if autonomous mode enabled
                if self.response_engine.autonomous:
                    execution_result = self.response_engine.execute_response(response)
                    assessment["response_executed"] = execution_result
                    assessment["response_details"] = response
                
                # Share with federation if enabled
                if self.federation_enabled and threat_level.value >= 3:
                    self.federation.share_threat_intelligence(assessment)
            
            # Update metrics
            self.metrics.events_processed += 1
            processing_time = time.time() - start_time
            self.metrics.avg_processing_time = (
                (self.metrics.avg_processing_time * (self.metrics.events_processed - 1) + processing_time)
                / self.metrics.events_processed
            )
            
            return assessment
            
        except Exception as e:
            logging.error(f"Error processing event: {e}")
            return {
                "error": str(e),
                "event": event,
                "timestamp": datetime.now().isoformat()
            }
    
    def _validate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize security event"""
        validated = event.copy()
        
        # Ensure required fields
        validated["timestamp"] = validated.get("timestamp") or datetime.now().isoformat()
        validated["event_id"] = validated.get("event_id") or self._generate_event_id()
        
        # Normalize IP addresses
        for field in ["source_ip", "dest_ip"]:
            if field in validated:
                validated[field] = self._normalize_ip(validated[field])
        
        return validated
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address format"""
        if ip == "localhost":
            return "127.0.0.1"
        return ip
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (non-RFC1918)"""
        try:
            octets = list(map(int, ip.split('.')))
            if octets[0] == 10:
                return False
            elif octets[0] == 172 and 16 <= octets[1] <= 31:
                return False
            elif octets[0] == 192 and octets[1] == 168:
                return False
            elif ip.startswith("127."):
                return False
            return True
        except:
            return True
    
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
                    "memory_usage": len(self.threat_matrix.attack_memory)
                },
                "deception_network": self.deception_net.get_statistics(),
                "response_engine": {
                    "responses_executed": len(self.response_engine.response_history),
                    "autonomous": self.response_engine.autonomous
                },
                "federation": {
                    "enabled": self.federation_enabled,
                    "nodes_connected": len(self.federation.connected_nodes) if self.federation_enabled else 0
                }
            },
            "event_counts": {
                "total_processed": self.metrics.events_processed,
                "threats_detected": self.metrics.threats_detected,
                "false_positives": self.metrics.false_positives,
                "active_decoys": self.deception_net.get_statistics()["active_decoys"]
            }
        }
    
    def _monitor_system(self):
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
                
                # Sleep before next check
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logging.error(f"Error in system monitor: {e}")
                time.sleep(60)
    
    def _update_resource_metrics(self):
        """Update resource usage metrics (simplified)"""
        # In production, use psutil or similar
        import random
        self.metrics.resource_usage = {
            "cpu": random.uniform(0.1, 0.4),
            "memory": random.uniform(0.2, 0.6),
            "bandwidth": random.uniform(0.05, 0.3),
            "disk": random.uniform(0.1, 0.3)
        }
    
    def _check_health(self) -> Dict[str, Any]:
        """Check system health status"""
        health = {
            "overall": "healthy",
            "components": {},
            "issues": []
        }
        
        # Check resource usage against budget
        for resource, usage in self.metrics.resource_usage.items():
            budget = self.resource_budget.get(resource, 1.0)
            if usage > budget:
                health["issues"].append(f"{resource}_over_budget")
                health["overall"] = "warning"
        
        # Check component health
        # (In production, would check actual component health)
        
        return health
    
    def _adjust_defenses(self, health_status: Dict[str, Any]):
        """Adjust defense levels based on health and threat load"""
        
        if health_status["overall"] == "warning":
            # Reduce defenses if system is stressed
            if self.defense_level != DefenseLevel.PASSIVE:
                self.defense_level = DefenseLevel.PASSIVE
                logging.warning("Reduced defense level due to resource constraints")
        
        # Adjust based on threat volume
        recent_threats = len([t for t in self.threat_log 
                            if (datetime.now() - datetime.fromisoformat(t["timestamp"])).seconds < 300])
        
        if recent_threats > 20 and self.defense_level != DefenseLevel.PARANOID:
            self.defense_level = DefenseLevel.PARANOID
            logging.warning("Elevated defense level due to high threat volume")
    
    def _cleanup_old_data(self):
        """Clean up old data to prevent memory exhaustion"""
        # Threat matrix self-cleans based on its memory size
        
        # Clean old events (keep last 24 hours)
        cutoff = datetime.now().timestamp() - (24 * 3600)
        self.event_log = deque(
            [e for e in self.event_log 
             if datetime.fromisoformat(e["timestamp"]).timestamp() > cutoff],
            maxlen=10000
        )
    
    def shutdown(self):
        """Gracefully shutdown the system"""
        logging.info("Shutting down Sentinel-V system")
        
        self.shutdown_flag.set()
        
        if self.federation_enabled:
            self.federation.leave_network()
        
        self.status = "shutdown"
        logging.info("Sentinel-V system shutdown complete")

# Convenience function for quick initialization
def create_sentinel_system(config_file: Optional[str] = None) -> SentinelVSystem:
    """
    Create a Sentinel-V system with optional configuration file
    
    Args:
        config_file: Path to configuration file (YAML or JSON)
    
    Returns:
        Initialized SentinelVSystem instance
    """
    config = {}
    
    if config_file:
        import yaml
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                config = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                config = json.load(f)
    
    return SentinelVSystem(config)
