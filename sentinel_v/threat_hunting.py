"""Threat Hunting Module - Proactive IoC scanning and detection.

Provides capabilities to:
- Scan running processes for malicious indicators
- Scan network connections for suspicious activity
- Scan filesystem for known malware hashes
- Monitor for common attack patterns
- Load and update IoC feeds from external sources

This module enables proactive threat detection beyond just
reacting to events.
"""

import hashlib
import json
import logging
import platform
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .paths import state_dir


@dataclass
class IoC:
    """Represents an Indicator of Compromise."""
    ioc_type: str  # ip, domain, hash, filename, etc.
    value: str
    description: str
    confidence: float  # 0.0 to 1.0
    source: str  # Where this IoC came from
    first_seen: str
    last_seen: str
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "description": self.description,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
        }


@dataclass
class ScanResult:
    """Represents the result of a threat hunt scan."""
    scan_type: str
    start_time: str
    end_time: str
    findings: List[Dict[str, Any]]
    total_items_scanned: int
    total_findings: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "findings": self.findings,
            "total_items_scanned": self.total_items_scanned,
            "total_findings": self.total_findings,
        }


class ThreatHunter:
    """Proactively hunts for threats on the system.
    
    Provides methods to scan for:
    - Malicious processes
    - Suspicious network connections
    - Known malware hashes
    - Common attack patterns
    """

    # Known malicious hashes (MD5, SHA1, SHA256)
    # In production, these would be loaded from external feeds
    KNOWN_MALWARE_HASHES = {
        # Example hashes (not real malware)
        "md5": {
            "d41d8cd98f00b204e9800998ecf8427e": "EICAR Test File",
            "098f6bcd4621d373cade4e832627b4f6": "Test Malware 1",
        },
        "sha1": {
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": "EICAR Test File",
            "a9993e364706816aba3e25717850c26c9cd0d89d": "Test Malware 2",
        },
        "sha256": {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EICAR Test File",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0ff": "Test Malware 3",
        },
    }
    
    # Known malicious IPs (example data)
    KNOWN_MALICIOUS_IPS = {
        "1.1.1.1": "Known C2 Server",
        "2.2.2.2": "Known Scanner",
        "3.3.3.3": "Known Botnet",
    }
    
    # Known malicious domains
    KNOWN_MALICIOUS_DOMAINS = {
        "evil.com": "Known Malware Domain",
        "bad-actor.net": "Known C2 Domain",
        "malware-server.org": "Known Malware Distribution",
    }
    
    # Suspicious process names
    SUSPICIOUS_PROCESS_NAMES = {
        "mimikatz": "Credential Dumping Tool",
        "crackmapexec": "Lateral Movement Tool",
        "bloodhound": "AD Recon Tool",
        "powersploit": "Exploitation Framework",
        "metasploit": "Exploitation Framework",
        "cobaltstrike": "C2 Framework",
        "empire": "C2 Framework",
        "poshc2": "C2 Framework",
        "rubeus": "Kerberos Attack Tool",
        "sharp": "Offensive Security Tool",
        "procdump": "Memory Dumping Tool",
        "7z": "Archiving Tool (often used by attackers)",
        "certutil": "File Transfer Tool (abused by attackers)",
        "bitsadmin": "File Transfer Tool (abused by attackers)",
        "mshta": "HTML Application (abused by attackers)",
        "rundll32": "DLL Execution (abused by attackers)",
        "regsvr32": "DLL Registration (abused by attackers)",
        "wscript": "Script Execution (abused by attackers)",
        "cscript": "Script Execution (abused by attackers)",
    }
    
    # Suspicious port combinations
    SUSPICIOUS_PORTS = {
        4444: "Metasploit",
        4443: "Metasploit SSL",
        50050: "Metasploit",
        8080: "Alternative HTTP (often used by C2)",
        8443: "Alternative HTTPS (often used by C2)",
        8000: "Alternative HTTP (often used by C2)",
        9001: "Port Forwarding",
        31337: "Back Orifice",
        6667: "IRC (often used by botnets)",
    }

    def __init__(
        self,
        ioc_feeds: Optional[List[str]] = None,
        scan_interval: int = 300,  # 5 minutes
        state_dir: Optional[str] = None,
    ):
        """Initialize the Threat Hunter.
        
        Args:
            ioc_feeds: List of URLs to load IoC feeds from
            scan_interval: Interval in seconds between automatic scans
            state_dir: Directory for storing state and cache
        """
        self.ioc_feeds = ioc_feeds or []
        self.scan_interval = scan_interval
        self.state_dir = Path(state_dir or str(state_dir())) / "threat_hunter"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # IoC storage
        self.iocs: Dict[str, IoC] = {}  # ioc_type:value -> IoC
        self._load_builtin_iocs()
        
        # Scan history
        self.scan_history: List[ScanResult] = []
        
        # Platform detection
        self.platform = platform.system().lower()
        
        # Load external IoC feeds
        self._load_ioc_feeds()
        
        logging.info(
            f"ThreatHunter initialized (platform={self.platform}, "
            f"ioc_feeds={len(self.ioc_feeds)}, "
            f"scan_interval={self.scan_interval})"
        )

    def _load_builtin_iocs(self) -> None:
        """Load built-in IoCs."""
        # Load malware hashes
        for hash_type, hashes in self.KNOWN_MALWARE_HASHES.items():
            for hash_val, description in hashes.items():
                self._add_ioc(
                    ioc_type=hash_type,
                    value=hash_val,
                    description=description,
                    confidence=0.9,
                    source="builtin",
                )
        
        # Load malicious IPs
        for ip, description in self.KNOWN_MALICIOUS_IPS.items():
            self._add_ioc(
                ioc_type="ip",
                value=ip,
                description=description,
                confidence=0.9,
                source="builtin",
            )
        
        # Load malicious domains
        for domain, description in self.KNOWN_MALICIOUS_DOMAINS.items():
            self._add_ioc(
                ioc_type="domain",
                value=domain,
                description=description,
                confidence=0.9,
                source="builtin",
            )

    def _load_ioc_feeds(self) -> None:
        """Load IoCs from external feeds."""
        for feed_url in self.ioc_feeds:
            try:
                self._load_ioc_feed(feed_url)
            except Exception as e:
                logging.error(f"Failed to load IoC feed {feed_url}: {e}")

    def _load_ioc_feed(self, url: str) -> None:
        """Load IoCs from a single feed URL."""
        # In a real implementation, this would fetch from the URL
        # For now, we'll just log that we would load it
        logging.info(f"Would load IoC feed from {url}")

    def _add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str,
        confidence: float,
        source: str,
    ) -> None:
        """Add an IoC to the collection."""
        key = f"{ioc_type}:{value}"
        
        if key in self.iocs:
            # Update existing IoC
            existing = self.iocs[key]
            existing.last_seen = datetime.now().isoformat()
            existing.confidence = max(existing.confidence, confidence)
        else:
            # Add new IoC
            self.iocs[key] = IoC(
                ioc_type=ioc_type,
                value=value,
                description=description,
                confidence=confidence,
                source=source,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
            )

    def scan_processes(self) -> ScanResult:
        """Scan running processes for malicious indicators.
        
        Returns:
            ScanResult with findings
        """
        start_time = datetime.now()
        findings = []
        total_scanned = 0
        
        try:
            if self.platform == "linux":
                processes = self._get_linux_processes()
            elif self.platform == "windows":
                processes = self._get_windows_processes()
            elif self.platform == "darwin":
                processes = self._get_macos_processes()
            else:
                processes = []
            
            for proc in processes:
                total_scanned += 1
                
                # Check process name
                proc_name = proc.get("name", "").lower()
                for suspicious_name, description in self.SUSPICIOUS_PROCESS_NAMES.items():
                    if suspicious_name in proc_name:
                        findings.append({
                            "type": "suspicious_process",
                            "process_name": proc.get("name"),
                            "pid": proc.get("pid"),
                            "description": description,
                            "confidence": 0.8,
                            "timestamp": datetime.now().isoformat(),
                        })
                        break
                
                # Check command line
                cmdline = proc.get("cmdline", "").lower()
                for ip, description in self.KNOWN_MALICIOUS_IPS.items():
                    if ip in cmdline:
                        findings.append({
                            "type": "malicious_ip_in_process",
                            "process_name": proc.get("name"),
                            "pid": proc.get("pid"),
                            "ip": ip,
                            "description": f"Process connecting to known malicious IP: {description}",
                            "confidence": 0.9,
                            "timestamp": datetime.now().isoformat(),
                        })
                        break
            
        except Exception as e:
            logging.error(f"Error scanning processes: {e}")
        
        end_time = datetime.now().isoformat()
        result = ScanResult(
            scan_type="processes",
            start_time=start_time.isoformat(),
            end_time=end_time,
            findings=findings,
            total_items_scanned=total_scanned,
            total_findings=len(findings),
        )
        
        self.scan_history.append(result)
        
        return result

    def _get_linux_processes(self) -> List[Dict[str, Any]]:
        """Get running processes on Linux."""
        processes = []
        
        try:
            # Use ps command
            result = subprocess.run(
                ["ps", "-eo", "pid,comm,cmd"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    processes.append({
                        "pid": parts[0],
                        "name": parts[1],
                        "cmdline": parts[2],
                    })
        except Exception as e:
            logging.error(f"Error getting Linux processes: {e}")
        
        return processes

    def _get_windows_processes(self) -> List[Dict[str, Any]]:
        """Get running processes on Windows."""
        processes = []
        
        try:
            result = subprocess.run(
                ["wmic", "process", "get", "ProcessId,Name,CommandLine", "/format:csv"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                # Parse CSV line
                parts = line.strip().split(",")
                if len(parts) >= 3:
                    processes.append({
                        "pid": parts[0].strip('"'),
                        "name": parts[1].strip('"'),
                        "cmdline": parts[2].strip('"'),
                    })
        except Exception as e:
            logging.error(f"Error getting Windows processes: {e}")
        
        return processes

    def _get_macos_processes(self) -> List[Dict[str, Any]]:
        """Get running processes on macOS."""
        processes = []
        
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,comm,args"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    processes.append({
                        "pid": parts[0],
                        "name": parts[1],
                        "cmdline": parts[2],
                    })
        except Exception as e:
            logging.error(f"Error getting macOS processes: {e}")
        
        return processes

    def scan_network_connections(self) -> ScanResult:
        """Scan active network connections for suspicious activity.
        
        Returns:
            ScanResult with findings
        """
        start_time = datetime.now()
        findings = []
        total_scanned = 0
        
        try:
            if self.platform == "linux":
                connections = self._get_linux_connections()
            elif self.platform == "windows":
                connections = self._get_windows_connections()
            elif self.platform == "darwin":
                connections = self._get_macos_connections()
            else:
                connections = []
            
            for conn in connections:
                total_scanned += 1
                
                # Check for connections to known malicious IPs
                remote_ip = conn.get("remote_ip", "")
                if remote_ip in self.KNOWN_MALICIOUS_IPS:
                    findings.append({
                        "type": "malicious_connection",
                        "local_ip": conn.get("local_ip"),
                        "local_port": conn.get("local_port"),
                        "remote_ip": remote_ip,
                        "remote_port": conn.get("remote_port"),
                        "protocol": conn.get("protocol"),
                        "process": conn.get("process"),
                        "description": f"Connection to known malicious IP: {self.KNOWN_MALICIOUS_IPS[remote_ip]}",
                        "confidence": 0.95,
                        "timestamp": datetime.now().isoformat(),
                    })
                
                # Check for connections to suspicious ports
                remote_port = conn.get("remote_port", 0)
                if remote_port in self.SUSPICIOUS_PORTS:
                    findings.append({
                        "type": "suspicious_port_connection",
                        "local_ip": conn.get("local_ip"),
                        "local_port": conn.get("local_port"),
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "protocol": conn.get("protocol"),
                        "process": conn.get("process"),
                        "description": f"Connection to suspicious port: {self.SUSPICIOUS_PORTS[remote_port]}",
                        "confidence": 0.8,
                        "timestamp": datetime.now().isoformat(),
                    })
            
        except Exception as e:
            logging.error(f"Error scanning network connections: {e}")
        
        end_time = datetime.now().isoformat()
        result = ScanResult(
            scan_type="network_connections",
            start_time=start_time.isoformat(),
            end_time=end_time,
            findings=findings,
            total_items_scanned=total_scanned,
            total_findings=len(findings),
        )
        
        self.scan_history.append(result)
        
        return result

    def _get_linux_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections on Linux."""
        connections = []
        
        try:
            # Use netstat or ss
            try:
                result = subprocess.run(
                    ["ss", "-tulnp"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except FileNotFoundError:
                result = subprocess.run(
                    ["netstat", "-tulnp"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                # Parse ss/netstat output
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]
                    remote_addr = parts[5] if len(parts) > 5 else ""
                    
                    # Parse local address
                    local_parts = local_addr.split(":")
                    local_ip = local_parts[0]
                    local_port = local_parts[1] if len(local_parts) > 1 else "0"
                    
                    # Parse remote address
                    remote_parts = remote_addr.split(":")
                    remote_ip = remote_parts[0]
                    remote_port = remote_parts[1] if len(remote_parts) > 1 else "0"
                    
                    connections.append({
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "protocol": parts[0],
                        "state": parts[1],
                        "process": parts[6] if len(parts) > 6 else "",
                    })
        except Exception as e:
            logging.error(f"Error getting Linux connections: {e}")
        
        return connections

    def _get_windows_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections on Windows."""
        connections = []
        
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            lines = result.stdout.strip().split("\n")[3:]  # Skip headers
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    
                    # Parse addresses
                    local_parts = local_addr.split(":")
                    local_ip = local_parts[0]
                    local_port = local_parts[1] if len(local_parts) > 1 else "0"
                    
                    remote_parts = remote_addr.split(":")
                    remote_ip = remote_parts[0]
                    remote_port = remote_parts[1] if len(remote_parts) > 1 else "0"
                    
                    connections.append({
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "protocol": parts[0],
                        "state": parts[3],
                        "pid": parts[4],
                        "process": "",
                    })
        except Exception as e:
            logging.error(f"Error getting Windows connections: {e}")
        
        return connections

    def _get_macos_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections on macOS."""
        connections = []
        
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                check=True,
            )
            
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    connections.append({
                        "local_ip": parts[8].split(":")[0],
                        "local_port": parts[8].split(":")[1] if ":" in parts[8] else "0",
                        "remote_ip": parts[9].split(":")[0] if len(parts) > 9 else "",
                        "remote_port": parts[9].split(":")[1] if len(parts) > 9 and ":" in parts[9] else "0",
                        "protocol": parts[7],
                        "state": "",
                        "process": parts[0],
                    })
        except Exception as e:
            logging.error(f"Error getting macOS connections: {e}")
        
        return connections

    def scan_filesystem(self, paths: List[str]) -> ScanResult:
        """Scan files for known malware hashes.
        
        Args:
            paths: List of paths to scan
            
        Returns:
            ScanResult with findings
        """
        start_time = datetime.now()
        findings = []
        total_scanned = 0
        
        for path in paths:
            try:
                path_obj = Path(path)
                if path_obj.is_dir():
                    # Scan directory recursively
                    for file_path in path_obj.rglob("*"):
                        if file_path.is_file():
                            total_scanned += 1
                            self._scan_file(file_path, findings)
                elif path_obj.is_file():
                    total_scanned += 1
                    self._scan_file(path_obj, findings)
            except Exception as e:
                logging.error(f"Error scanning path {path}: {e}")
        
        end_time = datetime.now().isoformat()
        result = ScanResult(
            scan_type="filesystem",
            start_time=start_time.isoformat(),
            end_time=end_time,
            findings=findings,
            total_items_scanned=total_scanned,
            total_findings=len(findings),
        )
        
        self.scan_history.append(result)
        
        return result

    def _scan_file(self, file_path: Path, findings: List[Dict[str, Any]]) -> None:
        """Scan a single file for malicious indicators."""
        try:
            # Calculate file hashes
            md5 = self._calculate_md5(file_path)
            sha1 = self._calculate_sha1(file_path)
            sha256 = self._calculate_sha256(file_path)
            
            # Check against known malware hashes
            if md5 in self.KNOWN_MALWARE_HASHES.get("md5", {}):
                findings.append({
                    "type": "malware_hash_match",
                    "file_path": str(file_path),
                    "hash_type": "md5",
                    "hash_value": md5,
                    "description": self.KNOWN_MALWARE_HASHES["md5"][md5],
                    "confidence": 1.0,
                    "timestamp": datetime.now().isoformat(),
                })
            
            if sha1 in self.KNOWN_MALWARE_HASHES.get("sha1", {}):
                findings.append({
                    "type": "malware_hash_match",
                    "file_path": str(file_path),
                    "hash_type": "sha1",
                    "hash_value": sha1,
                    "description": self.KNOWN_MALWARE_HASHES["sha1"][sha1],
                    "confidence": 1.0,
                    "timestamp": datetime.now().isoformat(),
                })
            
            if sha256 in self.KNOWN_MALWARE_HASHES.get("sha256", {}):
                findings.append({
                    "type": "malware_hash_match",
                    "file_path": str(file_path),
                    "hash_type": "sha256",
                    "hash_value": sha256,
                    "description": self.KNOWN_MALWARE_HASHES["sha256"][sha256],
                    "confidence": 1.0,
                    "timestamp": datetime.now().isoformat(),
                })
            
            # Check filename against suspicious patterns
            filename = file_path.name.lower()
            for pattern, description in self.SUSPICIOUS_PROCESS_NAMES.items():
                if pattern in filename:
                    findings.append({
                        "type": "suspicious_filename",
                        "file_path": str(file_path),
                        "filename": filename,
                        "pattern": pattern,
                        "description": f"File with suspicious name: {description}",
                        "confidence": 0.7,
                        "timestamp": datetime.now().isoformat(),
                    })
                    break
            
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")

    def _calculate_md5(self, file_path: Path) -> str:
        """Calculate MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _calculate_sha1(self, file_path: Path) -> str:
        """Calculate SHA1 hash of a file."""
        hash_sha1 = hashlib.sha1()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def check_ioc(self, ioc_type: str, value: str) -> Tuple[bool, Optional[IoC]]:
        """Check if a value matches any known IoC.
        
        Args:
            ioc_type: Type of IoC to check
            value: Value to check
            
        Returns:
            Tuple of (is_match, ioc) where ioc is the matching IoC or None
        """
        key = f"{ioc_type}:{value}"
        if key in self.iocs:
            return True, self.iocs[key]
        return False, None

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str,
        confidence: float,
        source: str,
    ) -> None:
        """Add a new IoC to the collection.
        
        Args:
            ioc_type: Type of IoC
            value: IoC value
            description: Description of the IoC
            confidence: Confidence level (0.0 to 1.0)
            source: Source of the IoC
        """
        self._add_ioc(ioc_type, value, description, confidence, source)

    def get_iocs(self) -> List[Dict[str, Any]]:
        """Get all IoCs.
        
        Returns:
            List of all IoCs as dictionaries
        """
        return [ioc.to_dict() for ioc in self.iocs.values()]

    def get_scan_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent scan history.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan results
        """
        return [scan.to_dict() for scan in self.scan_history[-limit:]]

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about threat hunting.
        
        Returns:
            Dictionary with hunting statistics
        """
        return {
            "total_iocs": len(self.iocs),
            "total_scans": len(self.scan_history),
            "total_findings": sum(s.total_findings for s in self.scan_history),
            "platform": self.platform,
            "ioc_feeds": len(self.ioc_feeds),
            "scan_interval": self.scan_interval,
        }

    def run_continuous_hunting(self, stop_event: threading.Event) -> None:
        """Run continuous threat hunting until stopped.
        
        Args:
            stop_event: Event to signal when to stop
        """
        logging.info("Starting continuous threat hunting")
        
        while not stop_event.is_set():
            start_time = time.time()
            
            # Run all scans
            self.scan_processes()
            self.scan_network_connections()
            
            # Scan common directories
            common_paths = ["/tmp", "/var/tmp", "/home", "/opt"]
            if self.platform == "windows":
                common_paths = ["C:\\Windows\\Temp", "C:\\Users"]
            elif self.platform == "darwin":
                common_paths = ["/tmp", "/var/tmp", "/Users"]
            
            for path in common_paths:
                if Path(path).exists():
                    self.scan_filesystem([path])
            
            # Sleep for remaining interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.scan_interval - elapsed)
            stop_event.wait(sleep_time)
        
        logging.info("Stopped continuous threat hunting")

    def reset(self) -> None:
        """Reset all threat hunting state (for testing)."""
        self.iocs.clear()
        self._load_builtin_iocs()
        self.scan_history.clear()
        logging.info("ThreatHunter reset")
