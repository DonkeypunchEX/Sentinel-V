"""Forensic Capture Module - Attacker payload and session logging.

Provides capabilities to:
- Capture and store attacker payloads
- Log attacker sessions (SSH, HTTP, etc.)
- Extract Indicators of Compromise (IoCs) from captured data
- Generate forensic reports

All captured data is stored in a dedicated forensics directory
and can be used for analysis and threat intelligence.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .paths import forensics_dir

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def _safe_path_component(value: str) -> str:
    """Strip anything but [A-Za-z0-9._-] from an identifier used in a path.

    threat_id/session_id reach dump_payload/start_session/generate_report
    as public-API arguments with no guarantee of origin; today's only
    caller derives them from a hash, but nothing stops a future caller
    (an API handler, a CLI wrapper) from passing an attacker-influenced
    value. Without this, a value like "../../etc/cron.d/x" would let a
    caller write outside payloads_dir/sessions_dir/reports_dir via
    pathlib's `/` operator, which honors embedded path separators.
    """
    cleaned = _UNSAFE_PATH_CHARS.sub("_", value)
    return cleaned or "unknown"


# Common patterns for extracting IoCs
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(
    r"\b(?:https?://|ftp://|www\.)[^\s/$.?#].[^\s]*\b", re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


@dataclass
class CapturedPayload:
    """Represents a captured attacker payload."""

    threat_id: str
    file_path: str
    file_hash: str  # SHA256
    file_size: int
    file_type: str
    timestamp: str
    source_ip: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
        }


@dataclass
class SessionLog:
    """Represents a logged attacker session."""

    session_id: str
    threat_id: str
    source_ip: str
    start_time: str
    end_time: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "threat_id": self.threat_id,
            "source_ip": self.source_ip,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "commands": self.commands,
            "metadata": self.metadata,
        }


@dataclass
class ExtractedIOC:
    """Represents an extracted Indicator of Compromise."""

    ioc_type: str  # ip, domain, url, email, hash, etc.
    value: str
    source: str  # file path or session ID
    confidence: float  # 0.0 to 1.0
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class ForensicCapture:
    """Captures and analyzes attacker payloads and sessions.

    Provides methods to:
    - Store attacker payloads with metadata
    - Log attacker sessions (commands, interactions)
    - Extract IoCs from captured data
    - Generate forensic reports
    """

    def __init__(
        self,
        capture_dir: Optional[str] = None,
        max_payload_size: int = 100 * 1024 * 1024,  # 100MB default
        extract_iocs: bool = True,
    ):
        """Initialize the Forensic Capture module.

        Args:
            capture_dir: Directory to store captured data
            max_payload_size: Maximum size for payload capture (bytes)
            extract_iocs: Whether to automatically extract IoCs
        """
        self.capture_dir = Path(capture_dir or str(forensics_dir()))
        self.capture_dir.mkdir(parents=True, exist_ok=True)

        self.max_payload_size = max_payload_size
        self.extract_iocs = extract_iocs

        # Track captured items
        self.captured_payloads: List[CapturedPayload] = []
        self.session_logs: List[SessionLog] = []
        self.extracted_iocs: List[ExtractedIOC] = []

        # Create subdirectories
        self.payloads_dir = self.capture_dir / "payloads"
        self.sessions_dir = self.capture_dir / "sessions"
        self.reports_dir = self.capture_dir / "reports"

        self.payloads_dir.mkdir(exist_ok=True)
        self.sessions_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        logging.info(
            f"ForensicCapture initialized (capture_dir={self.capture_dir}, "
            f"max_payload_size={self.max_payload_size})"
        )

    def _generate_file_path(self, threat_id: str, extension: str = "") -> Path:
        """Generate a unique file path for captured data."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{_safe_path_component(threat_id)}_{timestamp}{extension}"
        return self.payloads_dir / filename

    def _generate_session_path(self, session_id: str) -> Path:
        """Generate a file path for session logs."""
        return self.sessions_dir / f"{_safe_path_component(session_id)}.json"

    def _calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA256 hash of data."""
        return hashlib.sha256(data).hexdigest()

    def _detect_file_type(self, data: bytes, filename: str = "") -> str:
        """Detect file type based on magic bytes or extension."""
        # Check for common magic bytes
        if len(data) >= 4:
            # ZIP
            if data[:4] == b"PK\x03\x04":
                return "zip"
            # ELF
            if data[:4] == b"\x7fELF":
                return "elf"
            # PE (Windows executable)
            if data[:2] == b"MZ":
                return "pe"
            # PDF
            if data[:4] == b"%PDF":
                return "pdf"
            # JPEG
            if data[:2] == b"\xff\xd8":
                return "jpeg"
            # PNG
            if data[:8] == b"\x89PNG\r\n\x1a\n":
                return "png"
            # GIF
            if data[:6] in (b"GIF87a", b"GIF89a"):
                return "gif"

        # Check extension
        if filename:
            ext = Path(filename).suffix.lower().lstrip(".")
            if ext:
                return ext

        return "unknown"

    def dump_payload(
        self,
        threat_id: str,
        payload: bytes,
        source_ip: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[CapturedPayload]:
        """Capture and store an attacker payload.

        Args:
            threat_id: Unique identifier for the threat
            payload: Binary payload data
            source_ip: Source IP address of the attacker
            metadata: Additional metadata about the payload

        Returns:
            CapturedPayload object if successful, None otherwise
        """
        if not payload:
            logging.warning(f"Empty payload received for threat {threat_id}")
            return None

        # Check size limit
        if len(payload) > self.max_payload_size:
            logging.warning(
                f"Payload for threat {threat_id} exceeds size limit "
                f"({len(payload)} > {self.max_payload_size}), truncating"
            )
            payload = payload[: self.max_payload_size]

        # Generate file path
        file_hash = self._calculate_sha256(payload)
        file_ext = ".bin"
        file_type = self._detect_file_type(payload)

        if file_type != "unknown":
            file_ext = f".{file_type}"

        file_path = self._generate_file_path(threat_id, file_ext)

        # Save payload to disk
        try:
            file_path.write_bytes(payload)
            logging.info(f"Saved payload to {file_path}")
        except Exception as e:
            logging.error(f"Failed to save payload: {e}")
            return None

        # Create captured payload record
        captured = CapturedPayload(
            threat_id=threat_id,
            file_path=str(file_path),
            file_hash=file_hash,
            file_size=len(payload),
            file_type=file_type,
            timestamp=datetime.now().isoformat(),
            source_ip=source_ip,
            metadata=metadata or {},
        )

        self.captured_payloads.append(captured)

        # Extract IoCs if enabled
        if self.extract_iocs:
            self._extract_iocs_from_payload(captured)

        logging.info(
            f"Captured payload: threat_id={threat_id}, "
            f"source_ip={source_ip}, size={len(payload)}, "
            f"hash={file_hash[:16]}..., type={file_type}"
        )

        return captured

    def _extract_iocs_from_payload(self, payload: CapturedPayload) -> None:
        """Extract IoCs from a captured payload."""
        try:
            # Try to extract text from the payload
            try:
                text = Path(payload.file_path).read_text(
                    encoding="utf-8", errors="ignore"
                )
            except Exception:
                text = ""

            # Extract IPs
            for match in IP_PATTERN.finditer(text):
                ip = match.group()
                self._add_ioc(
                    ioc_type="ip",
                    value=ip,
                    source=payload.file_path,
                    confidence=0.9,
                )

            # Extract IPv6
            for match in IPV6_PATTERN.finditer(text):
                ip = match.group()
                self._add_ioc(
                    ioc_type="ipv6",
                    value=ip,
                    source=payload.file_path,
                    confidence=0.9,
                )

            # Extract domains
            for match in DOMAIN_PATTERN.finditer(text):
                domain = match.group()
                self._add_ioc(
                    ioc_type="domain",
                    value=domain,
                    source=payload.file_path,
                    confidence=0.8,
                )

            # Extract URLs
            for match in URL_PATTERN.finditer(text):
                url = match.group()
                self._add_ioc(
                    ioc_type="url",
                    value=url,
                    source=payload.file_path,
                    confidence=0.9,
                )

            # Extract hashes
            for match in MD5_PATTERN.finditer(text):
                hash_val = match.group()
                self._add_ioc(
                    ioc_type="md5",
                    value=hash_val,
                    source=payload.file_path,
                    confidence=0.7,
                )

            for match in SHA1_PATTERN.finditer(text):
                hash_val = match.group()
                self._add_ioc(
                    ioc_type="sha1",
                    value=hash_val,
                    source=payload.file_path,
                    confidence=0.7,
                )

            for match in SHA256_PATTERN.finditer(text):
                hash_val = match.group()
                self._add_ioc(
                    ioc_type="sha256",
                    value=hash_val,
                    source=payload.file_path,
                    confidence=0.7,
                )

        except Exception as e:
            logging.error(
                f"Error extracting IoCs from payload {payload.file_path}: {e}"
            )

    def _add_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float,
    ) -> None:
        """Add an extracted IoC to the collection."""
        # Check if this IoC already exists
        for ioc in self.extracted_iocs:
            if ioc.ioc_type == ioc_type and ioc.value == value:
                return

        ioc = ExtractedIOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            timestamp=datetime.now().isoformat(),
        )
        self.extracted_iocs.append(ioc)
        logging.debug(f"Extracted IoC: {ioc_type}={value} (confidence={confidence})")

    def start_session(
        self,
        threat_id: str,
        source_ip: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Start a new session log for an attacker.

        Args:
            threat_id: Unique identifier for the threat
            source_ip: Source IP address of the attacker
            metadata: Additional metadata about the session

        Returns:
            Session ID for the new session
        """
        session_id = f"{threat_id}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

        session = SessionLog(
            session_id=session_id,
            threat_id=threat_id,
            source_ip=source_ip,
            start_time=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.session_logs.append(session)

        logging.info(f"Started session: {session_id} for threat {threat_id}")

        return session_id

    def log_command(
        self,
        session_id: str,
        command: str,
    ) -> bool:
        """Log a command executed by an attacker.

        Args:
            session_id: ID of the session to log to
            command: Command string to log

        Returns:
            True if command was logged, False if session not found
        """
        for session in self.session_logs:
            if session.session_id == session_id:
                session.commands.append(command)
                session.end_time = datetime.now().isoformat()

                # Extract IoCs from command
                if self.extract_iocs:
                    self._extract_iocs_from_command(session_id, command)

                return True

        logging.warning(f"Session {session_id} not found for command logging")
        return False

    def _extract_iocs_from_command(self, session_id: str, command: str) -> None:
        """Extract IoCs from a command string."""
        try:
            # Extract IPs
            for match in IP_PATTERN.finditer(command):
                ip = match.group()
                self._add_ioc(
                    ioc_type="ip",
                    value=ip,
                    source=session_id,
                    confidence=0.95,
                )

            # Extract domains
            for match in DOMAIN_PATTERN.finditer(command):
                domain = match.group()
                self._add_ioc(
                    ioc_type="domain",
                    value=domain,
                    source=session_id,
                    confidence=0.9,
                )

            # Extract URLs
            for match in URL_PATTERN.finditer(command):
                url = match.group()
                self._add_ioc(
                    ioc_type="url",
                    value=url,
                    source=session_id,
                    confidence=0.95,
                )

        except Exception as e:
            logging.error(f"Error extracting IoCs from command: {e}")

    def end_session(self, session_id: str) -> bool:
        """End a session and save it to disk.

        Args:
            session_id: ID of the session to end

        Returns:
            True if session was ended and saved, False otherwise
        """
        for i, session in enumerate(self.session_logs):
            if session.session_id == session_id:
                if not session.end_time:
                    session.end_time = datetime.now().isoformat()

                # Save to disk
                session_path = self._generate_session_path(session_id)
                try:
                    session_path.write_text(json.dumps(session.to_dict(), indent=2))
                    logging.info(f"Saved session to {session_path}")
                except Exception as e:
                    logging.error(f"Failed to save session {session_id}: {e}")

                # Remove from memory (keep only recent sessions)
                self.session_logs.pop(i)

                return True

        return False

    def save_payload_metadata(self, payload: CapturedPayload) -> bool:
        """Save payload metadata to disk.

        Args:
            payload: Payload to save metadata for

        Returns:
            True if metadata was saved, False otherwise
        """
        metadata_path = Path(payload.file_path).with_suffix(".json")
        try:
            metadata_path.write_text(json.dumps(payload.to_dict(), indent=2))
            return True
        except Exception as e:
            logging.error(f"Failed to save payload metadata: {e}")
            return False

    def get_iocs_by_type(self, ioc_type: str) -> List[Dict[str, Any]]:
        """Get all IoCs of a specific type.

        Args:
            ioc_type: Type of IoC to filter by (ip, domain, url, etc.)

        Returns:
            List of IoC dictionaries
        """
        return [
            ioc.to_dict() for ioc in self.extracted_iocs if ioc.ioc_type == ioc_type
        ]

    def get_iocs_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Get all IoCs extracted from a specific source.

        Args:
            source: Source file or session ID

        Returns:
            List of IoC dictionaries
        """
        return [ioc.to_dict() for ioc in self.extracted_iocs if ioc.source == source]

    def get_unique_iocs(self) -> Dict[str, List[str]]:
        """Get all unique IoCs grouped by type.

        Returns:
            Dictionary mapping IoC types to lists of unique values
        """
        unique_iocs: Dict[str, Set[str]] = {}

        for ioc in self.extracted_iocs:
            if ioc.ioc_type not in unique_iocs:
                unique_iocs[ioc.ioc_type] = set()
            unique_iocs[ioc.ioc_type].add(ioc.value)

        return {k: sorted(list(v)) for k, v in unique_iocs.items()}

    def generate_report(
        self,
        threat_id: str,
        include_payloads: bool = True,
        include_sessions: bool = True,
        include_iocs: bool = True,
    ) -> Optional[Path]:
        """Generate a forensic report for a threat.

        Args:
            threat_id: Threat ID to generate report for
            include_payloads: Include payload information
            include_sessions: Include session information
            include_iocs: Include extracted IoCs

        Returns:
            Path to the generated report file, or None if failed
        """
        report_data: Dict[str, Any] = {
            "threat_id": threat_id,
            "generated_at": datetime.now().isoformat(),
            "report_version": "1.0",
        }

        # Add payloads
        if include_payloads:
            report_data["payloads"] = [
                p.to_dict() for p in self.captured_payloads if p.threat_id == threat_id
            ]

        # Add sessions
        if include_sessions:
            report_data["sessions"] = [
                s.to_dict() for s in self.session_logs if s.threat_id == threat_id
            ]

        # Add IoCs
        if include_iocs:
            report_data["iocs"] = [
                i.to_dict()
                for i in self.extracted_iocs
                if i.source.startswith(threat_id)
            ]

        # Generate report file path
        safe_threat_id = _safe_path_component(threat_id)
        report_path = (
            self.reports_dir
            / f"{safe_threat_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        try:
            report_path.write_text(json.dumps(report_data, indent=2))
            logging.info(f"Generated forensic report: {report_path}")
            return report_path
        except Exception as e:
            logging.error(f"Failed to generate forensic report: {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about forensic captures.

        Returns:
            Dictionary with capture statistics
        """
        return {
            "total_payloads": len(self.captured_payloads),
            "total_sessions": len(self.session_logs),
            "total_iocs": len(self.extracted_iocs),
            "unique_ioc_types": len({ioc.ioc_type for ioc in self.extracted_iocs}),
            "capture_dir": str(self.capture_dir),
            "max_payload_size": self.max_payload_size,
            "extract_iocs": self.extract_iocs,
        }

    def cleanup_old_data(self, max_age_days: int = 30) -> int:
        """Clean up old forensic data.

        Args:
            max_age_days: Maximum age in days for captured data

        Returns:
            Number of files deleted
        """
        import time

        cutoff = time.time() - (max_age_days * 24 * 60 * 60)
        deleted_count = 0

        # Clean up payload files
        for payload_file in self.payloads_dir.glob("*"):
            if payload_file.stat().st_mtime < cutoff:
                try:
                    payload_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    logging.error(f"Failed to delete {payload_file}: {e}")

        # Clean up session files
        for session_file in self.sessions_dir.glob("*.json"):
            if session_file.stat().st_mtime < cutoff:
                try:
                    session_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    logging.error(f"Failed to delete {session_file}: {e}")

        # Clean up report files
        for report_file in self.reports_dir.glob("*.json"):
            if report_file.stat().st_mtime < cutoff:
                try:
                    report_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    logging.error(f"Failed to delete {report_file}: {e}")

        logging.info(f"Cleaned up {deleted_count} old forensic files")
        return deleted_count

    def reset(self) -> None:
        """Reset all forensic capture state (for testing)."""
        self.captured_payloads.clear()
        self.session_logs.clear()
        self.extracted_iocs.clear()
        logging.info("ForensicCapture reset")
