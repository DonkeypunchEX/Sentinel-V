"""Windows Sysmon/Security event collector.

Bridges live Windows Event Log data into ``SentinelVSystem.process_event``,
so the framework can defend the host it's running on instead of only
replaying canned event files from ``analyze``. Covers Sysmon Event IDs 1
(process create), 3 (network connect), 22 (DNS query), and Security 4625
(failed logon) - the host is expected to already have Sysmon installed and
configured to log those IDs.

Windows-only: event collection shells out to Get-WinEvent via PowerShell,
which does not exist elsewhere. Importing this module works on any
platform; using ``WindowsEventCollector`` off Windows will simply fail to
find events (or the powershell executable) on every poll.
"""

import json
import logging
import re
import socket
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core import SentinelVSystem

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
SECURITY_LOG = "Security"

_COLLECT_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "collect-sysmon-events.ps1"

# Logon Type codes (Security 4625) mapped to the port most commonly
# associated with that access method, used only when the event itself
# doesn't carry a nonzero IpPort.
_LOGON_TYPE_PORTS = {
    "3": 445,  # Network (SMB/RPC)
    "5": 445,  # Service
    "8": 445,  # NetworkCleartext
    "10": 3389,  # RemoteInteractive (RDP)
}

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _local_ip() -> str:
    """Best-effort primary IPv4 of this host, for locally-sourced events.

    Doesn't actually send anything - connect() on a UDP socket just forces
    the OS to pick the outbound-facing interface so we can read it back.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _as_int(value: Optional[str]) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def shape_process_create(data: Dict[str, str]) -> Dict[str, Any]:
    """Sysmon Event ID 1: a process was created on this host."""
    return {
        "event_type": "process_create",
        "source": "sysmon",
        "source_ip": _local_ip(),
        "dest_port": 0,
        "protocol": "process",
        "process_name": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "parent_image": data.get("ParentImage", ""),
        "user": data.get("User", ""),
    }


def shape_network_connect(data: Dict[str, str]) -> Dict[str, Any]:
    """Sysmon Event ID 3: a process opened a network connection."""
    return {
        "event_type": "network_connect",
        "source": "sysmon",
        "source_ip": data.get("SourceIp", ""),
        "dest_ip": data.get("DestinationIp", ""),
        "dest_port": _as_int(data.get("DestinationPort")),
        "protocol": (data.get("Protocol") or "tcp").lower(),
        "process_name": data.get("Image", ""),
        "user": data.get("User", ""),
    }


def shape_dns_query(data: Dict[str, str]) -> Dict[str, Any]:
    """Sysmon Event ID 22: a process resolved a domain name."""
    resolved = _IPV4_RE.search(data.get("QueryResults") or "")
    return {
        "event_type": "dns_query",
        "source": "sysmon",
        "source_ip": _local_ip(),
        "dest_ip": resolved.group(0) if resolved else "",
        "dest_port": 53,
        "protocol": "dns",
        "domain": data.get("QueryName", ""),
        "process_name": data.get("Image", ""),
        "user": data.get("User", ""),
    }


def shape_failed_logon(data: Dict[str, str]) -> Dict[str, Any]:
    """Security Event ID 4625: a logon attempt failed."""
    source_ip = data.get("IpAddress") or ""
    if source_ip in ("-", ""):
        source_ip = "127.0.0.1"  # local/console logon attempts carry no IP

    logon_type = data.get("LogonType", "")
    port = _as_int(data.get("IpPort")) or _LOGON_TYPE_PORTS.get(logon_type, 0)

    return {
        "event_type": "failed_logon",
        "source": "security",
        "source_ip": source_ip,
        "dest_ip": _local_ip(),
        "dest_port": port,
        "protocol": "tcp",
        "failed_auth": True,
        "user": data.get("TargetUserName", ""),
        "logon_type": logon_type,
    }


_SHAPERS = {
    (SYSMON_LOG, 1): shape_process_create,
    (SYSMON_LOG, 3): shape_network_connect,
    (SYSMON_LOG, 22): shape_dns_query,
    (SECURITY_LOG, 4625): shape_failed_logon,
}


def shape_event(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map one raw Get-WinEvent record to the dict ``process_event`` expects.

    Returns None for a (LogName, EventId) this collector doesn't handle,
    instead of raising, so one unexpected record can't take down the
    collector loop.
    """
    shaper = _SHAPERS.get((record.get("LogName"), record.get("EventId")))
    if shaper is None:
        return None

    event = shaper(record.get("Data") or {})
    if record.get("TimeCreated"):
        event["timestamp"] = record["TimeCreated"]
    return event


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


class WindowsEventCollector:
    """Polls Sysmon/Security event logs and feeds them into a SentinelVSystem.

    Tracks the UTC timestamp of the latest event seen so each poll only
    asks PowerShell for events since the last one, rather than re-querying
    (and re-scoring) the whole log on every cycle.
    """

    def __init__(
        self,
        sentinel: SentinelVSystem,
        *,
        poll_interval: float = 10.0,
        lookback: timedelta = timedelta(minutes=5),
        powershell_path: str = "powershell",
    ) -> None:
        self.sentinel = sentinel
        self.poll_interval = poll_interval
        self.powershell_path = powershell_path
        self._since = datetime.now(timezone.utc).replace(tzinfo=None) - lookback

    def poll_once(self) -> List[Dict[str, Any]]:
        """Query events since the last poll and process each through the pipeline.

        Returns the threat assessments produced. Failures talking to
        PowerShell or the event log are logged and yield an empty list
        rather than raising, so a single bad poll doesn't kill the loop.
        """
        try:
            records = self._query(self._since)
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            logging.error("Windows event collection failed: %s", e)
            return []

        assessments = []
        latest = self._since
        for record in records:
            created = _parse_time(record.get("TimeCreated"))
            if created and created > latest:
                latest = created

            event = shape_event(record)
            if event is None:
                continue
            assessments.append(self.sentinel.process_event(event))

        self._since = latest
        return assessments

    def _query(self, since: datetime) -> List[Dict[str, Any]]:
        if not _COLLECT_SCRIPT.exists():
            raise OSError(f"collector script not found: {_COLLECT_SCRIPT}")

        result = subprocess.run(
            [
                self.powershell_path,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(_COLLECT_SCRIPT),
                "-Since",
                since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )

        records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records

    def run_forever(self, stop_event: threading.Event) -> None:
        """Poll on ``poll_interval`` until ``stop_event`` is set."""
        while not stop_event.is_set():
            self.poll_once()
            stop_event.wait(self.poll_interval)
