"""auth.log / syslog authentication collector.

Extracts failed authentication attempts (the raw material for the brute-force
playbook, ATT&CK T1110) from a syslog-format auth log and normalizes them to
``kind="auth_fail"`` Events. Successful logins are captured as ``auth_success``
so correlation can spot a brute-force that eventually lands.

NIST CSF: Detect.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from sentinel_v.collectors.base import Collector
from sentinel_v.models import Event, _utcnow

# "Jan  1 12:00:00 host sshd[1234]: <message>"
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_ACCEPT = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _syslog_ts(mon: str, day: str, time: str) -> datetime:
    """Syslog omits the year; assume the current UTC year (best-effort)."""
    try:
        hh, mm, ss = (int(x) for x in time.split(":"))
        now = _utcnow()
        return datetime(now.year, _MONTHS[mon], int(day), hh, mm, ss, tzinfo=UTC)
    except (KeyError, ValueError):
        return _utcnow()


class AuthLogCollector(Collector):
    name = "auth.log"

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @classmethod
    def parse_line(cls, line: str) -> Event | None:
        """Normalize one auth.log line, or None if it is not an auth event."""
        m = _SYSLOG.match(line.strip())
        if not m:
            return None
        msg = m.group("msg")
        ts = _syslog_ts(m.group("mon"), m.group("day"), m.group("time"))
        host = m.group("host")
        proc = m.group("proc")

        fail = _FAIL.search(msg)
        if fail:
            return cls._event(
                "auth_fail", ts, host, proc, fail.group("ip"),
                {"user": fail.group("user"), "port": int(fail.group("port")), "raw": msg},
            )
        invalid = _INVALID.search(msg)
        if invalid:
            return cls._event(
                "auth_fail", ts, host, proc, invalid.group("ip"),
                {"user": invalid.group("user"), "reason": "invalid_user", "raw": msg},
            )
        accept = _ACCEPT.search(msg)
        if accept:
            return cls._event(
                "auth_success", ts, host, proc, accept.group("ip"),
                {"user": accept.group("user"), "port": int(accept.group("port")), "raw": msg},
            )
        return None

    @staticmethod
    def _event(
        kind: str,
        ts: datetime,
        host: str,
        proc: str,
        ip: str,
        fields: dict[str, object],
    ) -> Event:
        fields = {"service": proc, **fields}
        return Event(source=AuthLogCollector.name, kind=kind, ts=ts, src_ip=ip,
                     host=host, fields=fields)

    @classmethod
    def parse_lines(cls, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            event = cls.parse_line(line)
            if event is not None:
                yield event

    def stream(self) -> Iterator[Event]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8", errors="replace") as fh:
            yield from self.parse_lines(fh)
