"""Suricata EVE JSON collector.

Suricata's EVE feed is the richest single network sensor (see docs/RND.md). Each
line is one JSON object; ``event_type`` (alert/flow/dns/http/...) becomes the
Event ``kind``. Parsing is stdlib ``json`` — no third-party dep.

NIST CSF: Detect. This is telemetry normalization only; detection happens later.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from sentinel_v.collectors.base import Collector
from sentinel_v.models import Event, _utcnow

# Fields we lift out of the flat EVE record onto the Event; everything else for a
# given event_type is preserved under Event.fields verbatim.
_TOP = {"timestamp", "event_type", "src_ip", "dest_ip", "src_port", "dest_port"}


def _parse_ts(raw: object) -> datetime:
    if isinstance(raw, str):
        try:
            # EVE emits e.g. "2024-01-01T12:00:00.000000+0000"; fromisoformat in
            # 3.11 accepts the +HHMM form.
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return _utcnow()


class SuricataEveCollector(Collector):
    name = "suricata.eve"

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @classmethod
    def parse_line(cls, line: str) -> Event | None:
        """Normalize one EVE JSON line into an Event, or None if not usable."""
        line = line.strip()
        if not line:
            return None
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(rec, dict):
            return None

        kind = str(rec.get("event_type") or "unknown")
        fields: dict[str, object] = {k: v for k, v in rec.items() if k not in _TOP}
        # Keep ports and app-layer info addressable on fields for detectors.
        for k in ("src_port", "dest_port"):
            if k in rec:
                fields[k] = rec[k]
        return Event(
            source=cls.name,
            kind=kind,
            ts=_parse_ts(rec.get("timestamp")),
            src_ip=_as_ip(rec.get("src_ip")),
            dst_ip=_as_ip(rec.get("dest_ip")),
            host=_as_str(rec.get("host")),
            fields=fields,
        )

    @classmethod
    def parse_lines(cls, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            event = cls.parse_line(line)
            if event is not None:
                yield event

    def stream(self) -> Iterator[Event]:
        """Yield Events from the current contents of the EVE log.

        Reads the file once (batch replay / test-friendly). Continuous tailing
        of a live file is a follow-up; the normalization is identical.
        """
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8", errors="replace") as fh:
            yield from self.parse_lines(fh)


def _as_ip(v: object) -> str | None:
    return str(v) if isinstance(v, str) and v else None


def _as_str(v: object) -> str | None:
    return str(v) if isinstance(v, str) and v else None
