"""Core schema. Everything in the system normalizes to these types.

Keep this stable — changing it ripples through every layer. Uses pydantic v2.
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Event(BaseModel):
    """A single normalized observation from any collector or sensor."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    source: str  # collector name, e.g. "suricata.eve", "cowrie", "auth.log"
    kind: str  # e.g. "flow", "auth_fail", "honeypot_login", "dns"
    src_ip: str | None = None
    dst_ip: str | None = None
    host: str | None = None
    # raw normalized fields; collectors decide the contents per kind
    fields: dict[str, object] = Field(default_factory=dict)

    @field_validator("source", "kind")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty identifier")
        return v

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _blank_ip_to_none(cls, v: str | None) -> str | None:
        # Collectors frequently hand us "" for a missing address; normalize it.
        if v is None:
            return None
        v = v.strip()
        return v or None

    def is_deception(self) -> bool:
        """Honeypot-origin events are near-zero-FP; correlation weights them heavily."""
        return self.source in {"cowrie", "opencanary", "canarytoken"}


class Alert(BaseModel):
    """A detection fired against one or more Events."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    title: str
    severity: Severity = Severity.LOW
    detector: str  # e.g. "rules.sigma", "anomaly.isoforest"
    attack_technique: str | None = None  # MITRE ATT&CK id, e.g. "T1110"
    event_ids: list[str] = Field(default_factory=list)
    detail: dict[str, object] = Field(default_factory=dict)


class Incident(BaseModel):
    """Correlated group of alerts about the same activity."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    title: str
    severity: Severity = Severity.LOW
    alert_ids: list[str] = Field(default_factory=list)
    status: str = "open"  # open | contained | closed


class Action(BaseModel):
    """A response step. Destructive actions require approval unless auto+reversible."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    playbook: str
    name: str  # e.g. "block_ip", "notify", "isolate_host"
    destructive: bool = False
    auto: bool = False
    reversible: bool = True
    undo: dict[str, object] | None = None  # how to reverse, recorded at execution
    approved: bool = False
    approver: str | None = None
    detail: dict[str, object] = Field(default_factory=dict)

    def requires_gate(self) -> bool:
        """A destructive action runs only when explicitly auto+reversible, else it gates."""
        if not self.destructive:
            return False
        return not (self.auto and self.reversible)
