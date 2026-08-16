"""Persistence layer: SQLite (dev) / any SQLAlchemy URL (prod).

Phase 0. NIST CSF: Recover (the audit trail that makes incidents reconstructable).

Four tables mirror the core schema in ``models.py``: ``events``, ``alerts``,
``incidents`` and ``audit`` (executed/queued response actions). The ``Store``
converts to and from the pydantic models so the rest of the system never touches
SQLAlchemy rows. Keep this thin — it is a mapping layer, not business logic.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel_v.models import Action, Alert, Event, Incident, Severity


def _aware(ts: datetime) -> datetime:
    """SQLite drops tzinfo; treat naive timestamps read back as UTC."""
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    src_ip: Mapped[str | None] = mapped_column(String, index=True, default=None)
    dst_ip: Mapped[str | None] = mapped_column(String, default=None)
    host: Mapped[str | None] = mapped_column(String, index=True, default=None)
    fields: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_model(self) -> Event:
        return Event(
            id=self.id,
            ts=_aware(self.ts),
            source=self.source,
            kind=self.kind,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            host=self.host,
            fields=dict(self.fields or {}),
        )

    @classmethod
    def from_model(cls, e: Event) -> EventRow:
        return cls(
            id=e.id,
            ts=e.ts,
            source=e.source,
            kind=e.kind,
            src_ip=e.src_ip,
            dst_ip=e.dst_ip,
            host=e.host,
            fields=dict(e.fields),
        )


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String, index=True)
    detector: Mapped[str] = mapped_column(String, index=True)
    attack_technique: Mapped[str | None] = mapped_column(String, index=True, default=None)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_model(self) -> Alert:
        return Alert(
            id=self.id,
            ts=_aware(self.ts),
            title=self.title,
            severity=Severity(self.severity),
            detector=self.detector,
            attack_technique=self.attack_technique,
            event_ids=list(self.event_ids or []),
            detail=dict(self.detail or {}),
        )

    @classmethod
    def from_model(cls, a: Alert) -> AlertRow:
        return cls(
            id=a.id,
            ts=a.ts,
            title=a.title,
            severity=a.severity.value,
            detector=a.detector,
            attack_technique=a.attack_technique,
            event_ids=list(a.event_ids),
            detail=dict(a.detail),
        )


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, index=True, default="open")
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)

    def to_model(self) -> Incident:
        return Incident(
            id=self.id,
            ts=_aware(self.ts),
            title=self.title,
            severity=Severity(self.severity),
            status=self.status,
            alert_ids=list(self.alert_ids or []),
        )

    @classmethod
    def from_model(cls, i: Incident) -> IncidentRow:
        return cls(
            id=i.id,
            ts=i.ts,
            title=i.title,
            severity=i.severity.value,
            status=i.status,
            alert_ids=list(i.alert_ids),
        )


class AuditRow(Base):
    __tablename__ = "audit"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    playbook: Mapped[str] = mapped_column(String, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    auto: Mapped[bool] = mapped_column(Boolean, default=False)
    reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approver: Mapped[str | None] = mapped_column(String, default=None)
    undo: Mapped[dict | None] = mapped_column(JSON, default=None)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_model(self) -> Action:
        return Action(
            id=self.id,
            ts=_aware(self.ts),
            playbook=self.playbook,
            name=self.name,
            destructive=self.destructive,
            auto=self.auto,
            reversible=self.reversible,
            undo=self.undo,
            approved=self.approved,
            approver=self.approver,
            detail=dict(self.detail or {}),
        )

    @classmethod
    def from_model(cls, a: Action) -> AuditRow:
        return cls(
            id=a.id,
            ts=a.ts,
            playbook=a.playbook,
            name=a.name,
            destructive=a.destructive,
            auto=a.auto,
            reversible=a.reversible,
            undo=a.undo,
            approved=a.approved,
            approver=a.approver,
            detail=dict(a.detail),
        )


class Store:
    """Thin persistence facade over SQLAlchemy.

    Construct once (per process) with a DB URL, then add/query domain models.
    ``check_same_thread`` is disabled for SQLite so the FastAPI worker threads
    can share one in-memory/file store in dev.
    """

    def __init__(self, db_url: str = "sqlite:///sentinel.db") -> None:
        kwargs: dict[str, object] = {"future": True}
        if db_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            # An in-memory SQLite DB lives per-connection; pin one shared
            # connection so every session sees the same tables/rows.
            if ":memory:" in db_url or db_url in {"sqlite://", "sqlite:///:memory:"}:
                kwargs["poolclass"] = StaticPool
        self.engine = create_engine(db_url, **kwargs)
        self._session = sessionmaker(self.engine, expire_on_commit=False, future=True)
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return self._session()

    # ---- Events -------------------------------------------------------------
    def add_event(self, event: Event) -> Event:
        with self.session() as s:
            s.merge(EventRow.from_model(event))
            s.commit()
        return event

    def add_events(self, events: Iterable[Event]) -> int:
        n = 0
        with self.session() as s:
            for e in events:
                s.merge(EventRow.from_model(e))
                n += 1
            s.commit()
        return n

    def get_events(
        self,
        *,
        limit: int = 100,
        source: str | None = None,
        kind: str | None = None,
        src_ip: str | None = None,
    ) -> list[Event]:
        stmt = select(EventRow).order_by(EventRow.ts.desc())
        if source is not None:
            stmt = stmt.where(EventRow.source == source)
        if kind is not None:
            stmt = stmt.where(EventRow.kind == kind)
        if src_ip is not None:
            stmt = stmt.where(EventRow.src_ip == src_ip)
        stmt = stmt.limit(limit)
        with self.session() as s:
            return [row.to_model() for row in s.scalars(stmt)]

    def get_event(self, event_id: str) -> Event | None:
        with self.session() as s:
            row = s.get(EventRow, event_id)
            return row.to_model() if row else None

    # ---- Alerts -------------------------------------------------------------
    def add_alert(self, alert: Alert) -> Alert:
        with self.session() as s:
            s.merge(AlertRow.from_model(alert))
            s.commit()
        return alert

    def get_alerts(
        self, *, limit: int = 100, severity: Severity | str | None = None
    ) -> list[Alert]:
        stmt = select(AlertRow).order_by(AlertRow.ts.desc())
        if severity is not None:
            sev = severity.value if isinstance(severity, Severity) else severity
            stmt = stmt.where(AlertRow.severity == sev)
        stmt = stmt.limit(limit)
        with self.session() as s:
            return [row.to_model() for row in s.scalars(stmt)]

    # ---- Incidents ----------------------------------------------------------
    def add_incident(self, incident: Incident) -> Incident:
        with self.session() as s:
            s.merge(IncidentRow.from_model(incident))
            s.commit()
        return incident

    def get_incidents(self, *, limit: int = 100, status: str | None = None) -> list[Incident]:
        stmt = select(IncidentRow).order_by(IncidentRow.ts.desc())
        if status is not None:
            stmt = stmt.where(IncidentRow.status == status)
        stmt = stmt.limit(limit)
        with self.session() as s:
            return [row.to_model() for row in s.scalars(stmt)]

    # ---- Audit (response actions) ------------------------------------------
    def record_action(self, action: Action) -> Action:
        with self.session() as s:
            s.merge(AuditRow.from_model(action))
            s.commit()
        return action

    def get_audit(self, *, limit: int = 100) -> list[Action]:
        stmt = select(AuditRow).order_by(AuditRow.ts.desc()).limit(limit)
        with self.session() as s:
            return [row.to_model() for row in s.scalars(stmt)]

    # ---- Metrics ------------------------------------------------------------
    def counts(self) -> dict[str, int]:
        with self.session() as s:
            return {
                "events": int(s.scalar(select(func.count()).select_from(EventRow)) or 0),
                "alerts": int(s.scalar(select(func.count()).select_from(AlertRow)) or 0),
                "incidents": int(s.scalar(select(func.count()).select_from(IncidentRow)) or 0),
                "audit": int(s.scalar(select(func.count()).select_from(AuditRow)) or 0),
            }
