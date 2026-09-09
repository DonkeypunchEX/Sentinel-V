"""Threat-intel enrichment — pluggable, cached, provenance-graded.

Phase 3. NIST CSF: Identify/Detect (context for triage). Enrichers take an
indicator (IP/domain/hash/email) and return provider context. Every result is
graded with a **provenance tier + confidence** (the model borrowed from the
OSINT provenance rubric) so an analyst sees *how much to trust* a tag, not just
the tag. Results are cached — intel APIs rate-limit.

This module is the framework side (ABC + service + result model); concrete
providers (OTX, GreyNoise, HIBP) live in ``providers.py`` and are only
constructed when configured, so with no keys the enrichment step is inert (it
never fabricates intel).
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from sentinel_v.models import Incident, _utcnow

if TYPE_CHECKING:
    from sentinel_v.storage import Store

log = logging.getLogger(__name__)


class Tier(IntEnum):
    """Provenance tiers (lower = stronger), mirrored from the OSINT rubric."""

    AUTHORITATIVE = 1  # authoritative dataset (e.g. HIBP breach presence)
    VERIFIED_AGGREGATOR = 2  # verified aggregator (e.g. GreyNoise)
    COMMUNITY = 3  # community-contributed intel (e.g. OTX pulses)
    UNVERIFIED = 5  # unverified / low-trust


class Confidence(StrEnum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class Enrichment(BaseModel):
    """One provider's graded context for an indicator."""

    provider: str
    indicator: str
    kind: str
    tier: int
    confidence: Confidence
    summary: str
    data: dict[str, object] = Field(default_factory=dict)
    ts: str = Field(default_factory=lambda: _utcnow().isoformat())


class Enricher(ABC):
    """A provider. Subclasses set name/tier and implement lookup()."""

    name: str
    tier: Tier = Tier.UNVERIFIED
    base_confidence: Confidence = Confidence.LOW

    @abstractmethod
    def lookup(self, indicator: str, kind: str = "ip") -> dict[str, object]:
        """Return raw provider context for an indicator, or {} if unknown."""
        raise NotImplementedError

    def summarize(self, data: dict[str, object]) -> str:
        """One-line human summary of the raw data. Override per provider."""
        return ", ".join(f"{k}={v}" for k, v in list(data.items())[:4])

    def confidence_for(self, data: dict[str, object]) -> Confidence:
        """Confidence in this result. Override to grade by content."""
        return self.base_confidence

    def enrich(self, indicator: str, kind: str = "ip") -> Enrichment | None:
        """Look up and wrap into a graded Enrichment, or None if no context."""
        try:
            data = self.lookup(indicator, kind)
        except Exception:  # noqa: BLE001 - a flaky provider must not break enrichment
            log.exception("enricher %s failed on %s", self.name, indicator)
            return None
        if not data:
            return None
        return Enrichment(
            provider=self.name,
            indicator=indicator,
            kind=kind,
            tier=int(self.tier),
            confidence=self.confidence_for(data),
            summary=self.summarize(data),
            data=data,
        )


class EnrichmentService:
    """Runs a set of enrichers with a small TTL cache and aggregates results."""

    def __init__(
        self,
        enrichers: list[Enricher],
        *,
        ttl_seconds: int = 3600,
        max_entries: int = 10_000,
    ) -> None:
        self.enrichers = enrichers
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        # Bounded + self-purging: the key includes the incident src_ip, which is
        # attacker-controlled on the ingest path, so an unbounded dict would grow
        # under a spoofed-source flood.
        self._cache: OrderedDict[tuple[str, str, str], tuple[float, Enrichment]] = OrderedDict()

    def _store_cached(self, key: tuple[str, str, str], now: float, result: Enrichment) -> None:
        for k in [k for k, (t, _) in self._cache.items() if now - t >= self.ttl]:
            del self._cache[k]
        self._cache[key] = (now, result)
        self._cache.move_to_end(key)
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def enrich_indicator(self, indicator: str, kind: str = "ip") -> list[Enrichment]:
        out: list[Enrichment] = []
        now = time.monotonic()
        for e in self.enrichers:
            key = (e.name, indicator, kind)
            cached = self._cache.get(key)
            if cached is not None and now - cached[0] < self.ttl:
                out.append(cached[1])
                continue
            result = e.enrich(indicator, kind)
            if result is not None:
                self._store_cached(key, now, result)
                out.append(result)
        # Strongest provenance first.
        return sorted(out, key=lambda r: (r.tier, r.confidence != Confidence.HIGH))

    def enrich_incident(
        self, incident: Incident, store: Store | None = None
    ) -> list[Enrichment]:
        """Enrich an incident's asset (src_ip) and attach results to its detail."""
        if not self.enrichers:
            return []
        src_ip = incident.detail.get("src_ip")
        if not src_ip or src_ip == "unknown":
            return []
        results = self.enrich_indicator(str(src_ip), "ip")
        if results:
            incident.detail = {
                **incident.detail,
                "enrichment": [r.model_dump() for r in results],
            }
            if store is not None:
                store.add_incident(incident)
        return results
