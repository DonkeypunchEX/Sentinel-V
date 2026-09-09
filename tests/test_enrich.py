"""Item 5: pluggable, cached, provenance-graded enrichment (offline tests).

No network here: providers are exercised via their pure parse() methods, and the
service via a fake enricher. build_enrichment defaults to inert (no keys/flags).
"""
from __future__ import annotations

from sentinel_v.config import Settings
from sentinel_v.intel.enrich import Confidence, Enricher, EnrichmentService, Tier
from sentinel_v.intel.providers import (
    GreyNoiseEnricher,
    HIBPExposureEnricher,
    OTXEnricher,
    build_enrichment,
)
from sentinel_v.models import Incident, Severity
from sentinel_v.storage import Store


class _FakeEnricher(Enricher):
    name = "fake"
    tier = Tier.VERIFIED_AGGREGATOR
    base_confidence = Confidence.MODERATE

    def __init__(self) -> None:
        self.calls = 0

    def lookup(self, indicator: str, kind: str = "ip") -> dict[str, object]:
        self.calls += 1
        return {"seen": indicator}


def test_service_wraps_and_grades():
    svc = EnrichmentService([_FakeEnricher()])
    [e] = svc.enrich_indicator("9.9.9.9")
    assert e.provider == "fake"
    assert e.tier == int(Tier.VERIFIED_AGGREGATOR)
    assert e.confidence == Confidence.MODERATE
    assert e.data == {"seen": "9.9.9.9"}


def test_service_caches():
    fake = _FakeEnricher()
    svc = EnrichmentService([fake], ttl_seconds=3600)
    svc.enrich_indicator("9.9.9.9")
    svc.enrich_indicator("9.9.9.9")
    assert fake.calls == 1  # second lookup served from cache


def test_enrich_incident_attaches_and_orders_by_tier():
    class _Tier1(_FakeEnricher):
        name = "auth"
        tier = Tier.AUTHORITATIVE

    store = Store("sqlite://")
    svc = EnrichmentService([_FakeEnricher(), _Tier1()])
    inc = Incident(title="t", severity=Severity.HIGH, detail={"src_ip": "9.9.9.9"})
    store.add_incident(inc)
    results = svc.enrich_incident(inc, store)
    assert [r.tier for r in results] == [1, 2]  # strongest provenance first
    reloaded = store.get_incident(inc.id)
    assert reloaded is not None and len(reloaded.detail["enrichment"]) == 2


def test_enrich_incident_skips_unknown_asset():
    svc = EnrichmentService([_FakeEnricher()])
    inc = Incident(title="t", severity=Severity.HIGH, detail={"src_ip": "unknown"})
    assert svc.enrich_incident(inc) == []


def test_greynoise_parse_and_confidence():
    raw = {"ip": "1.2.3.4", "noise": True, "classification": "malicious",
           "name": "ET SCAN", "last_seen": "2024-01-01", "riot": False}
    data = GreyNoiseEnricher.parse(raw)
    assert data["classification"] == "malicious"
    assert GreyNoiseEnricher().confidence_for(data) == Confidence.HIGH
    assert GreyNoiseEnricher.parse({}) == {}


def test_otx_parse_counts_pulses():
    raw = {"pulse_info": {"count": 4, "pulses": [{"name": "APT feed"}, {"name": "Botnet"}]}}
    data = OTXEnricher.parse(raw)
    assert data["pulse_count"] == 4 and "APT feed" in data["pulses"]
    assert OTXEnricher.parse({"pulse_info": {"count": 0}}) == {}


def test_hibp_parse_breaches():
    data = HIBPExposureEnricher.parse([{"Name": "Adobe"}, {"Name": "LinkedIn"}])
    assert data["breach_count"] == 2 and "Adobe" in data["breaches"]
    assert HIBPExposureEnricher.parse([]) == {}


def test_build_enrichment_inert_by_default():
    svc = build_enrichment(Settings(db_url="sqlite://"))
    assert svc.enrichers == []  # nothing enabled → no network, no fabricated intel
