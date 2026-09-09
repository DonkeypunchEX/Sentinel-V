"""Concrete intel enrichers: GreyNoise, OTX, HIBP exposure.

Each provider does real HTTP against its API, but is only built when configured
(see build_enrichment): no key/enabled flag → the provider is absent, so the
enrichment step stays inert rather than inventing intel. The network parsing is
split into pure ``parse()`` staticmethods so it is unit-testable offline.

Concept map (docs/RND.md, PLAYBOOKS.md):
* GreyNoise → "is this IP mass-scanning the internet?" noise filter (Tier 2).
* OTX → community pulses referencing the indicator (Tier 3).
* HIBP → breach/exposure for assets YOU own — defensive Identify (Tier 1).
"""
from __future__ import annotations

import os

from sentinel_v.config import Settings
from sentinel_v.intel.enrich import Confidence, Enricher, EnrichmentService, Tier

_TIMEOUT = 8


class GreyNoiseEnricher(Enricher):
    name = "greynoise.community"
    tier = Tier.VERIFIED_AGGREGATOR
    base_confidence = Confidence.MODERATE

    def lookup(self, indicator: str, kind: str = "ip") -> dict[str, object]:
        if kind != "ip":
            return {}
        import requests

        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{indicator}", timeout=_TIMEOUT
        )
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return self.parse(resp.json())

    @staticmethod
    def parse(raw: dict) -> dict[str, object]:
        if not isinstance(raw, dict):
            return {}
        if raw.get("noise") is None and raw.get("classification") is None:
            return {}
        return {
            "classification": raw.get("classification"),
            "name": raw.get("name"),
            "noise": raw.get("noise"),
            "riot": raw.get("riot"),
            "last_seen": raw.get("last_seen"),
        }

    def confidence_for(self, data: dict[str, object]) -> Confidence:
        known = data.get("classification") in {"malicious", "benign"}
        return Confidence.HIGH if known else Confidence.LOW

    def summarize(self, data: dict[str, object]) -> str:
        return f"GreyNoise: {data.get('classification', 'unknown')} ({data.get('name') or 'n/a'})"


class OTXEnricher(Enricher):
    name = "otx.alienvault"
    tier = Tier.COMMUNITY
    base_confidence = Confidence.MODERATE

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def lookup(self, indicator: str, kind: str = "ip") -> dict[str, object]:
        from OTXv2 import IndicatorTypes, OTXv2

        types = {"ip": IndicatorTypes.IPv4, "domain": IndicatorTypes.DOMAIN,
                 "hash": IndicatorTypes.FILE_HASH_SHA256}
        itype = types.get(kind)
        if itype is None:
            return {}
        otx = OTXv2(self._api_key)
        return self.parse(otx.get_indicator_details_by_section(itype, indicator, "general"))

    @staticmethod
    def parse(raw: dict) -> dict[str, object]:
        if not isinstance(raw, dict):
            return {}
        pulses = (raw.get("pulse_info") or {}).get("count", 0)
        if not pulses:
            return {}
        names = [p.get("name") for p in (raw.get("pulse_info") or {}).get("pulses", [])[:5]]
        return {"pulse_count": pulses, "pulses": [n for n in names if n]}

    def confidence_for(self, data: dict[str, object]) -> Confidence:
        raw = data.get("pulse_count", 0)
        count = int(raw) if isinstance(raw, (int, float, str)) else 0
        return Confidence.MODERATE if count >= 3 else Confidence.LOW

    def summarize(self, data: dict[str, object]) -> str:
        return f"OTX: {data.get('pulse_count', 0)} pulse(s)"


class HIBPExposureEnricher(Enricher):
    """Breach exposure for OWNED identifiers/domains (defensive). Tier 1."""

    name = "hibp.exposure"
    tier = Tier.AUTHORITATIVE
    base_confidence = Confidence.HIGH

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def lookup(self, indicator: str, kind: str = "email") -> dict[str, object]:
        if kind not in {"email", "account"}:
            return {}
        import requests

        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{indicator}",
            params={"truncateResponse": "true"},
            headers={"hibp-api-key": self._api_key, "user-agent": "Sentinel-V"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {}  # not found in any breach
        resp.raise_for_status()
        return self.parse(resp.json())

    @staticmethod
    def parse(raw: object) -> dict[str, object]:
        if not isinstance(raw, list) or not raw:
            return {}
        names = [b.get("Name") for b in raw if isinstance(b, dict) and b.get("Name")]
        return {"breach_count": len(names), "breaches": names[:10]}

    def summarize(self, data: dict[str, object]) -> str:
        return f"HIBP: exposed in {data.get('breach_count', 0)} breach(es)"


def build_enrichment(settings: Settings) -> EnrichmentService:
    """Assemble the EnrichmentService from settings — only enabled providers.

    Default config disables everything, so this returns an empty service and the
    incident enrichment step is a no-op (no network, no fabricated intel).
    """
    enrichers: list[Enricher] = []
    intel = settings.intel
    if getattr(intel.greynoise, "enabled", False):
        enrichers.append(GreyNoiseEnricher())
    if getattr(intel.otx, "enabled", False):
        key = os.environ.get(intel.otx.api_key_env, "")
        if key:
            enrichers.append(OTXEnricher(key))
    hibp = getattr(intel, "hibp", None)
    if hibp is not None and getattr(hibp, "enabled", False):
        key = os.environ.get(hibp.api_key_env, "")
        if key:
            enrichers.append(HIBPExposureEnricher(key))
    return EnrichmentService(enrichers)
