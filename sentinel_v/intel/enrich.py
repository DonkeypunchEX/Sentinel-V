"""Threat-intel enrichment — pluggable providers (OTX, GreyNoise, MISP).

Enrichers take an indicator (IP/domain/hash) and return context. Cache results;
intel APIs rate-limit. See docs/RND.md for provider clients.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class Enricher(ABC):
    name: str

    @abstractmethod
    def lookup(self, indicator: str, kind: str = "ip") -> dict[str, object]:
        """Return provider context for an indicator, or {} if unknown."""
        raise NotImplementedError


# Phase-3 targets: OTXEnricher (OTXv2), GreyNoiseEnricher (community API).
