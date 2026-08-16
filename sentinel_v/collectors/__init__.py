"""Collectors: normalize source-native telemetry into Events."""
from __future__ import annotations

from sentinel_v.collectors.auth import AuthLogCollector
from sentinel_v.collectors.base import Collector
from sentinel_v.collectors.suricata import SuricataEveCollector

__all__ = ["Collector", "SuricataEveCollector", "AuthLogCollector"]
