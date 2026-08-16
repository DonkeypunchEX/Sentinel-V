"""Sentinel-V: a self-hostable defensive (blue-team) automation framework.

Pipeline: collectors -> Event -> detection (rules + ML) -> correlation
-> gated response. See docs/ARCHITECTURE.md.
"""
from __future__ import annotations

__version__ = "0.1.0-dev"
