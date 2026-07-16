"""Shared fixtures for the Sentinel-V test suite."""

from typing import Iterator

import pytest

from sentinel_v import SentinelVSystem


@pytest.fixture()
def system() -> Iterator[SentinelVSystem]:
    """A production-mode system on a documentation network range.

    Production mode keeps the threat matrix multiplier high enough for
    deterministic threat-level assertions; the TEST-NET-2 range makes
    decoy addresses look external so decoy detection paths run.
    """
    sentinel = SentinelVSystem(
        {
            "system_mode": "production",
            "deception_network": "198.51.100.0/24",
            "decoy_count": 3,
            "federation_enabled": True,
        }
    )
    yield sentinel
    sentinel.shutdown()
