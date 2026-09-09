"""Typed settings: defaults < config/sentinel.yaml < SENTINEL_* env vars.

Phase 0. NIST CSF: Identify (system/telemetry inventory lives here).

Precedence (lowest to highest): model defaults, then the YAML file, then
environment variables. Nested values use a double-underscore delimiter, e.g.
``SENTINEL_RESPONSE__REQUIRE_APPROVAL_FOR_DESTRUCTIVE=false`` or
``SENTINEL_API_PORT=9000``. Nothing here is hard-coded into logic — every host,
port and path is a setting (CLAUDE.md quality bar).
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = Path("config/sentinel.yaml")


class CollectorCfg(BaseModel):
    """A file-tailing collector (Suricata EVE, auth.log)."""

    path: Path | None = None
    enabled: bool = False


class CollectorsCfg(BaseModel):
    suricata_eve: CollectorCfg = Field(
        default_factory=lambda: CollectorCfg(path=Path("/var/log/suricata/eve.json"))
    )
    auth_log: CollectorCfg = Field(
        default_factory=lambda: CollectorCfg(path=Path("/var/log/auth.log"))
    )


class DeceptionSourceCfg(BaseModel):
    log: Path | None = None
    enabled: bool = False


class DeceptionCfg(BaseModel):
    cowrie: DeceptionSourceCfg = Field(
        default_factory=lambda: DeceptionSourceCfg(log=Path("/var/lib/cowrie/log/cowrie.json"))
    )
    opencanary: DeceptionSourceCfg = Field(
        default_factory=lambda: DeceptionSourceCfg(log=Path("/var/tmp/opencanary.log"))
    )


class OtxCfg(BaseModel):
    api_key_env: str = "OTX_API_KEY"
    enabled: bool = False


class GreyNoiseCfg(BaseModel):
    community: bool = True
    enabled: bool = False


class HibpCfg(BaseModel):
    # Breach/exposure lookups for identifiers and domains you OWN (defensive).
    api_key_env: str = "HIBP_API_KEY"
    enabled: bool = False


class IntelCfg(BaseModel):
    otx: OtxCfg = Field(default_factory=OtxCfg)
    greynoise: GreyNoiseCfg = Field(default_factory=GreyNoiseCfg)
    hibp: HibpCfg = Field(default_factory=HibpCfg)


class CorrelationCfg(BaseModel):
    """Dedupe + time/asset grouping of Alerts into Incidents."""

    window_seconds: int = 60  # sliding window for grouping same-asset alerts
    brute_force_threshold: int = 5  # N same-detector alerts from one src → incident


class ResponseCfg(BaseModel):
    # Do not flip this off without reading docs/PLAYBOOKS.md — it is the gate.
    require_approval_for_destructive: bool = True
    playbooks_dir: Path = Path("playbooks/")
    # Where the simulated block_ip handler writes its (reversible) firewall rules.
    # Simulation-safe by design: we write intent to a file, we do not touch nftables.
    block_list_path: Path = Path("var/blocked_ips.nft")


class Settings(BaseSettings):
    """Root configuration object for the control plane."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        extra="ignore",
        yaml_file=None,
    )

    db_url: str = "sqlite:///sentinel.db"
    rules_dir: Path = Path("rules/")
    model_path: Path = Path("models/anomaly.joblib")
    api_host: str = "127.0.0.1"
    api_port: int = 8787

    collectors: CollectorsCfg = Field(default_factory=CollectorsCfg)
    deception: DeceptionCfg = Field(default_factory=DeceptionCfg)
    intel: IntelCfg = Field(default_factory=IntelCfg)
    correlation: CorrelationCfg = Field(default_factory=CorrelationCfg)
    response: ResponseCfg = Field(default_factory=ResponseCfg)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Order = precedence (first wins): explicit init args, then env, then the
        # YAML file, then defaults. This is what makes env override the file.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings, layering the YAML file (if present) under env overrides.

    ``path`` defaults to ``$SENTINEL_CONFIG`` or ``config/sentinel.yaml``. A
    missing file is fine — you get defaults plus any env overrides.
    """
    yaml_path = Path(path) if path is not None else Path(
        os.environ.get("SENTINEL_CONFIG", str(DEFAULT_CONFIG_PATH))
    )
    if not yaml_path.exists():
        return Settings()

    # Scope the yaml_file to THIS call via a subclass rather than mutating the
    # shared Settings.model_config — otherwise concurrent loads of different
    # files would race on one class-level path. YamlConfigSettingsSource reads
    # yaml_file from the (sub)class's model_config.
    class _Scoped(Settings):
        model_config = SettingsConfigDict(
            **{**Settings.model_config, "yaml_file": str(yaml_path)}
        )

    return _Scoped()
