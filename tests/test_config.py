"""Phase 0: settings precedence — defaults < YAML < env."""
from __future__ import annotations

from sentinel_v.config import load_settings


def test_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_CONFIG", raising=False)
    s = load_settings(tmp_path / "does-not-exist.yaml")
    assert s.api_host == "127.0.0.1"
    assert s.api_port == 8787
    assert s.response.require_approval_for_destructive is True
    assert s.collectors.suricata_eve.enabled is False


def test_yaml_overrides_defaults(tmp_path):
    cfg = tmp_path / "sentinel.yaml"
    cfg.write_text(
        "api_port: 9000\n"
        "collectors:\n"
        "  auth_log: { path: /tmp/auth.log, enabled: true }\n"
        "response:\n"
        "  require_approval_for_destructive: false\n"
    )
    s = load_settings(cfg)
    assert s.api_port == 9000
    assert s.collectors.auth_log.enabled is True
    assert s.response.require_approval_for_destructive is False


def test_env_overrides_yaml(tmp_path, monkeypatch):
    cfg = tmp_path / "sentinel.yaml"
    cfg.write_text("api_port: 9000\n")
    monkeypatch.setenv("SENTINEL_API_PORT", "9100")
    monkeypatch.setenv("SENTINEL_RESPONSE__REQUIRE_APPROVAL_FOR_DESTRUCTIVE", "false")
    s = load_settings(cfg)
    assert s.api_port == 9100  # env beats the file
    assert s.response.require_approval_for_destructive is False
