#!/usr/bin/env python3
"""Command line interface for Sentinel-V."""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import click
import yaml

from .core import SystemMode, create_sentinel_system
from .paths import main_log_file, status_file

# A running daemon's monitor thread refreshes the heartbeat every 30s
# (retrying after 60s on error) - anything older than this is treated as
# a crashed or killed process rather than a live one.
HEARTBEAT_STALE_SECONDS = 90


def _configured_log_file(config_file: Optional[str]) -> Path:
    """Resolve the configured log path without depending on the CWD."""
    if not config_file:
        return main_log_file()

    config_path = Path(config_file).resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        config_data = yaml.safe_load(handle) or {}

    configured = config_data.get("log_file")
    if not configured:
        return main_log_file()

    log_path = Path(str(configured)).expanduser()
    if not log_path.is_absolute():
        base = config_path.parent
        if base.name.lower() == "config":
            base = base.parent
        log_path = base / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return log_path


@click.group()
@click.version_option(version="1.0.0", prog_name="sentinel-v")
def cli() -> None:
    """Sentinel-V: Autonomous Cyber-Defense Framework."""


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file")
@click.option(
    "--mode",
    type=click.Choice(["dev", "test", "production"]),
    default="production",
    help="System mode",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level",
)
@click.option(
    "--windows-events",
    is_flag=True,
    help=(
        "Feed local Sysmon (process/network/DNS) and Security (failed logon) "
        "events into the running system. Windows only."
    ),
)
@click.option(
    "--active-defense",
    is_flag=True,
    help="Enable active defense (firewall blocking, host isolation).",
)
@click.option(
    "--enforce",
    is_flag=True,
    help=(
        "Enforce active defense actions (block IPs, isolate hosts). "
        "WARNING: This modifies firewall rules."
    ),
)
@click.option(
    "--auto-block",
    is_flag=True,
    default=None,
    help="Automatically block malicious IPs (requires --enforce).",
)
@click.option(
    "--auto-isolate",
    is_flag=True,
    default=None,
    help="Automatically isolate compromised hosts (requires --enforce).",
)
def start(
    config: Optional[str],
    mode: str,
    log_level: str,
    windows_events: bool,
    active_defense: bool,
    enforce: bool,
    auto_block: Optional[bool],
    auto_isolate: Optional[bool],
) -> None:
    """Start the Sentinel-V system and run until interrupted."""
    log_path = _configured_log_file(config)
    logging.basicConfig(
        level=getattr(logging, log_level),
        handlers=[logging.StreamHandler(), logging.FileHandler(str(log_path))],
    )

    # Build overrides for active defense
    overrides: Dict[str, Any] = {}
    if active_defense:
        overrides["active_defense_enabled"] = True
        overrides["active_defense_enforce"] = enforce
        if auto_block is not None:
            overrides["active_defense_auto_block"] = auto_block
        if auto_isolate is not None:
            overrides["active_defense_auto_isolate"] = auto_isolate
        
        if enforce:
            click.echo(
                "WARNING: Active defense ENFORCE mode enabled. "
                "Firewall rules will be modified.",
                err=True,
            )

    sentinel = create_sentinel_system(config, overrides=overrides, write_status_file=True)
    sentinel.mode = SystemMode(mode)

    click.echo(f"Sentinel-V system started (ID: {sentinel.system_id})")
    click.echo(f"   Mode: {mode}")
    click.echo(f"   Defense Level: {sentinel.defense_level.value}")
    click.echo(f"   Log file: {log_path}")
    
    if sentinel.active_defense_enabled:
        click.echo(f"   Active Defense: ENABLED")
        click.echo(f"   Enforce Mode: {sentinel.active_defense.enforce_mode}")
        click.echo(f"   Auto Block: {sentinel.active_defense.auto_block}")
        click.echo(f"   Auto Isolate: {sentinel.active_defense.auto_isolate}")
        click.echo(f"   Auto Rate Limit: {sentinel.active_defense.auto_rate_limit}")

    collector_stop = threading.Event()
    if windows_events:
        if os.name != "nt":
            click.echo(
                "   --windows-events requires Windows (Get-WinEvent); ignoring.",
                err=True,
            )
        else:
            from .windows_events import WindowsEventCollector

            collector = WindowsEventCollector(sentinel)
            threading.Thread(
                target=collector.run_forever, args=(collector_stop,), daemon=True
            ).start()
            click.echo(
                "   Windows event collection: Sysmon (process/network/DNS) + "
                "Security (failed logon)"
            )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nShutting down Sentinel-V system...")
        collector_stop.set()
        sentinel.shutdown()


@cli.command()
@click.argument("event_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file")
def analyze(event_file: str, output: Optional[str]) -> None:
    """Analyze events from a JSON file."""
    sentinel = create_sentinel_system()

    with open(event_file, "r") as f:
        events = json.load(f)

    results = [sentinel.process_event(event) for event in events]
    sentinel.shutdown()

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        click.echo(f"Results written to {output}")
    else:
        click.echo(json.dumps(results, indent=2))


@cli.command()
def status() -> None:
    """Show system status.

    Reads the heartbeat file a running `sentinel-v start` daemon publishes.
    This process never contacts that daemon directly, so if no heartbeat
    is found (or it's stale) that is reported plainly rather than showing
    a freshly-created, empty system's all-zero metrics as if they were
    live.
    """
    heartbeat = status_file()

    if not heartbeat.exists():
        click.echo("Sentinel-V is not running (no active daemon found)")
        click.echo(f"   Checked: {heartbeat}")
        return

    try:
        status_info = json.loads(heartbeat.read_text())
    except (OSError, ValueError):
        click.echo("Sentinel-V is not running (heartbeat file unreadable)")
        return

    last_updated = status_info.get("last_updated")
    age_seconds: Optional[float] = None
    if last_updated:
        try:
            age_seconds = (
                datetime.now() - datetime.fromisoformat(last_updated)
            ).total_seconds()
        except ValueError:
            age_seconds = None

    if age_seconds is None or age_seconds > HEARTBEAT_STALE_SECONDS:
        click.echo("Sentinel-V is not running (stale heartbeat - process likely died)")
        click.echo(f"   Last seen: {last_updated or 'unknown'}")
        return

    click.echo("Sentinel-V System Status")
    click.echo("=" * 40)
    click.echo(f"System ID: {status_info['system_id']}")
    click.echo(f"Status: {status_info['status']}")
    click.echo(f"PID: {status_info.get('pid', 'unknown')}")
    click.echo(f"Uptime: {status_info['uptime']:.0f} seconds")
    click.echo(f"Events Processed: {status_info['metrics']['events_processed']}")
    click.echo(f"Threats Detected: {status_info['metrics']['threats_detected']}")

    click.echo("\nResource Usage:")
    for resource, usage in status_info["metrics"]["resource_usage"].items():
        click.echo(f"  {resource}: {usage:.1%}")
    
    # Show active defense stats if available
    components = status_info.get("components", {})
    active_defense = components.get("active_defense")
    if active_defense:
        click.echo("\nActive Defense:")
        click.echo(f"  Enabled: {active_defense.get('enabled', False)}")
        click.echo(f"  Enforce Mode: {active_defense.get('enforce_mode', False)}")
        click.echo(f"  Blocked IPs: {active_defense.get('total_blocked_ips', 0)}")
        click.echo(f"  Blocked Networks: {active_defense.get('total_blocked_networks', 0)}")
        click.echo(f"  Isolated Hosts: {active_defense.get('total_isolated_hosts', 0)}")
        click.echo(f"  Rate Limit Rules: {active_defense.get('total_rate_limit_rules', 0)}")


@cli.command()
@click.argument("ip")
@click.option("--reason", default="Manual block", help="Reason for blocking")
@click.option("--duration", type=int, default=None, help="Duration in seconds (default: permanent)")
def block_ip(ip: str, reason: str, duration: Optional[int]) -> None:
    """Manually block an IP address using active defense."""
    sentinel = create_sentinel_system(
        None,
        overrides={
            "active_defense_enabled": True,
            "active_defense_enforce": True,
        }
    )
    
    success = sentinel.active_defense.block_ip(ip, reason, duration)
    
    if success:
        click.echo(f"Successfully blocked IP: {ip}")
        click.echo(f"  Reason: {reason}")
        if duration:
            click.echo(f"  Duration: {duration} seconds")
        else:
            click.echo(f"  Duration: Permanent")
    else:
        click.echo(f"Failed to block IP: {ip}", err=True)
        click.echo(f"  Enforce mode may be disabled, or IP may already be blocked.")
    
    sentinel.shutdown()


@cli.command()
@click.argument("ip")
def unblock_ip(ip: str) -> None:
    """Remove a block on an IP address."""
    sentinel = create_sentinel_system(
        None,
        overrides={
            "active_defense_enabled": True,
            "active_defense_enforce": True,
        }
    )
    
    success = sentinel.active_defense.unblock_ip(ip)
    
    if success:
        click.echo(f"Successfully unblocked IP: {ip}")
    else:
        click.echo(f"Failed to unblock IP: {ip}", err=True)
    
    sentinel.shutdown()


@cli.command()
@click.option("--network", default="10.0.0.0/24", help="Network range for decoys")
@click.option("--count", default=5, help="Number of decoys to deploy")
def deploy_decoys(network: str, count: int) -> None:
    """Deploy the deception network and list its decoys."""
    sentinel = create_sentinel_system(
        None, overrides={"deception_network": network, "decoy_count": count}
    )
    sentinel.deception_net.active = True

    for decoy_ip in sentinel.deception_net.decoys:
        click.echo(f"Deployed decoy at {decoy_ip}")

    stats = sentinel.deception_net.get_statistics()
    sentinel.shutdown()
    click.echo(f"\nDeception Network: {stats['active_decoys']} active decoys")


@cli.command()
@click.option("--limit", default=100, help="Number of recent actions to show")
def active_defense_status(limit: int) -> None:
    """Show active defense status and recent actions."""
    sentinel = create_sentinel_system(
        None,
        overrides={"active_defense_enabled": True}
    )
    
    stats = sentinel.active_defense.get_statistics()
    
    click.echo("Active Defense Status")
    click.echo("=" * 40)
    click.echo(f"Enforce Mode: {stats['enforce_mode']}")
    click.echo(f"Auto Block: {stats['auto_block']}")
    click.echo(f"Auto Isolate: {stats['auto_isolate']}")
    click.echo(f"Auto Rate Limit: {stats['auto_rate_limit']}")
    click.echo(f"\nCounters:")
    click.echo(f"  Blocked IPs: {stats['total_blocked_ips']}")
    click.echo(f"  Blocked Networks: {stats['total_blocked_networks']}")
    click.echo(f"  Isolated Hosts: {stats['total_isolated_hosts']}")
    click.echo(f"  Rate Limit Rules: {stats['total_rate_limit_rules']}")
    click.echo(f"  Total Actions: {stats['total_actions']}")
    
    # Show recent actions
    if stats['total_actions'] > 0:
        click.echo(f"\nRecent Actions (last {limit}):")
        actions = sentinel.active_defense.get_action_history(limit)
        for action in actions:
            status = "EXECUTED" if action['success'] and action['enforce_mode'] else "LOGGED"
            click.echo(f"  [{action['timestamp']}] {action['action']} {action['target']} - {action['reason']} ({status})")
    
    sentinel.shutdown()


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate_config(config_file: str) -> None:
    """Validate a configuration file."""
    try:
        with open(config_file, "r") as f:
            if config_file.endswith((".yaml", ".yml")):
                config = yaml.safe_load(f)
            elif config_file.endswith(".json"):
                config = json.load(f)
            else:
                click.echo("Unsupported file format", err=True)
                sys.exit(1)

        required = ["system_mode", "defense_level"]
        missing = [field for field in required if field not in (config or {})]
        if missing:
            click.echo(f"Missing required fields: {', '.join(missing)}", err=True)
            sys.exit(1)

        click.echo("Configuration is valid")

    except (OSError, ValueError, yaml.YAMLError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def export_sbom() -> None:
    """Export a Software Bill of Materials for the environment."""
    from importlib import metadata

    components = []
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": dist.version,
                "purl": f"pkg:pypi/{name}@{dist.version}",
            }
        )

    sbom: Dict[str, Any] = {
        "format": "CycloneDX",
        "version": "1.4",
        "components": sorted(components, key=lambda c: str(c["name"]).lower()),
    }

    sbom_file = "sbom.json"
    with open(sbom_file, "w") as f:
        json.dump(sbom, f, indent=2)

    click.echo(f"SBOM exported to {sbom_file}")


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
