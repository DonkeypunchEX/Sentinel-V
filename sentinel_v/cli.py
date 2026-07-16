#!/usr/bin/env python3
"""Command line interface for Sentinel-V."""

import json
import logging
import sys
import time
from typing import Any, Dict, Optional

import click
import yaml

from .core import SystemMode, create_sentinel_system


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
def start(config: Optional[str], mode: str, log_level: str) -> None:
    """Start the Sentinel-V system and run until interrupted."""
    logging.basicConfig(level=getattr(logging, log_level))

    sentinel = create_sentinel_system(config)
    sentinel.mode = SystemMode(mode)

    click.echo(f"Sentinel-V system started (ID: {sentinel.system_id})")
    click.echo(f"   Mode: {mode}")
    click.echo(f"   Defense Level: {sentinel.defense_level.value}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nShutting down Sentinel-V system...")
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
    """Show system status."""
    sentinel = create_sentinel_system()
    status_info = sentinel.get_system_status()
    sentinel.shutdown()

    click.echo("Sentinel-V System Status")
    click.echo("=" * 40)
    click.echo(f"System ID: {status_info['system_id']}")
    click.echo(f"Status: {status_info['status']}")
    click.echo(f"Uptime: {status_info['uptime']:.0f} seconds")
    click.echo(f"Events Processed: {status_info['metrics']['events_processed']}")
    click.echo(f"Threats Detected: {status_info['metrics']['threats_detected']}")

    click.echo("\nResource Usage:")
    for resource, usage in status_info["metrics"]["resource_usage"].items():
        click.echo(f"  {resource}: {usage:.1%}")


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
