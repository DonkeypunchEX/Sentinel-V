#!/usr/bin/env python3
"""
Command Line Interface for Sentinel-V
"""

import click
import yaml
import json
import sys
from pathlib import Path
from typing import Optional

from .core import SentinelVSystem, create_sentinel_system

@click.group()
@click.version_option()
def cli():
    """Sentinel-V: Autonomous Cyber-Defense Framework"""
    pass

@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file')
@click.option('--mode', type=click.Choice(['dev', 'test', 'production']), 
              default='production', help='System mode')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              default='INFO', help='Logging level')
def start(config, mode, log_level):
    """Start the Sentinel-V system"""
    import logging
    logging.basicConfig(level=getattr(logging, log_level))
    
    try:
        sentinel = create_sentinel_system(config)
        sentinel.mode = mode
        
        click.echo(f"✅ Sentinel-V system started (ID: {sentinel.system_id})")
        click.echo(f"   Mode: {mode}")
        click.echo(f"   Defense Level: {sentinel.defense_level.value}")
        
        # Keep system running
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        click.echo("\n🛑 Shutting down Sentinel-V system...")
        sentinel.shutdown()
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('event_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file')
def analyze(event_file, output):
    """Analyze events from a file"""
    import json
    
    sentinel = create_sentinel_system()
    
    with open(event_file, 'r') as f:
        events = json.load(f)
    
    results = []
    for event in events:
        result = sentinel.process_event(event)
        results.append(result)
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"✅ Results written to {output}")
    else:
        click.echo(json.dumps(results, indent=2))

@cli.command()
def status():
    """Get system status"""
    sentinel = create_sentinel_system()
    status_info = sentinel.get_system_status()
    
    click.echo("📊 Sentinel-V System Status")
    click.echo("=" * 40)
    
    click.echo(f"System ID: {status_info['system_id']}")
    click.echo(f"Status: {status_info['status']}")
    click.echo(f"Uptime: {status_info['uptime']:.0f} seconds")
    click.echo(f"Events Processed: {status_info['metrics']['events_processed']}")
    click.echo(f"Threats Detected: {status_info['metrics']['threats_detected']}")
    
    click.echo("\n📈 Resource Usage:")
    for resource, usage in status_info['metrics']['resource_usage'].items():
        click.echo(f"  {resource}: {usage:.1%}")

@cli.command()
@click.option('--network', default='10.0.0.0/24', help='Network range for decoys')
@click.option('--count', default=5, help='Number of decoys to deploy')
def deploy_decoys(network, count):
    """Deploy deception network"""
    sentinel = create_sentinel_system()
    
    for i in range(count):
        decoy_ip = sentinel.deception_net.add_decoy(
            profile_type='web_server',
            ip_address=None  # Auto-assign
        )
        click.echo(f"✅ Deployed decoy at {decoy_ip}")
    
    stats = sentinel.deception_net.get_statistics()
    click.echo(f"\n📊 Deception Network: {stats['active_decoys']} active decoys")

@cli.command()
@click.argument('config_file', type=click.Path())
def validate_config(config_file):
    """Validate configuration file"""
    try:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                config = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                config = json.load(f)
            else:
                click.echo("❌ Unsupported file format", err=True)
                sys.exit(1)
        
        # Validate required fields
        required = ['system_mode', 'defense_level']
        for field in required:
            if field not in config:
                click.echo(f"❌ Missing required field: {field}", err=True)
                sys.exit(1)
        
        click.echo("✅ Configuration is valid")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@cli.command()
def export_sbom():
    """Export Software Bill of Materials"""
    import json
    import pkg_resources
    
    sbom = {
        "format": "CycloneDX",
        "version": "1.4",
        "components": []
    }
    
    for dist in pkg_resources.working_set:
        component = {
            "type": "library",
            "name": dist.project_name,
            "version": dist.version,
            "purl": f"pkg:pypi/{dist.project_name}@{dist.version}"
        }
        sbom["components"].append(component)
    
    sbom_file = "sbom.json"
    with open(sbom_file, 'w') as f:
        json.dump(sbom, f, indent=2)
    
    click.echo(f"✅ SBOM exported to {sbom_file}")

if __name__ == '__main__':
    cli()
