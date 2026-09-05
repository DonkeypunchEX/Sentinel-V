# 🛡️ Sentinel-V: Autonomous Cyber-Defense Framework

![Tests](https://github.com/DonkeypunchEX/Sentinel-V/actions/workflows/test.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Autonomous defense framework: an event-processing core that scores
threats behaviorally, runs a deception network, and produces
proportional, auditable responses. Response execution is
**simulation-safe by design** — the engine logs and recommends actions;
enforcement is left to integrations you control.

This repository also contains **WHSE-01**, a self-hosted warehouse
inventory system, under [`warehouse-app/`](warehouse-app/README.md).

## What's implemented

Working with only the base install (`pip install -e .`):

- **`SentinelVSystem`** — orchestrates the full event pipeline:
  validate → deception check → threat scoring → response → federation
- **Adaptive threat matrix** — behavioral anomaly scoring (port
  fan-out, sensitive-port pressure, repetition, sensor signals) with
  bounded memory and `BENIGN / SUSPICIOUS / MALICIOUS / CRITICAL` levels
- **Deception network** — deterministic decoy allocation across a
  network range; any contact with a decoy is flagged and escalates
- **Response engine** — graduated playbooks with capped escalation;
  every execution is recorded in an auditable history
- **Federation node** — queues minimized threat intelligence (raw
  events never leave the node); transport is integration-defined
- **Hybrid crypto** — X25519 + HKDF + AES-256-GCM behind a
  PQC-shaped interface
- **`sentinel-v` CLI** — start, analyze, status, deploy-decoys,
  validate-config, export-sbom

Optional extras add research modules loaded lazily (the base package
never imports them): `ml` (scikit-learn detector, federated learning),
`quantum` (liboqs KEM), and a paramiko SSH honeypot.

## Quick start

```bash
git clone https://github.com/DonkeypunchEX/Sentinel-V.git
cd Sentinel-V
pip install -e ".[dev,cli]"   # Python 3.10+
pytest tests/                 # 32 tests
python examples/basic_usage.py
```

```python
from sentinel_v import SentinelVSystem

sentinel = SentinelVSystem({"system_mode": "production"})
assessment = sentinel.process_event(
    {
        "source_ip": "203.0.113.66",
        "dest_ip": "10.0.0.15",
        "dest_port": 22,
        "protocol": "tcp",
        "failed_auth": True,
    }
)
print(assessment["threat_level"], assessment["anomaly_score"])
sentinel.shutdown()
```

CLI equivalent:

```bash
sentinel-v status
sentinel-v analyze events.json --output results.json
sentinel-v deploy-decoys --network 10.0.0.0/24 --count 5
```

Configuration reference: [`config/sentinel.default.yaml`](config/sentinel.default.yaml).
Docker: `docker build -t sentinel-v . && docker run sentinel-v`
(mount your own `config/` to override defaults).

### Windows

`scripts/deploy.sh` is bash-only. On native Windows (PowerShell, no
WSL required), use the equivalent script:

```powershell
.\scripts\deploy.ps1 install   # install deps, write config/sentinel.yaml, run tests
.\scripts\deploy.ps1 start     # start in the background, log to logs\sentinel.log
.\scripts\deploy.ps1 status
.\scripts\deploy.ps1 stop
```

### Standalone executable

To hand `sentinel-v` to someone without a Python environment, build a
single-file executable with [PyInstaller](https://pyinstaller.org/):

```bash
make build-exe             # Linux/macOS: writes dist/sentinel-v
```

```powershell
.\scripts\build-exe.ps1    # Windows: writes dist\sentinel-v.exe
```

The result runs standalone (`dist/sentinel-v status`) — no `pip
install` needed on the target machine. It bundles only the base +
`cli` extras; the optional `ml`/`quantum` research modules still
require their own environment.

## Development

```bash
make dev-install   # editable install with dev tools
make test          # pytest
make lint          # flake8 + mypy + bandit (same gates as CI)
make security      # bandit + pip-audit
make format        # black
```

CI runs the same gates across Python 3.10–3.12 on every push and pull
request; `warehouse-app/` changes are gated by its own Node test suite
instead.

### Optional extras

```bash
pip install -e ".[ml]"       # scikit-learn detector, ART robust model, Flower federated learning
pip install -e ".[quantum]"  # liboqs-backed post-quantum KEM (QuantumCrypto)
pip install -e ".[cli,build]"  # CLI + PyInstaller, for building a standalone executable
```

## License

MIT
