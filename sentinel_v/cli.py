"""``sentinel-v`` command-line entry point.

Small, dependency-free (argparse) operator CLI. Today it exposes:

* ``sentinel-v fit`` — fit the ML anomaly detector on a REAL baseline (CIC-IDS2017
  benign rows) and persist it, so the anomaly leg of the pipeline actually runs.
  Without this step there is no model on disk and the detector stays dormant by
  design (it never trains itself on ingest, and never on fabricated data).
* ``sentinel-v serve`` — launch the FastAPI control plane (thin uvicorn wrapper).
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from sentinel_v import __version__
from sentinel_v.config import load_settings


def _cmd_fit(args: argparse.Namespace) -> int:
    from sentinel_v.detection.anomaly import AnomalyDetector
    from sentinel_v.detection.datasets import load_cic_ids2017_benign
    from sentinel_v.detection.features import flow_features

    settings = load_settings(args.config)
    model_path = Path(args.model_path) if args.model_path else settings.model_path

    baseline = list(load_cic_ids2017_benign(args.dataset, limit=args.limit))
    print(f"Loaded {len(baseline)} benign baseline flows from {args.dataset}")
    detector = AnomalyDetector(
        flow_features,
        contamination=args.contamination,
        model_path=model_path,
        kinds={"flow"},
    )
    detector.fit(baseline)  # raises clearly on an empty/absent baseline
    print(f"Fitted IsolationForest and saved model → {model_path}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = load_settings(args.config)
    uvicorn.run(
        "sentinel_v.api.app:app",
        host=args.host or settings.api_host,
        port=args.port or settings.api_port,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel-v", description="Sentinel-V control CLI")
    p.add_argument("--version", action="version", version=f"sentinel-v {__version__}")
    p.add_argument("--config", default=None, help="path to sentinel.yaml (else default/env)")
    sub = p.add_subparsers(dest="command", required=True)

    fit = sub.add_parser("fit", help="fit the anomaly model on a CIC-IDS2017 baseline")
    fit.add_argument("--dataset", required=True, help="path to a CIC-IDS2017 flow CSV")
    fit.add_argument("--model-path", default=None, help="output model path (else config)")
    fit.add_argument("--contamination", type=float, default=0.02)
    fit.add_argument("--limit", type=int, default=None, help="cap number of baseline rows")
    fit.set_defaults(func=_cmd_fit)

    serve = sub.add_parser("serve", help="run the FastAPI control plane")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.set_defaults(func=_cmd_serve)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
