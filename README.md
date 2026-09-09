# Sentinel-V

A self-hostable **defensive (blue-team) automation framework**:
**ingest → detect (rules + ML) → deceive → enrich → gated response → dashboard.**

This is an honest rebuild of an earlier stub whose README over-promised
("quantum-resistant, federated, formally verified") and under-delivered (empty
package dirs, placeholder code). Scope and status below are truthful. See
`docs/FEASIBILITY.md` for what's real vs deferred.

## Status
**Phases 0 and 1 are in.** The control plane persists telemetry and runs both
detectors on ingest; alerts land in the store and are queryable over the API.
Deception, enrichment and gated response follow per `docs/ROADMAP.md`.

| Capability | Status | Notes |
|---|---|---|
| Core Event/Alert/Incident/Action schema | 🟢 done | `sentinel_v/models.py`, validated |
| Typed settings (YAML + env) | 🟢 done | `sentinel_v/config.py`, pydantic-settings |
| Storage (SQLAlchemy: events/alerts/incidents/audit) | 🟢 done | `sentinel_v/storage.py` |
| Control plane API (`/health` `/events` `/alerts` `/incidents` `/actions/pending` `/approve` `/metrics`) | 🟢 done | `sentinel_v/api/app.py` |
| Correlation → Incidents (thresholded, deduped) | 🟢 done | `sentinel_v/correlation.py`; real T1110 brute-force threshold |
| Gated response + YAML playbooks (durable audit, reversible) | 🟢 done | `sentinel_v/response/`, `playbooks/`; human-in-loop `/approve` |
| Collectors (Suricata EVE + auth.log) | 🟢 done | `sentinel_v/collectors/` |
| Rule (Sigma) detection | 🟢 done | `detection/rules.py`, ATT&CK-tagged, rules in `rules/` |
| ML anomaly detection (reference impl) | 🟢 done | `detection/anomaly.py` + `features.py` + `datasets.py`, real-data only |
| Ingest pipeline (detectors → correlate → respond) | 🟢 done | `sentinel_v/pipeline.py` |
| Deception adapters (Cowrie/OpenCanary) | 🟡 stubbed | Phase 2 |
| Intel enrichment (OTX/GreyNoise/HIBP exposure) | 🟢 done | `intel/`, provenance-tiered, cached, inert without keys |
| Playbooks (brute-force done; honeypot/C2/rogue-device) | 🟡 1 of 4 | `playbooks/` |
| Purple-team validation (`make validate`, ATT&CK-mapped) | 🟢 done | `sentinel_v/validation/`, CI-gated, proves detections fire |
| `sentinel-v` CLI (`fit`, `serve`) | 🟢 done | `sentinel_v/cli.py` |
| Post-quantum / federated / adversarial | 🔴 deferred | Phase 4 stretch, not MVP |

## Quick start
```bash
make setup          # venv + editable install (.[ml,intel,dev])
make test           # pytest
make run            # FastAPI control plane on :8787
```
`GET http://127.0.0.1:8787/health` returns ok. Then ingest and query:
```bash
curl -s localhost:8787/events -H 'content-type: application/json' \
  -d '{"source":"auth.log","kind":"auth_fail","src_ip":"1.2.3.4",
       "fields":{"service":"sshd","user":"root"}}'
curl -s localhost:8787/alerts    # the T1110 rule alert this just fired
curl -s localhost:8787/metrics   # table counts + loaded detectors
```
The ML detector joins the pipeline once a fitted model exists at
`model_path` (config). Fit it on a real baseline (it will not train on
synthetic data):
```bash
sentinel-v fit --dataset /path/to/CIC-IDS2017-benign.csv   # persists model_path
sentinel-v serve                                           # = make run
```

## Also in this repo
`warehouse-app/` is a separate, self-hosted warehouse inventory system
(**WHSE-01**, Node) with its own toolchain and CI path; it is unrelated to the
Sentinel-V Python framework and lives alongside it.

## Design in one breath
Deception is the highest-fidelity sensor (near-zero false positives); rules
catch known TTPs; ML catches the unknowns; response is **gated and reversible**
by default because a blue tool that can brick your own network on a false
positive is a liability. Everything maps to NIST CSF + MITRE ATT&CK/D3FEND.

## Scope guardrails
Defensive only. No offensive tooling, no attacking third parties, no
autonomous destructive action without an approval gate. See `CLAUDE.md`.

## Docs
`CLAUDE.md` (build brief) · `docs/ARCHITECTURE.md` · `docs/FEASIBILITY.md` ·
`docs/ROADMAP.md` · `docs/RND.md` · `docs/PLAYBOOKS.md` · `docs/HARDWARE.md`

## License
MIT (add `LICENSE` file — original repo had none).
