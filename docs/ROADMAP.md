# Roadmap — phased build (this is Claude Code's worklist)

Work top to bottom. Each phase has an **acceptance criterion** — don't advance
until it's met. Check boxes as you go. Keep `make test` green throughout.

## Phase 0 — Foundation  ✅ done
- [x] Repo scaffold, packaging, CI, Docker, docs (done in handoff)
- [x] `models.py`: finalize `Event`, `Alert`, `Incident`, `Action` schemas + validation
- [x] `config.py`: pydantic settings load from `config/sentinel.yaml` + env
- [x] Storage layer: SQLite via SQLAlchemy; `events`, `alerts`, `incidents`, `audit` tables
- [x] `api/app.py`: `/health`, `/events` (ingest+query), `/alerts`, `/metrics` live
- **Accept:** ✅ `POST /events` persists an Event; `GET /events` returns it; CI green. (`tests/test_api.py`)

## Phase 1 — Detect (the core value)  ✅ done
- [x] `collectors/base.py` + a Suricata EVE collector + a syslog/auth collector → normalized Events
- [x] `detection/rules.py`: load Sigma rules, evaluate stream, emit Alerts with ATT&CK IDs
  (in-process Sigma-subset evaluator rather than a pySigma *backend compile* — pySigma
  targets external query languages, the wrong shape for an in-memory stream; the rule
  grammar honored is documented in the module)
- [x] `detection/anomaly.py`: IsolationForest detector; canonical flow feature pipeline
  (`features.py`); **loads a real dataset or captured baseline** (`datasets.py`,
  CIC-IDS2017 benign rows), persists the fitted model, scores live Events
- [x] Wire detectors into the ingest path (`pipeline.py`); Alerts land in store + `/alerts`
- **Accept:** ✅ replay attack + baseline through the API → the Sigma rule fires on a known
  attack (T1110) AND the anomaly detector flags an injected outlier, both visible via
  `/alerts`. (`tests/test_pipeline_e2e.py`)

## Phase 2 — Deceive (highest-signal sensor)
- [ ] `deception/base.py`: controller interface + Cowrie log adapter → Events
- [ ] OpenCanary adapter; canarytoken webhook receiver
- [ ] docker-compose service for Cowrie on an isolated network
- **Accept:** an SSH login attempt to the Cowrie container produces a normalized honeypot Event that reaches the store and auto-escalates severity.

## Phase 3 — Enrich + Correlate + Respond (gated)  🟡 in progress
- [x] `intel/enrich.py`: OTX + GreyNoise + HIBP exposure providers, cached, pluggable,
  provenance-tiered (Tier/Confidence); enriches incidents in-pipeline; inert without
  keys (never fabricates intel). (`intel/providers.py`, `tests/test_enrich.py`)
- [x] Correlation service: dedupe + time/asset grouping → Incidents (`correlation.py`;
  threshold T1110 brute-force, deception auto-escalate; `tests/test_correlation.py`)
- [x] `response/orchestrator.py`: YAML playbook runner + **approval gate** + **durable**
  audit (persisted to store, survives restart) + reversible actions (`response/`;
  `tests/test_response.py`)
- [~] Implement the 4 playbooks from PLAYBOOKS.md — **1/4 done**: brute-force
  (`playbooks/brute_force.yml`). honeypot-hit / C2-beacon / rogue-device pending.
- **Accept:** ✅ brute-force runs end-to-end via the API — alert → correlated incident →
  propose block → wait for `/approve` → simulated block recorded in audit with an undo;
  nothing destructive fires before approval (`tests/test_incidents_api.py`). (Enrichment
  step of the chain lands with item above.)

## Phase 4 — Harden + stretch (only after 0–3 ship)
- [x] Purple-team validation: ATT&CK-tagged attack samples mapped to Atomic Red Team
  refs; `make validate` (`python -m sentinel_v.validation`) replays them through the
  real pipeline and asserts the expected Alert/Incident fires, exiting non-zero on a
  gap (wired into CI). Replays samples today; running live atomics on a lab host and
  ingesting the telemetry reuses the same assertions. (`sentinel_v/validation/`,
  `validation/scenarios/`, `tests/test_validation.py`)
- [ ] Supply chain: pip-audit + SBOM (syft) + grype in CI; pin + Dependabot
- [ ] (stretch) ART adversarial testing of the anomaly detector
- [ ] (stretch) Inter-node mTLS with hybrid PQC (oqs-python) — only if multi-node
- [ ] (stretch) earned auto-response for the honeypot playbook
- **Accept:** `make validate` proves ≥N detections fire against Atomic tests; CI blocks on known-vuln deps.

## Definition of done (project-level)
A single command brings up the stack; you can point a captured attack at it and
watch it detect → enrich → propose a gated response → log an auditable incident,
with detections validated by Atomic Red Team and mapped to ATT&CK/D3FEND.
That's the demoable, resume-able artifact.
