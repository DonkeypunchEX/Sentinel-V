# Sentinel-V — Claude Code Operating Brief

You are picking up an early-stage **defensive** cyber-security framework. This
file is your contract. Read it, then read `docs/ROADMAP.md` and work the phases
in order. Do not freestyle architecture — it's already decided in `docs/`.

## What this project is
Sentinel-V is a self-hostable **blue-team automation framework**: it ingests
security telemetry, detects threats (rules + ML anomaly detection), runs
deception (honeypots/honeytokens), and orchestrates **gated** automated
response. Think "SOAR-lite + detection engine + honeynet controller" for a
homelab / small-org SOC.

## What this project is NOT (hard scope guards)
- **Not offensive.** No exploit code, no C2, no malware, no scanning/attacking
  third-party infrastructure. Deception components are defensive (they wait to
  be attacked; they do not attack). If a task drifts offensive, stop and flag.
- **Not autonomous-destructive.** Any response action that blocks, isolates, or
  kills a process/host is **human-in-the-loop by default** (see
  `response/orchestrator.py`). Fully-auto actions are opt-in per-playbook and
  must be reversible + logged.
- **Not a buzzword generator.** The original README claimed "quantum-resistant,
  federated, formally-verified." Those are Phase 4 *stretch* items, clearly
  scoped in `docs/FEASIBILITY.md`. Do not scaffold them into the MVP.

## Quality bar (this is why the previous stub was scrapped)
- Real libraries, real data paths. **No models trained on `np.random`.** If a
  module needs data it doesn't have yet, it takes a `Path`/dataset injection and
  raises clearly when unset — it does not fake it.
- No dead crypto. No `RSAKey.generate(1024)`. Use vetted libs; never hand-roll.
- Typed (`from __future__ import annotations`, real type hints), `ruff` +
  `mypy` clean, `pytest` for every module you implement.
- Config-driven (`config/sentinel.example.yaml` → pydantic settings), no
  hard-coded hosts/ports/paths in logic.
- Every module you build gets: a docstring stating its ATT&CK/D3FEND mapping, a
  test, and an entry in the README feature table with an honest status.

## How to work
1. `make setup` (creates venv, installs dev deps).
2. Pick the lowest unchecked item in `docs/ROADMAP.md`.
3. Implement against the interface already stubbed in `sentinel_v/`. Interfaces
   (ABCs) are contracts — extend, don't rewrite, unless ROADMAP says to.
4. Write the test first or alongside. `make test` must stay green.
5. Update README status + ROADMAP checkbox. Commit small.

## Commands
- `make setup` — venv + editable install + dev deps
- `make test` — pytest
- `make lint` — ruff + mypy
- `make run` — launch the FastAPI control plane (dev)
- `docker compose up` — full stack (api + store) for integration testing

## Ground truth docs (read before coding)
- `docs/ARCHITECTURE.md` — module map + data flow
- `docs/FEASIBILITY.md` — what's MVP-real vs stretch vs fantasy, with ratings
- `docs/ROADMAP.md` — phased build plan + acceptance criteria (**your worklist**)
- `docs/RND.md` — the actual libraries/papers/datasets per module
- `docs/PLAYBOOKS.md` — NIST/MITRE alignment + detection & IR playbooks
- `docs/HARDWARE.md` — the physical testbed this is meant to run on
