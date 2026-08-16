# Architecture

Sentinel-V is a pipeline, not a monolith. Telemetry flows left→right; the
control plane (API) sits across the top; everything is event-driven around a
single normalized `Event` schema (`sentinel_v/models.py`).

```
                    ┌───────────────────────── Control Plane (FastAPI) ─────────────────────────┐
                    │   /events  /alerts  /playbooks  /approve  /metrics  /health               │
                    └───────────────┬───────────────────────────────────────────────┬──────────┘
                                    │                                                 │
  sources                collectors │            detection            correlation    │   response
 ─────────              ───────────▼──         ──────────────        ────────────    ▼  ──────────────
 Suricata EVE ─┐                              ┌ rules.py (Sigma) ─┐               ┌ orchestrator.py ─┐
 Zeek conn.log ┼─► collectors/*  ─► Event ─►  ┤                   ├─► Alert ─►    │  playbook runner │
 auth/syslog   ┤     (normalize)              └ anomaly.py (ML) ──┘  enrich +     │  human-in-loop   │
 honeypot logs ┘                                                     dedupe/corr  │  gate + actions  │
                                    ▲                                             └────────┬─────────┘
                          deception │ (emits Event on interaction)                          │ actions
                         ───────────┴───                                          ┌─────────▼─────────┐
                          deception/base.py                                       │ notify / block /  │
                          (Cowrie / OpenCanary / honeytokens)                     │ isolate (gated)   │
                                                                                  └───────────────────┘

  intel/enrich.py  ── enriches Events/Alerts with OTX/MISP/GreyNoise context (out-of-band)
  storage          ── SQLite (dev) → Postgres/OpenSearch (prod); event + alert + audit tables
```

## Components
| Layer | Module | Responsibility |
|---|---|---|
| Collectors | `collectors/` | Tail/subscribe to a source, normalize to `Event`. One collector per source type. |
| Detection (rules) | `detection/rules.py` | Deterministic signatures. Load Sigma rules, evaluate against `Event` stream. High precision, ATT&CK-tagged. |
| Detection (ML) | `detection/anomaly.py` | Unsupervised anomaly detection on engineered features. Flags the unknown-unknowns rules miss. Trained on **real** baseline traffic. |
| Deception | `deception/` | Controller for honeypots/honeytokens. Does not implement a honeypot from scratch — wraps Cowrie / OpenCanary / canarytokens and normalizes their hits into `Event`s (highest-fidelity signal in the system). |
| Intel | `intel/enrich.py` | Enrich indicators (IP/domain/hash) with threat-intel context. Pluggable providers. |
| Correlation | (in API/service layer) | Dedupe, group related alerts into incidents, apply enrichment, score severity. |
| Response | `response/orchestrator.py` | Execute playbooks. Every destructive action passes an approval gate unless the playbook is explicitly marked `auto` + `reversible`. Full audit log. |
| Control plane | `api/app.py` | FastAPI: ingest, query, approve responses, expose metrics/health. |

## Core schema (single source of truth)
Everything normalizes to `Event` → detection emits `Alert` → correlation groups
into `Incident` → response consumes `Incident`. Defined in
`sentinel_v/models.py`. Keep it stable; changing it ripples through every layer.

## Design principles
1. **Deception is your best sensor.** Nobody legitimate touches a honeypot, so
   its false-positive rate is ~0. Weight it accordingly in correlation.
2. **Rules for the known, ML for the unknown.** They cover different failure
   modes; ship both, don't pick.
3. **Reversible + gated response.** Autonomy is earned per-playbook, never
   assumed. A blue tool that can brick your own network on a false positive is
   a liability, not a feature.
4. **Everything is an Event.** One schema means new sources are cheap and
   correlation is uniform.
