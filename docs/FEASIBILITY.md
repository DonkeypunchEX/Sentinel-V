# Feasibility — honest ratings

Legend: 🟢 buildable now, well-trodden · 🟡 real but non-trivial / needs care ·
🔴 stretch or research-grade, defer · ⛔ fantasy, cut it.

Effort is rough solo-dev calendar time assuming Claude Code does the typing.

| Capability (from original README) | Rating | Reality check | MVP? |
|---|---|---|---|
| Log/flow ingestion + normalization | 🟢 | Parsing Suricata EVE / Zeek / syslog is solved. Just plumbing. | **Yes** |
| Rule-based detection (Sigma) | 🟢 | `pySigma` compiles Sigma → queries. Thousands of community rules exist. | **Yes** |
| ML anomaly detection | 🟡 | Isolation Forest / autoencoder is easy to *run*, hard to make *not-noisy*. The work is feature engineering + a real baseline, not the model. Needs labeled/real data (CIC-IDS2017, or your own honeynet capture). | **Yes (v1 simple)** |
| Deception (honeypots) | 🟢 | **Do not hand-roll.** Wrap Cowrie (SSH/Telnet), OpenCanary (multi-svc), canarytokens (files/URLs). Your code = controller + log normalizer. | **Yes** |
| Attacker profiling | 🟡 | Realistic version = session clustering + TTP tagging from honeypot logs. "AI profiling" is aspirational; TTP extraction is doable. | Partial |
| Threat-intel enrichment | 🟢 | AlienVault OTX / GreyNoise / MISP have APIs + Python clients. | **Yes** |
| Alert correlation → incidents | 🟡 | Dedupe + time/asset grouping is doable; "smart" correlation is iterative. Start dumb, improve. | **Yes (basic)** |
| Automated response (SOAR-lite) | 🟡 | Playbook runner is easy; doing it *safely* (gating, reversibility, audit) is the actual engineering. This is where discipline matters most. | **Yes (gated)** |
| Real-time dashboard / API | 🟢 | FastAPI + a simple frontend or Grafana on the event store. | **Yes** |
| Supply-chain security (SBOM, pinned deps) | 🟢 | `pip-audit`, `syft`/`grype`, pinned `pyproject`, signed commits. Free hygiene. | **Yes** |
| Adversarial robustness of the ML | 🔴 | Real research area (evasion/poisoning). ART library exists but this is a Phase-4 hardening pass, not MVP. Ship detection first, harden later. | No |
| Post-quantum crypto | 🔴 | `liboqs`/`oqs-python` is real, but PQC belongs to *transport/signing* (e.g., mTLS between nodes), not "the detection engine." Scope it to inter-node comms in Phase 4. It is not a feature of a SOC; it's plumbing. | No |
| Federated learning across deployments | 🔴 | Flower is real but this only matters at multi-site scale you don't have. Cool R&D, zero MVP value solo. | No |
| "Formally verified" | ⛔ | Marketing word. Formal verification is a specialist discipline; you will not formally verify this framework. Cut the claim; keep good tests instead. | Cut |
| Autonomous / no-human response | ⛔→🟡 | Reframed: fully-autonomous destructive action is a *liability*. The feasible, valuable version is **gated** autonomy with reversibility. Keep that; drop "fully autonomous." | Reframed |

## The honest one-liner
The MVP — **ingest → detect (rules+ML) → deceive → enrich → gated response → dashboard** —
is a genuinely useful, buildable, portfolio-grade blue-team system. Everything
tagged 🔴/⛔ is what turned the original repo into vaporware. Ship the 🟢/🟡
core first; the stretch items are a *later* flex, not the foundation.
