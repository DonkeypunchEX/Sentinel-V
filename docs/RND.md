# R&D — libraries, datasets, papers per module

Everything here is real and current-ish as of the handoff. Claude Code should
verify latest versions at build time (`pip index versions <pkg>`), not trust
pins blindly.

## Collectors / telemetry
- **Suricata** (IDS/IPS) → EVE JSON is the richest single feed. Parse with stdlib `json`.
- **Zeek** (network metadata) → `conn.log`, `dns.log`, etc. `zat` (Zeek Analysis Tools) for pandas ingestion.
- **Filebeat/Vector** as optional shippers if you outgrow tailing files.
- Auth/syslog: journald / `/var/log` tailing; normalize to `Event`.

## Detection — rules
- **pySigma** (`sigma-cli`, `pysigma`) — compile Sigma rules → backend queries.
- **SigmaHQ/sigma** repo — thousands of community detection rules (ATT&CK-tagged).
- Concept: **Detection Engineering** — treat detections as code (versioned, tested).
  Read: Palantir "Alerting & Detection Strategy (ADS)" framework; Florian Roth's
  detection posts; "Detection Engineering" chapters in the SOC literature.

## Detection — ML anomaly
- **scikit-learn**: `IsolationForest`, `LocalOutlierFactor`, `OneClassSVM` for baselines.
- **PyOD** — purpose-built outlier detection library, many algorithms, clean API. Prefer this over rolling your own.
- **River** — online/streaming anomaly detection (Half-Space Trees) if you want incremental learning on a live stream.
- Autoencoder route: PyTorch, only if PyOD's models underperform on your data.
- **Datasets (for training + eval, real not synthetic):**
  - CIC-IDS2017 / CSE-CIC-IDS2018 (labeled, modern-ish attack traffic) — Canadian Institute for Cybersecurity.
  - UNSW-NB15 (labeled, good feature set).
  - NSL-KDD (classic; known-dated, use only as a smoke test, not a benchmark).
  - **Best long-term: your own honeynet capture** — real, local, no domain-shift.
- Feature engineering matters more than model choice. Flow features: bytes/pkts
  per direction, duration, inter-arrival stats, port/entropy features. Read the
  CIC feature list; CICFlowMeter generates them from pcap.
- Papers/reading: "Isolation Forest" (Liu et al. 2008); PyOD paper (Zhao et al.);
  be aware of the "anomaly detection for intrusion is oversold" critique
  (Sommer & Paxson, "Outside the Closed World", 2010) — it's the honest counterweight and tells you *why* to pair ML with rules + deception.

## Deception (highest-signal sensor — do not hand-roll)
- **Cowrie** — SSH/Telnet honeypot, mature, logs full sessions (commands, downloads).
- **OpenCanary** — lightweight multi-service (HTTP/FTP/SMB/etc.) canary.
- **canarytokens** (Thinkst, self-hostable) — honeytokens: tripwire files, URLs, AWS keys, DNS tokens.
- **T-Pot** — the "everything" honeypot platform (Docker) if you want a full sensor node fast; heavy but comprehensive.
- Your code wraps these: read their logs → normalize to `Event` → the fact that
  *anything* hit them is near-certain-malicious signal.

## Intel enrichment
- **AlienVault OTX** (`OTXv2` python client) — free, pulse/indicator lookups.
- **GreyNoise** (community API) — is this IP mass-scanning the internet? Great noise filter.
- **MISP** (`pymisp`) — if you run a MISP instance for structured intel.
- **abuse.ch** feeds (URLhaus, ThreatFox, Feodo Tracker) — free, high quality.
- Concept: **Pyramid of Pain** (David Bianco) — prioritize TTP-level detections over IOC whack-a-mole.

## Response orchestration (SOAR-lite)
- Playbooks as declarative YAML → a Python runner. No heavyweight SOAR needed for MVP.
- Actions: notify (Slack/email/webhook), block (nftables/pf rule, or push to firewall API), isolate (tag host), enrich, ticket.
- **Gating**: destructive actions enqueue an approval, wait for `/approve`. Reversibility = every block records how to undo it.
- Reference designs: TheHive + Cortex (open-source IR/SOAR) for how a mature version structures cases/observables/responders — you're building a lean cousin.

## Cross-cutting hardening (Phase 4)
- Adversarial ML: **Adversarial Robustness Toolbox (ART)** — evasion/poisoning testing of your detectors.
- PQC: **oqs-python (liboqs)** — for mTLS/signing *between Sentinel-V nodes*, not "the engine." Hybrid X25519+ML-KEM key exchange is the pragmatic move.
- Supply chain: `pip-audit`, `syft` (SBOM) + `grype` (vuln scan), pinned deps, signed commits, Dependabot.

## Purple-team / validation (prove the detections work)
- **Atomic Red Team** (Red Canary) — small, ATT&CK-mapped attack simulations you
  run against your own lab to confirm Sentinel-V actually detects them. This is
  how you get from "I wrote a detector" to "I proved it fires."
- **Caldera** (MITRE) — automated adversary emulation, heavier.
