# Playbooks & framework alignment

Sentinel-V should *speak the standard languages* so its output maps onto what
SOCs, auditors, and (relevant to your goals) intel/defense employers already
use. Alignment isn't bureaucracy here — it's what makes the project legible to
someone evaluating you.

## Governing frameworks (map the whole system to these)
- **NIST CSF 2.0** — six functions: Govern, Identify, Protect, Detect, Respond,
  Recover. Sentinel-V lives mostly in **Detect + Respond**, touches Identify
  (asset/telemetry inventory) and Recover (audit trail for post-incident). Tag
  each module with the CSF function it serves.
- **NIST SP 800-61r2** — Computer Security Incident Handling Guide. The response
  layer's lifecycle (Preparation → Detection & Analysis → Containment,
  Eradication & Recovery → Post-Incident) comes from here.
- **MITRE ATT&CK** — every detection (rule or ML alert type) gets an ATT&CK
  technique ID in its docstring/metadata. This is the detection coverage map.
- **MITRE D3FEND** — every *response/mitigation* action maps to a D3FEND
  countermeasure. It's the defensive twin of ATT&CK and most people skip it;
  using it makes the project stand out.

## Operational playbooks to implement (as YAML → runner)
Each playbook = trigger + steps + gating. Start with these four; they cover the
common homelab/small-org incident types and exercise every layer.

1. **Brute-force / credential stuffing (ATT&CK T1110)**
   - Trigger: N failed auths from one source in window, OR any Cowrie login.
   - Steps: enrich source IP (OTX/GreyNoise) → correlate with other alerts →
     [GATE] propose firewall block → notify → open incident.
   - D3FEND: Network Traffic Filtering.

2. **Honeypot interaction (any)**
   - Trigger: any Event from `deception/`.
   - Steps: auto-escalate severity (near-zero FP) → capture full session →
     enrich attacker IP → tag TTPs → [GATE optional-auto] block at perimeter.
   - This is your highest-confidence playbook; a good candidate for *earned*
     auto-response once you trust it.

3. **Suspicious outbound / C2 beacon (T1071)**
   - Trigger: ML anomaly on egress flow + intel match on destination.
   - Steps: enrich dest → check beacon periodicity → [GATE] isolate host tag →
     notify → incident. High-value, higher-FP → keep gated.

4. **New-host / rogue-device on network (T1200 / discovery)**
   - Trigger: first-seen MAC/IP on a monitored segment.
   - Steps: fingerprint → check asset inventory → notify if unknown.

## Detection engineering discipline
- Treat each detection as code: it has an owner, a hypothesis ("what attacker
  behavior does this catch?"), an ATT&CK mapping, a test (Atomic Red Team
  procedure that should trigger it), and a known-FP list.
- Use the **ADS (Alerting & Detection Strategy)** template per detection:
  Goal → Categorization (ATT&CK) → Strategy Abstract → Technical Context →
  Blind Spots → False Positives → Validation → Priority.

## Incident response loop (what Respond layer automates/assists)
PICERL / 800-61: **P**reparation, **I**dentification, **C**ontainment,
**E**radication, **R**ecovery, **L**essons-learned. Sentinel-V automates I and
assists C; it must *log enough* to support E/R/L (that's why the audit trail is
non-negotiable).

## Why this matters for your actual goal
You floated intel/defense work (DTRA, analyst track). A project that speaks
NIST CSF + ATT&CK + D3FEND + detection-engineering fluently, with a validation
story (Atomic Red Team proving detections fire), is a far stronger signal to
that world than any single tool. Build it framework-aligned from day one so the
resume line writes itself.
