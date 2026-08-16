# Hardware — the testbed Sentinel-V runs on

You don't need a datacenter. You need an isolated segment, a place to run the
control plane, and sacrificial nodes for deception. Budget-tiered below.

## Minimum viable lab (~$0–150, use what you have)
- **Control node**: any x86 box with 16GB RAM you already own (your Fedora
  machine works). Runs the API + event store + detectors in containers.
- **Network visibility**: if your router supports it, mirror a port; otherwise
  run Suricata/Zeek on the control node watching its own interface. Software-only
  to start.
- **Deception**: Cowrie + OpenCanary in Docker on the same box, bound to a
  separate Docker network. Zero extra hardware.
- Verdict: this gets you through Phases 0–2. Start here. Don't buy anything yet.

## Recommended lab (~$200–400, the real testbed)
- **Dedicated SOC node**: used mini PC — Intel N100 / N305 mini (Beelink/GMKtec,
  ~$150–250 new) or a used Dell OptiPlex/Lenovo Tiny (i5-8500T, 16–32GB,
  ~$100–180 used). Runs Proxmox → VMs for control plane, sensors, honeypots,
  all isolated.
- **Managed switch w/ port mirroring (SPAN)**: TP-Link TL-SG108E or Netgear
  GS308E (~$30–45) — cheap, does VLANs + mirroring so your IDS actually sees
  traffic. Step up to a MikroTik hEX/CRS (~$60–120) if you want real routing/VLAN
  segmentation for the honeynet.
- **Sensor/honeypot node**: Raspberry Pi 4/5 (4–8GB) on an isolated VLAN running
  T-Pot-lite or OpenCanary — your "in the DMZ getting shot at" box, physically
  separate from the control node.
- **Segmentation is the point**: honeypots live on a VLAN that can talk *out* to
  the internet but **not** into your real LAN. If an attacker owns the honeypot,
  they're in a box, not your network.

## ML / compute reality check
- Isolation Forest / PyOD / River on flow features → **CPU is plenty.** No GPU
  needed for the MVP. Don't buy a GPU for this.
- If you later go autoencoder/deep on large pcap, a used GTX 1660 / RTX 3060
  (12GB) is the cheap-but-real tier — but that's Phase 3+, and probably never
  necessary. Resist the urge.

## Storage
- Dev: SQLite on an SSD. Prod-ish: Postgres (metadata) + OpenSearch/Elasticsearch
  (event search) or just Postgres + timescale if you want to stay lean. A
  256–512GB SSD on the SOC node holds a lot of normalized events.

## What NOT to buy
- No enterprise firewall, no rackmount server, no GPU, no commercial threat
  feeds. All optional, none MVP. The whole value here is proving you can build
  the capability on prosumer gear — which is *more* impressive, not less.

## Networking hygiene for the lab
- Put the honeynet on its own VLAN + firewall rules (egress-only).
- Never expose the control plane API to the internet. VPN (WireGuard) in.
- Snapshot honeypot VMs so you can revert after they get owned.
