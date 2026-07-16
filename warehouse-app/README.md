# WHSE-01 — Lumber Warehouse Inventory

AS/400-inspired mobile inventory system for a small warehouse crew, with
Stratton Warren-style requisition and cost-center workflows. Two builds live
here:

| Build | Where it runs | Best for |
|---|---|---|
| `server/` — **self-hosted server** (recommended) | Any box with Node 22+ or Docker | Real logins, real transactions, unlimited journal |
| `whse01-inventory.jsx` — **claude.ai Artifact** | Published artifact, `window.storage` | Zero-infrastructure trial run |

## The server build (`server/`)

Node + Express + SQLite (built-in `node:sqlite` — zero native dependencies).
All stock math runs server-side inside real transactions, per-user sign-on
with initials + PIN, and an unlimited audit journal.

### AS/400 heritage

- **Screen IDs** — every panel is numbered like a 5250 program: `SGN001`
  sign-on, `INQ001` stock inquiry, `JRN001` journal, `REQ001` requisitions,
  `ITM001` item entry, `CRW001` crew.
- **Fast-path command line** — the `===>` prompt at the top takes commands
  straight from a keyboard or scanner:
  - `RCV SKU QTY [REF]` — receive stock
  - `ISS SKU QTY [DEPT] [REF]` — issue to a cost center
  - `CNT SKU QTY` — post a physical count
  - `REQ SKU QTY [DEPT] [NOTE]` — raise a requisition
  - `GO STOCK / JRN / REQ / ADD / CREW` — jump between screens
  - anything else — stock search; `?` — help
- **Function keys** — `F3`=Exit, `F5`=Refresh, `F6`=New SKU, `F9`=Journal,
  `F10`=Requisitions (hint bar shows on wide screens).

### Stratton Warren heritage

- **Department / cost-center coding** — issues can be charged to a
  department (`YARD`, `SHOP`, `DELIV`, `JOBSITE`, `MAINT`, `WASTE` seeded;
  admins manage the list under CREW). The journal and CSV exports carry the
  dept on every issue, so you can see where material went.
- **Requisition queue** — any crew member raises a REQ for stock; whoever
  pulls it hits FILL, which posts a real short-checked ISS transaction
  stamped with requester, filler, dept, and `REQ#`. Only the requester or an
  admin can cancel.
- **Par-level reorder report** — `REORDER CSV` exports everything at/below
  its reorder point with a suggested buy quantity (restock to 2× reorder
  point) and estimated cost.

### Security posture

- Initials + PIN sign-on; PINs scrypt-hashed, never stored in plain text
- First run creates one admin and prints its PIN to the console **once**
- Signed httpOnly session cookies; login rate limiting (8 fails → 15 min)
- Admin vs operator roles: only admins delete SKUs, manage crew and depts
- Server-side validation on every field; movement quantities are strictly
  rejected (never silently clamped) when out of range
- Transactions guarantee no negative stock and no lost entries under
  concurrent use — verified by a test that fires 30 simultaneous issues at
  20 units and gets exactly 20 through
- CSP, nosniff, same-origin checks on mutations, no external assets

### Run it with Docker (recommended)

```bash
cd warehouse-app/server
docker compose up -d --build
docker compose logs whse01   # grab the first-run ADMIN PIN from here
```

Open `http://<host>:8080`, sign on as `ADMIN` with the printed PIN, change
the PIN under CREW, then add your crew members. Data lives in the
`whse01-data` volume — back it up like any other database.

### Run it bare

```bash
cd warehouse-app/server
npm ci
npm run build        # bundles the frontend into public/app.js
node server.js       # first run prints the ADMIN PIN
```

Requires Node **22.5+** (uses the built-in `node:sqlite`).

### Put it on the internet safely

Run it behind a TLS reverse proxy (Caddy is the least work):

```
whse.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

and set `WHSE_TRUST_PROXY=1` so session cookies are marked `Secure`.
On a shop LAN with no external access, plain HTTP is a reasonable tradeoff.

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `WHSE_DATA_DIR` | `./data` | SQLite database + session secret location |
| `WHSE_TRUST_PROXY` | `0` | Set `1` behind a TLS reverse proxy |
| `WHSE_SESSION_HOURS` | `168` | Session lifetime (7 days) |
| `WHSE_ADMIN_INITIALS` | `ADMIN` | Bootstrap admin initials |

### Tests

```bash
npm test   # 14 API tests: auth, roles, movements, reqs, rate limit, race safety
```

A Playwright browser e2e (sign-on → seed → command-line issue → journal →
requisition fill) is exercised in development; the API suite is the
committed regression net.

## The artifact build (`whse01-inventory.jsx`)

Single-file React artifact for claude.ai using shared `window.storage`.
Hardened with write-verify-retry sync, schema sanitization, operator
stamping, and CSV/JSON export — but it has no real authentication and
storage is best-effort rather than transactional. Good for trying the
workflow with the crew before standing up the server; see the header
comment in the file for details. The AS/400 command line and Stratton
Warren requisition features are server-build only.
