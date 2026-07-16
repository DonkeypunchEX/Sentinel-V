# WHSE-01 — Lumber Warehouse Inventory

AS/400-inspired mobile inventory system for a small warehouse crew, with
Stratton Warren-style requisition and cost-center workflows. Everything
lives in `server/`: Node + Express + SQLite (built-in `node:sqlite` — the
only dependency is express itself). All stock math runs server-side inside
real transactions, sign-on is per-user, and the audit journal is unlimited.

## Deploy it (Docker, recommended)

```bash
cd warehouse-app/server
docker compose up -d --build
docker compose logs whse01   # grab the one-time ADMIN PIN from here
```

Open `http://<host>:8080`, sign on as `ADMIN` with the printed PIN, change
the PIN under CREW, then add your crew members (each gets initials + a PIN).
Phones: add to home screen for one-tap access. Data lives in the
`whse01-data` volume — back it up like any other database, or use the
admin BACKUP export on the JRN screen.

### Or run it bare

```bash
cd warehouse-app/server
npm ci && npm run build && node server.js   # needs Node 22.5+
```

### Putting it on the internet

Run behind a TLS reverse proxy (Caddy is the least work):

```
whse.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

and set `WHSE_TRUST_PROXY=1` so cookies are marked `Secure` and HSTS is
sent. On a shop LAN with no outside access, plain HTTP is a fair tradeoff.

## Using it

### AS/400 heritage

- **Screen IDs** — every panel is numbered like a 5250 program: `SGN001`
  sign-on, `INQ001` stock inquiry, `JRN001` journal, `REQ001` requisitions,
  `ITM001` item entry, `CRW001` crew.
- **Fast-path command line** — the `===>` prompt takes commands straight
  from a keyboard or scanner:
  - `RCV SKU QTY [REF]` — receive stock
  - `ISS SKU QTY [DEPT] [REF]` — issue to a cost center
  - `CNT SKU QTY` — post a physical count
  - `REQ SKU QTY [DEPT] [NOTE]` — raise a requisition
  - `GO STOCK / JRN / REQ / ADD / CREW` — jump screens
  - anything else — stock search; `?` — help
- **Function keys** — `F3`=Exit, `F5`=Refresh, `F6`=New SKU, `F9`=Journal,
  `F10`=Requisitions.

### Stratton Warren heritage

- **Department / cost-center coding** — issues are charged to a department
  (`YARD`, `SHOP`, `DELIV`, `JOBSITE`, `MAINT`, `WASTE` seeded; admins
  manage the list under CREW). Journal and exports show where material went.
- **Requisition queue** — crew raises a REQ; whoever pulls it hits FILL,
  which posts a short-checked ISS stamped with requester, filler, dept, and
  `REQ#`. Only the requester or an admin can cancel.
- **Par-level reorder report** — `REORDER CSV` lists everything at/below
  reorder point with suggested buy quantities and estimated cost.

## Security posture

- Initials + PIN sign-on; PINs scrypt-hashed, never stored or exported
- First run creates one admin and prints its PIN to the console **once**
- Signed httpOnly session cookies; changing or resetting a PIN revokes
  every outstanding session for that user immediately
- Login rate limiting (8 failures → 15-minute lockout)
- Admin vs operator roles: only admins delete SKUs, manage crew/depts,
  or pull the full backup
- Server-side validation everywhere; out-of-range movement quantities are
  rejected, never silently clamped
- SQLite transactions guarantee no negative stock and no lost entries under
  concurrent use — regression-tested by firing 30 simultaneous issues at
  20 units and getting exactly 20 through
- CSP, nosniff, HSTS (behind TLS), same-origin checks on mutations, no
  external assets, request body caps

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `WHSE_DATA_DIR` | `./data` | SQLite database + session secret location |
| `WHSE_TRUST_PROXY` | `0` | Set `1` behind a TLS reverse proxy |
| `WHSE_SESSION_HOURS` | `168` | Session lifetime (7 days) |
| `WHSE_ADMIN_INITIALS` | `ADMIN` | Bootstrap admin initials |

## Tests

```bash
npm test   # 16 API tests: auth, roles, movements, reqs, session
           # revocation, rate limiting, exports, race safety
```

A Playwright browser e2e (sign-on → seed → command-line issue → journal →
requisition fill) is exercised in development; the API suite is the
committed regression net.

## History

An earlier single-file claude.ai Artifact build (`whse01-inventory.jsx`,
shared `window.storage`, no real auth) was removed once this server build
superseded it — recover it from git history if you ever want the
zero-infrastructure trial version.
