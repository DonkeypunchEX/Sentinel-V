# WHSE-01 — Lumber Warehouse Inventory (Hardened)

AS/400-inspired mobile inventory app for a small warehouse crew. One shared
stock file and transaction journal; every phone sees the same numbers.

`whse01-inventory.jsx` is the complete app — a single React component built to
run as a **claude.ai Artifact** using the `window.storage` API (shared
key-value storage scoped to the published artifact).

## Deploying to your crew

1. Open [claude.ai](https://claude.ai), start a chat, and paste the contents of
   `whse01-inventory.jsx` asking Claude to create it as a React artifact
   (or update your existing WHSE-01 artifact with this code).
2. Publish the artifact and share the link with your crew. If your team is on
   a Claude Team/Enterprise plan, share it within the organization so only
   coworkers can open it.
3. Each person opens the link on their phone and signs on with their initials
   the first time. Add to home screen for one-tap access.

That's the whole deployment — no server, no build step. `window.storage` with
the shared flag is what makes every device see the same stock file.

## What "hardened" means in this build

| Area | Protection |
|---|---|
| Concurrent edits | Every posting re-reads the shared file, applies the change, writes, then **reads back to verify** it wasn't clobbered. A lost race retries on the fresher copy (3 attempts) instead of silently dropping a coworker's entry. |
| Stale screens | Devices poll the shared file every 12 s (when visible) so stock levels converge without manual refresh. |
| Accountability | Operator sign-on (initials per device); every journal entry is stamped with who posted it. |
| Corrupt data | Everything read from storage is schema-sanitized: bad JSON, truncated blobs, wrong types, duplicate SKUs, and out-of-range numbers are normalized before they can crash a phone or poison a write. |
| Input abuse | Length limits and numeric clamps on every field (qty capped at 999,999; SKU restricted to `A-Z 0-9 -`). |
| Render crashes | Error boundary shows a recover screen instead of a blank page; stock data is unaffected. |
| Data loss | One-tap CSV export of stock and journal, plus full JSON backup, from the JOURNAL tab. Journal keeps the last 500 entries — export regularly. |
| Seed wipe | "Load sample stock" refuses to run if the shared file already has items (stale phone can't wipe real inventory). |
| Storage outage | Write failures switch the device to LOCAL ONLY with a visible retry button instead of silently losing entries. |
| Network deps | No external fonts/scripts — system fonts only, works under a strict CSP. |

## Known limits — read before relying on it

- **No real authentication.** Anyone with the artifact link (and, on a team
  plan, org access) can post transactions under any initials. The journal is
  an honor-system audit trail, not a security control.
- **Not transactional.** The write-verify-retry loop makes lost updates rare,
  not impossible. Two devices posting the same SKU in the same second can
  still race; the journal will show both entries, so discrepancies are
  auditable and fixable with a COUNT.
- **Journal is capped** at 500 entries. Export the CSV weekly (or daily on a
  busy yard) if you need permanent records.
- **This is a crew convenience tool, not a system of record.** If the numbers
  drive purchasing or accounting, treat the CSV exports as the record and
  reconcile with physical counts.

If you outgrow these limits, the next step is a small real backend
(e.g. Postgres + a few endpoints) with per-user logins — the UI here ports
over largely unchanged.

## Verifying changes

The component parses with esbuild and the sanitizer/CSV helpers are
unit-testable by appending an export line:

```bash
npx esbuild whse01-inventory.jsx --loader:.jsx=jsx --outfile=/dev/null
```
