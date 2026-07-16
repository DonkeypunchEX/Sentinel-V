"use strict";
/* ============================================================
   WHSE-01 server — real backend for the warehouse inventory app.

   - SQLite (built-in node:sqlite) with true transactions
   - Per-user login: crew initials + numeric PIN (scrypt-hashed)
   - Signed httpOnly session cookies, login rate limiting
   - All stock math happens server-side inside transactions;
     the client can never write a negative balance or race a
     coworker's entry
   - Unlimited journal with CSV export
   ============================================================ */

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { openDb, inTransaction } = require("./db");

/* ---------- config ---------- */
const PORT = Number(process.env.PORT) || 8080;
const DATA_DIR = process.env.WHSE_DATA_DIR || path.join(__dirname, "data");
const TRUST_PROXY = process.env.WHSE_TRUST_PROXY === "1";
const SESSION_HOURS = Number(process.env.WHSE_SESSION_HOURS) || 168; // 7 days
const ADMIN_INITIALS = (process.env.WHSE_ADMIN_INITIALS || "ADMIN").toUpperCase();

const MAX_QTY = 999999;
const LEN = { sku: 32, desc: 80, bin: 12, ref: 40, note: 60, op: 6, name: 40, dept: 8 };
const CATS = ["Dimensional", "Treated", "Sheet Goods", "Drywall", "Doors", "Trim", "Siding", "Hardware"];
const UNITS = ["PC", "SHT", "EA", "LF", "BF", "BDL", "BX"];
const SKU_RE = /^[A-Z0-9][A-Z0-9-]{1,31}$/;
const INITIALS_RE = /^[A-Z0-9]{2,6}$/;
const PIN_RE = /^[0-9]{4,8}$/;
const DEPT_RE = /^[A-Z0-9]{2,8}$/;

const db = openDb(DATA_DIR);

/* ---------- input scrubbing ---------- */
const cleanStr = (s, max) =>
  String(s ?? "").replace(/[\u0000-\u001F\u007F]/g, "").slice(0, max).trim();
const cleanInt = (n, min, max) => {
  const v = Math.trunc(Number(n));
  return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : NaN;
};
const cleanMoney = (n) => {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return 0;
  return Math.min(9999999, Math.round(v * 100) / 100);
};
/* movement quantities are strict: out-of-range means the operator
   fat-fingered it — reject, never silently clamp a stock posting */
const strictQty = (n, min, max) => {
  const v = Number(n);
  return Number.isInteger(v) && v >= min && v <= max ? v : NaN;
};

/* ---------- PIN hashing (scrypt, built-in) ---------- */
function hashPin(pin) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pin, salt, 32, { N: 16384, r: 8, p: 1 });
  return `s1:${salt.toString("hex")}:${key.toString("hex")}`;
}
function verifyPin(pin, stored) {
  const [v, saltHex, keyHex] = String(stored).split(":");
  if (v !== "s1" || !saltHex || !keyHex) return false;
  const key = crypto.scryptSync(pin, Buffer.from(saltHex, "hex"), 32, { N: 16384, r: 8, p: 1 });
  const expect = Buffer.from(keyHex, "hex");
  return key.length === expect.length && crypto.timingSafeEqual(key, expect);
}

/* ---------- session tokens: uid.exp.hmac ---------- */
const secretPath = path.join(DATA_DIR, "session-secret");
let SECRET;
if (fs.existsSync(secretPath)) {
  SECRET = fs.readFileSync(secretPath);
} else {
  SECRET = crypto.randomBytes(32);
  fs.writeFileSync(secretPath, SECRET, { mode: 0o600 });
}
/* token: uid.tokver.exp.hmac — tokver is the user's session generation;
   bumping it in the DB (PIN change/reset) revokes every outstanding token */
const sign = (s) => crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
function makeToken(uid, tokver) {
  const body = `${uid}.${tokver}.${Date.now() + SESSION_HOURS * 3600 * 1000}`;
  return `${body}.${sign(body)}`;
}
function parseToken(tok) {
  const parts = String(tok || "").split(".");
  if (parts.length !== 4) return null;
  const body = `${parts[0]}.${parts[1]}.${parts[2]}`;
  const mac = sign(body);
  if (mac.length !== parts[3].length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(parts[3]))) return null;
  if (Number(parts[2]) < Date.now()) return null;
  return { uid: Number(parts[0]), tokver: Number(parts[1]) };
}

/* ---------- login rate limiting (in-memory) ---------- */
const attempts = new Map(); // key -> {count, until}
const MAX_FAILS = 8;
const LOCK_MS = 15 * 60 * 1000;
function loginBlocked(key) {
  const a = attempts.get(key);
  if (!a) return false;
  if (Date.now() >= a.until) {
    /* lock expired — clear the stale count so one new failure
       doesn't instantly re-lock */
    attempts.delete(key);
    return false;
  }
  return a.count >= MAX_FAILS;
}
function loginFailed(key) {
  const a = attempts.get(key) || { count: 0, until: 0 };
  a.count += 1;
  a.until = Date.now() + LOCK_MS;
  attempts.set(key, a);
}
function loginOk(key) {
  attempts.delete(key);
}
setInterval(() => {
  const t = Date.now();
  for (const [k, a] of attempts) if (t > a.until) attempts.delete(k);
}, 60 * 1000).unref();

/* ---------- bootstrap admin ---------- */
(function bootstrap() {
  const n = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
  if (n > 0) return;
  /* prefer WHSE_ADMIN_PIN so the credential never touches process logs;
     fall back to a random PIN printed once for zero-config first runs */
  const envPin = process.env.WHSE_ADMIN_PIN || "";
  const usingEnv = PIN_RE.test(envPin);
  const pin = usingEnv ? envPin : String(crypto.randomInt(0, 100000000)).padStart(8, "0");
  db.prepare("INSERT INTO users (initials, name, pin_hash, role, created_at) VALUES (?,?,?,?,?)")
    .run(ADMIN_INITIALS, "Administrator", hashPin(pin), "admin", Date.now());
  console.log("==============================================");
  console.log(`  FIRST RUN — admin account created`);
  console.log(`  Initials: ${ADMIN_INITIALS}`);
  if (usingEnv) {
    console.log("  PIN:      from WHSE_ADMIN_PIN (not logged)");
  } else {
    console.log(`  PIN:      ${pin}`);
    console.log("  Set WHSE_ADMIN_PIN to keep this out of logs.");
  }
  console.log(`  Sign in and change it under CREW right away.`);
  console.log("==============================================");
})();

/* ---------- app ---------- */
const app = express();
if (TRUST_PROXY) app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));

app.use((req, res, next) => {
  res.set({
    "Content-Security-Policy":
      "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": req.path.startsWith("/api/") ? "no-store" : "no-cache",
  });
  if (TRUST_PROXY && req.secure) {
    res.set("Strict-Transport-Security", "max-age=31536000");
  }
  next();
});

/* same-origin check on mutating requests (belt on top of SameSite) */
app.use((req, res, next) => {
  if (!["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next(); // curl / same-origin fetch without Origin
  const host = req.headers.host;
  try {
    if (new URL(origin).host !== host) return res.status(403).json({ error: "CROSS-ORIGIN REQUEST BLOCKED" });
  } catch (_) {
    return res.status(403).json({ error: "BAD ORIGIN" });
  }
  next();
});

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}
function setSession(req, res, user) {
  const secure = TRUST_PROXY ? req.secure : false;
  res.set("Set-Cookie",
    `whse_sid=${makeToken(user.id, user.tok)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}${secure ? "; Secure" : ""}`);
}
function clearSession(res) {
  res.set("Set-Cookie", "whse_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

const getUser = db.prepare("SELECT id, initials, name, role, active, tok FROM users WHERE id = ?");
function auth(req, res, next) {
  const t = parseToken(getCookie(req, "whse_sid"));
  const user = t ? getUser.get(t.uid) : null;
  if (!user || !user.active || user.tok !== t.tokver) return res.status(401).json({ error: "SIGN-ON REQUIRED" });
  req.user = user;
  next();
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "ADMIN ONLY" });
  next();
}

const findItem = db.prepare("SELECT * FROM items WHERE sku = ?");
const insertTx = db.prepare(
  "INSERT INTO tx (ts, code, sku, qty, bal, unit, ref, note, by, dept) VALUES (?,?,?,?,?,?,?,?,?,?)");
function postTx(code, item, delta, ref, note, by, dept) {
  insertTx.run(Date.now(), code, item.sku, delta, item.qty, item.unit, ref || "", note || "", by || "", dept || "");
}

/* SWS-style cost center: optional on an issue, but if given it must be
   a real, active department code. */
function checkDept(body) {
  const dept = cleanStr(body?.dept, LEN.dept).toUpperCase();
  if (!dept) return { dept: "" };
  if (!DEPT_RE.test(dept)) return { error: "BAD DEPT CODE" };
  const row = db.prepare("SELECT code FROM depts WHERE code = ? AND active = 1").get(dept);
  if (!row) return { error: `DEPT ${dept} NOT ON FILE` };
  return { dept };
}

/* ---------- routes ---------- */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/login", (req, res) => {
  const initials = cleanStr(req.body?.initials, LEN.op).toUpperCase();
  const pin = String(req.body?.pin ?? "");
  if (!INITIALS_RE.test(initials) || !PIN_RE.test(pin)) {
    return res.status(400).json({ error: "BAD INITIALS OR PIN FORMAT" });
  }
  const key = `${req.ip}|${initials}`;
  if (loginBlocked(key)) return res.status(429).json({ error: "TOO MANY ATTEMPTS — WAIT 15 MIN" });
  const user = db.prepare("SELECT * FROM users WHERE initials = ?").get(initials);
  if (!user || !user.active || !verifyPin(pin, user.pin_hash)) {
    loginFailed(key);
    return res.status(401).json({ error: "SIGN-ON FAILED" });
  }
  loginOk(key);
  setSession(req, res, user);
  res.json({ user: { initials: user.initials, name: user.name, role: user.role } });
});

app.post("/api/logout", (_req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: { initials: req.user.initials, name: req.user.name, role: req.user.role } });
});

app.post("/api/me/pin", auth, (req, res) => {
  const oldPin = String(req.body?.oldPin ?? "");
  const newPin = String(req.body?.newPin ?? "");
  if (!PIN_RE.test(newPin)) return res.status(400).json({ error: "NEW PIN MUST BE 4–8 DIGITS" });
  const u = db.prepare("SELECT pin_hash FROM users WHERE id = ?").get(req.user.id);
  if (!verifyPin(oldPin, u.pin_hash)) return res.status(401).json({ error: "CURRENT PIN WRONG" });
  /* bump the token version to revoke every outstanding session for this
     user, then hand this device a fresh cookie so it stays signed on */
  db.prepare("UPDATE users SET pin_hash = ?, tok = tok + 1 WHERE id = ?").run(hashPin(newPin), req.user.id);
  setSession(req, res, { id: req.user.id, tok: req.user.tok + 1 });
  res.json({ ok: true });
});

app.get("/api/state", auth, (_req, res) => {
  const items = db.prepare("SELECT * FROM items ORDER BY sku").all();
  const tx = db.prepare("SELECT * FROM tx ORDER BY id DESC LIMIT 200").all();
  const depts = db.prepare("SELECT code, name FROM depts WHERE active = 1 ORDER BY code").all();
  const reqs = db.prepare(
    "SELECT * FROM reqs WHERE status = 'OPEN' OR ts > ? ORDER BY (status = 'OPEN') DESC, id DESC LIMIT 100")
    .all(Date.now() - 7 * 24 * 3600 * 1000);
  res.json({ items, tx, depts, reqs, now: Date.now() });
});

function movement(req, res, code) {
  const sku = cleanStr(req.body?.sku, LEN.sku).toUpperCase();
  const qty = strictQty(req.body?.qty, 1, MAX_QTY);
  const ref = cleanStr(req.body?.ref, LEN.ref);
  if (!SKU_RE.test(sku)) return res.status(400).json({ error: "BAD SKU" });
  if (!Number.isInteger(qty)) return res.status(400).json({ error: "BAD QUANTITY" });
  const d = code === "ISS" ? checkDept(req.body) : { dept: "" };
  if (d.error) return res.status(400).json({ error: d.error });
  try {
    const out = inTransaction(db, () => {
      const it = findItem.get(sku);
      if (!it) return { status: 404, error: `SKU ${sku} NOT ON FILE` };
      if (code === "ISS" && qty > it.qty) {
        return { status: 409, error: `SHORT — only ${it.qty} ${it.unit} on hand` };
      }
      if (code === "RCV" && it.qty + qty > MAX_QTY) {
        return { status: 409, error: `OVER MAX — balance cannot exceed ${MAX_QTY}` };
      }
      const delta = code === "RCV" ? qty : -qty;
      it.qty += delta;
      db.prepare("UPDATE items SET qty = ?, updated_at = ? WHERE sku = ?").run(it.qty, Date.now(), sku);
      postTx(code, it, delta, ref, "", req.user.initials, d.dept);
      return { item: it };
    });
    if (out.error) return res.status(out.status).json({ error: out.error });
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: "POSTING FAILED — TRY AGAIN" });
  }
}
app.post("/api/receive", auth, (req, res) => movement(req, res, "RCV"));
app.post("/api/issue", auth, (req, res) => movement(req, res, "ISS"));

app.post("/api/count", auth, (req, res) => {
  const sku = cleanStr(req.body?.sku, LEN.sku).toUpperCase();
  const exact = strictQty(req.body?.exact, 0, MAX_QTY);
  const ref = cleanStr(req.body?.ref, LEN.ref);
  if (!SKU_RE.test(sku)) return res.status(400).json({ error: "BAD SKU" });
  if (!Number.isInteger(exact)) return res.status(400).json({ error: "BAD COUNT" });
  const out = inTransaction(db, () => {
    const it = findItem.get(sku);
    if (!it) return { status: 404, error: `SKU ${sku} NOT ON FILE` };
    const delta = exact - it.qty;
    it.qty = exact;
    db.prepare("UPDATE items SET qty = ?, updated_at = ? WHERE sku = ?").run(exact, Date.now(), sku);
    postTx("ADJ", it, delta, ref, "cycle count", req.user.initials);
    return { item: it, delta };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

function scrubItemBody(b, forCreate) {
  const item = {
    sku: cleanStr(b?.sku, LEN.sku).toUpperCase(),
    desc: cleanStr(b?.desc, LEN.desc),
    cat: CATS.includes(b?.cat) ? b.cat : "Hardware",
    unit: UNITS.includes(b?.unit) ? b.unit : "EA",
    bin: cleanStr(b?.bin, LEN.bin).toUpperCase() || "—",
    reorder: cleanInt(b?.reorder, 0, MAX_QTY) || 0,
    cost: cleanMoney(b?.cost),
  };
  if (forCreate) item.qty = cleanInt(b?.qty, 0, MAX_QTY) || 0;
  return item;
}

app.post("/api/items", auth, (req, res) => {
  const it = scrubItemBody(req.body, true);
  if (!SKU_RE.test(it.sku)) return res.status(400).json({ error: "SKU: 2–32 chars, A–Z 0–9 dashes" });
  if (!it.desc) return res.status(400).json({ error: "DESCRIPTION REQUIRED" });
  const out = inTransaction(db, () => {
    if (findItem.get(it.sku)) return { status: 409, error: `SKU ${it.sku} already exists` };
    db.prepare(
      "INSERT INTO items (sku, desc, cat, unit, bin, qty, reorder, cost, updated_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(it.sku, it.desc, it.cat, it.unit, it.bin, it.qty, it.reorder, it.cost, Date.now());
    postTx("NEW", it, it.qty, "", "item created", req.user.initials);
    return { item: it };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

app.patch("/api/items/:sku", auth, (req, res) => {
  const sku = cleanStr(req.params.sku, LEN.sku).toUpperCase();
  const out = inTransaction(db, () => {
    const it = findItem.get(sku);
    if (!it) return { status: 404, error: `SKU ${sku} NOT ON FILE` };
    /* merge the stored item first so omitted fields keep their values */
    const p = scrubItemBody({ ...it, ...req.body, sku }, false);
    if (!p.desc) return { status: 400, error: "DESCRIPTION REQUIRED" };
    db.prepare("UPDATE items SET desc=?, cat=?, unit=?, bin=?, reorder=?, cost=?, updated_at=? WHERE sku=?")
      .run(p.desc, p.cat, p.unit, p.bin, p.reorder, p.cost, Date.now(), sku);
    return { item: { ...it, ...p } };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

app.delete("/api/items/:sku", auth, adminOnly, (req, res) => {
  const sku = cleanStr(req.params.sku, LEN.sku).toUpperCase();
  const out = inTransaction(db, () => {
    const it = findItem.get(sku);
    if (!it) return { status: 404, error: `SKU ${sku} NOT ON FILE` };
    db.prepare("DELETE FROM items WHERE sku = ?").run(sku);
    postTx("DEL", { ...it, qty: 0 }, -it.qty, "", "item removed", req.user.initials);
    return { ok: true };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

app.post("/api/seed", auth, (req, res) => {
  const SEED = require("./seed.json");
  const out = inTransaction(db, () => {
    const n = db.prepare("SELECT COUNT(*) AS c FROM items").get().c;
    if (n > 0) return { status: 409, error: "FILE NOT EMPTY — crew already has stock on file" };
    const ins = db.prepare(
      "INSERT INTO items (sku, desc, cat, unit, bin, qty, reorder, cost, updated_at) VALUES (?,?,?,?,?,?,?,?,?)");
    for (const it of SEED) {
      ins.run(it.sku, it.desc, it.cat, it.unit, it.bin, it.qty, it.reorder, it.cost, Date.now());
      postTx("NEW", it, it.qty, "", "opening stock", req.user.initials);
    }
    return { ok: true };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

/* ---------- requisitions (Stratton Warren-style) ----------
   Any crew member can raise a REQ for stock. Filling one posts a
   real ISS transaction (transactional, short-checked) and stamps
   the journal with REQ#, department, requester, and filler. */
app.post("/api/reqs", auth, (req, res) => {
  const sku = cleanStr(req.body?.sku, LEN.sku).toUpperCase();
  const qty = strictQty(req.body?.qty, 1, MAX_QTY);
  const note = cleanStr(req.body?.note, LEN.note);
  if (!SKU_RE.test(sku)) return res.status(400).json({ error: "BAD SKU" });
  if (!Number.isInteger(qty)) return res.status(400).json({ error: "BAD QUANTITY" });
  const d = checkDept(req.body);
  if (d.error) return res.status(400).json({ error: d.error });
  if (!findItem.get(sku)) return res.status(404).json({ error: `SKU ${sku} NOT ON FILE` });
  const r = db.prepare("INSERT INTO reqs (ts, sku, qty, dept, note, by) VALUES (?,?,?,?,?,?)")
    .run(Date.now(), sku, qty, d.dept, note, req.user.initials);
  res.json({ req: { id: Number(r.lastInsertRowid), sku, qty, dept: d.dept, note, by: req.user.initials, status: "OPEN" } });
});

app.post("/api/reqs/:id/fill", auth, (req, res) => {
  const id = Number(req.params.id);
  const out = inTransaction(db, () => {
    const r = db.prepare("SELECT * FROM reqs WHERE id = ?").get(id);
    if (!r) return { status: 404, error: "REQ NOT FOUND" };
    if (r.status !== "OPEN") return { status: 409, error: `REQ #${id} ALREADY ${r.status}` };
    const it = findItem.get(r.sku);
    if (!it) return { status: 404, error: `SKU ${r.sku} NO LONGER ON FILE` };
    if (r.qty > it.qty) return { status: 409, error: `SHORT — only ${it.qty} ${it.unit} on hand` };
    it.qty -= r.qty;
    db.prepare("UPDATE items SET qty = ?, updated_at = ? WHERE sku = ?").run(it.qty, Date.now(), r.sku);
    postTx("ISS", it, -r.qty, `REQ#${id}`, `req by ${r.by}`, req.user.initials, r.dept);
    db.prepare("UPDATE reqs SET status = 'FILLED', filled_by = ?, filled_ts = ? WHERE id = ?")
      .run(req.user.initials, Date.now(), id);
    return { item: it };
  });
  if (out.error) return res.status(out.status).json({ error: out.error });
  res.json(out);
});

app.post("/api/reqs/:id/cancel", auth, (req, res) => {
  const id = Number(req.params.id);
  const r = db.prepare("SELECT * FROM reqs WHERE id = ?").get(id);
  if (!r) return res.status(404).json({ error: "REQ NOT FOUND" });
  if (r.status !== "OPEN") return res.status(409).json({ error: `REQ #${id} ALREADY ${r.status}` });
  if (r.by !== req.user.initials && req.user.role !== "admin") {
    return res.status(403).json({ error: "ONLY THE REQUESTER OR AN ADMIN CAN CANCEL" });
  }
  db.prepare("UPDATE reqs SET status = 'CANCELLED', filled_by = ?, filled_ts = ? WHERE id = ?")
    .run(req.user.initials, Date.now(), id);
  res.json({ ok: true });
});

/* ---------- departments / cost centers (admin) ---------- */
app.get("/api/depts", auth, adminOnly, (_req, res) => {
  res.json({ depts: db.prepare("SELECT * FROM depts ORDER BY code").all() });
});

app.post("/api/depts", auth, adminOnly, (req, res) => {
  const code = cleanStr(req.body?.code, LEN.dept).toUpperCase();
  const name = cleanStr(req.body?.name, LEN.name);
  if (!DEPT_RE.test(code)) return res.status(400).json({ error: "DEPT CODE: 2–8 LETTERS/NUMBERS" });
  try {
    db.prepare("INSERT INTO depts (code, name) VALUES (?,?)").run(code, name);
    res.json({ dept: { code, name, active: 1 } });
  } catch (e) {
    res.status(409).json({ error: `DEPT ${code} ALREADY ON FILE` });
  }
});

app.patch("/api/depts/:code", auth, adminOnly, (req, res) => {
  const code = cleanStr(req.params.code, LEN.dept).toUpperCase();
  const row = db.prepare("SELECT * FROM depts WHERE code = ?").get(code);
  if (!row) return res.status(404).json({ error: "DEPT NOT FOUND" });
  if (req.body?.active !== undefined) {
    db.prepare("UPDATE depts SET active = ? WHERE code = ?").run(req.body.active ? 1 : 0, code);
  }
  if (req.body?.name !== undefined) {
    db.prepare("UPDATE depts SET name = ? WHERE code = ?").run(cleanStr(req.body.name, LEN.name), code);
  }
  res.json({ ok: true });
});

/* ---------- CSV exports ---------- */
const csvEsc = (v) => {
  let s = String(v ?? "");
  /* neutralize spreadsheet formula injection in free-text fields */
  if (typeof v === "string" && /^[=+\-@]/.test(s)) s = `'${s}`;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const csvRow = (r) => r.map(csvEsc).join(",") + "\r\n";

app.get("/api/export/stock.csv", auth, (_req, res) => {
  res.set("Content-Type", "text/csv");
  res.set("Content-Disposition", 'attachment; filename="whse01-stock.csv"');
  res.write(csvRow(["sku", "description", "category", "unit", "bin", "qty_on_hand", "reorder_point", "unit_cost", "low"]));
  for (const i of db.prepare("SELECT * FROM items ORDER BY sku").all()) {
    res.write(csvRow([i.sku, i.desc, i.cat, i.unit, i.bin, i.qty, i.reorder, i.cost.toFixed(2), i.qty <= i.reorder ? "YES" : ""]));
  }
  res.end();
});

app.get("/api/export/journal.csv", auth, (_req, res) => {
  res.set("Content-Type", "text/csv");
  res.set("Content-Disposition", 'attachment; filename="whse01-journal.csv"');
  res.write(csvRow(["timestamp", "code", "sku", "qty", "balance", "unit", "reference", "note", "operator", "dept"]));
  for (const t of db.prepare("SELECT * FROM tx ORDER BY id DESC").all()) {
    res.write(csvRow([new Date(t.ts).toISOString(), t.code, t.sku, t.qty, t.bal, t.unit, t.ref, t.note, t.by, t.dept]));
  }
  res.end();
});

/* Par-level reorder report: everything at/below reorder point, with a
   suggested buy that restocks to 2x the reorder point (simple par
   heuristic — adjust reorder points per SKU to tune it). */
app.get("/api/export/reorder.csv", auth, (_req, res) => {
  res.set("Content-Type", "text/csv");
  res.set("Content-Disposition", 'attachment; filename="whse01-reorder.csv"');
  res.write(csvRow(["sku", "description", "bin", "unit", "on_hand", "reorder_point", "suggested_order", "unit_cost", "est_cost"]));
  for (const i of db.prepare("SELECT * FROM items WHERE qty <= reorder AND reorder > 0 ORDER BY sku").all()) {
    const suggest = Math.max(i.reorder * 2 - i.qty, 0);
    res.write(csvRow([i.sku, i.desc, i.bin, i.unit, i.qty, i.reorder, suggest, i.cost.toFixed(2), (suggest * i.cost).toFixed(2)]));
  }
  res.end();
});

/* Full restore point: every table except PIN hashes and the session
   secret. Admin-only — this is the whole business in one file. */
app.get("/api/export/backup.json", auth, adminOnly, (_req, res) => {
  res.set("Content-Disposition", 'attachment; filename="whse01-backup.json"');
  res.json({
    exported: new Date().toISOString(),
    items: db.prepare("SELECT * FROM items ORDER BY sku").all(),
    tx: db.prepare("SELECT * FROM tx ORDER BY id").all(),
    depts: db.prepare("SELECT * FROM depts ORDER BY code").all(),
    reqs: db.prepare("SELECT * FROM reqs ORDER BY id").all(),
    users: db.prepare("SELECT id, initials, name, role, active, created_at FROM users ORDER BY initials").all(),
  });
});

/* ---------- crew management (admin) ---------- */
app.get("/api/users", auth, adminOnly, (_req, res) => {
  res.json({ users: db.prepare("SELECT id, initials, name, role, active, created_at FROM users ORDER BY initials").all() });
});

app.post("/api/users", auth, adminOnly, (req, res) => {
  const initials = cleanStr(req.body?.initials, LEN.op).toUpperCase();
  const name = cleanStr(req.body?.name, LEN.name);
  const pin = String(req.body?.pin ?? "");
  const role = req.body?.role === "admin" ? "admin" : "operator";
  if (!INITIALS_RE.test(initials)) return res.status(400).json({ error: "INITIALS: 2–6 letters/numbers" });
  if (!PIN_RE.test(pin)) return res.status(400).json({ error: "PIN MUST BE 4–8 DIGITS" });
  try {
    const r = db.prepare("INSERT INTO users (initials, name, pin_hash, role, created_at) VALUES (?,?,?,?,?)")
      .run(initials, name, hashPin(pin), role, Date.now());
    res.json({ user: { id: Number(r.lastInsertRowid), initials, name, role, active: 1 } });
  } catch (e) {
    res.status(409).json({ error: `INITIALS ${initials} ALREADY ON FILE` });
  }
});

app.patch("/api/users/:id", auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "USER NOT FOUND" });
  if (req.body?.pin !== undefined) {
    if (!PIN_RE.test(String(req.body.pin))) return res.status(400).json({ error: "PIN MUST BE 4–8 DIGITS" });
    /* admin reset also revokes the target's outstanding sessions */
    db.prepare("UPDATE users SET pin_hash = ?, tok = tok + 1 WHERE id = ?").run(hashPin(String(req.body.pin)), id);
  }
  if (req.body?.active !== undefined) {
    const active = req.body.active ? 1 : 0;
    if (!active && target.role === "admin" &&
        db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1").get().c <= 1) {
      return res.status(400).json({ error: "CANNOT DEACTIVATE THE LAST ADMIN" });
    }
    db.prepare("UPDATE users SET active = ? WHERE id = ?").run(active, id);
  }
  if (req.body?.name !== undefined) {
    db.prepare("UPDATE users SET name = ? WHERE id = ?").run(cleanStr(req.body.name, LEN.name), id);
  }
  res.json({ ok: true });
});

/* ---------- static frontend ---------- */
app.use(express.static(path.join(__dirname, "public"), { index: "index.html", maxAge: "1h" }));
app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.use((err, _req, res, _next) => {
  if (err?.type === "entity.parse.failed" || err?.type === "entity.too.large") {
    return res.status(400).json({ error: "BAD REQUEST BODY" });
  }
  console.error(err);
  res.status(500).json({ error: "SERVER FAULT" });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`WHSE-01 listening on :${PORT} (data: ${DATA_DIR})`));
}
module.exports = app;
