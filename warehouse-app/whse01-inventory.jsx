import React, { useState, useEffect, useRef } from "react";

/* ============================================================
   WHSE-01 — Lumber Warehouse Inventory (hardened build)
   AS/400-inspired mobile inventory system.

   Data persists via window.storage (SHARED — whole crew sees
   the same stock levels and transaction journal).

   Hardening in this build:
   - Write-verify-retry sync: every mutation re-reads the shared
     store, applies the change, writes, then reads back to verify
     it wasn't clobbered by another device. Lost race → retry on
     the fresher copy (up to 3 attempts).
   - Background polling keeps every phone converged on the same
     stock picture without manual refresh.
   - Operator badge: each device sets crew initials once; every
     journal entry is stamped with who posted it.
   - Schema sanitization on every read — corrupt or truncated
     data in storage can't crash the app or poison writes.
   - Input clamps and length limits on every field.
   - Error boundary so a render crash shows a recover screen
     instead of a blank page.
   - CSV / JSON export for stock and journal backups.
   - No external network dependencies (system fonts only).
   ============================================================ */

const STORE_KEY = "whse01-data";
const OP_KEY = "whse01-operator";
const TX_CAP = 500;
const POLL_MS = 12000;
const MAX_QTY = 999999;
const LEN = { sku: 32, desc: 80, bin: 12, ref: 40, note: 60, op: 6, cat: 20, unit: 6 };

const C = {
  bg: "#14171B",
  panel: "#1C2127",
  panel2: "#232A32",
  line: "#2A313A",
  text: "#EDE8DC",
  dim: "#8B94A3",
  amber: "#FFB000",
  amberDim: "#7A5A10",
  green: "#4CD97B",
  red: "#FF5D45",
  blue: "#8FA6FF",
};

const MONO = "ui-monospace, 'IBM Plex Mono', Menlo, Consolas, monospace";
const COND = "'Barlow Condensed', 'Arial Narrow', system-ui, sans-serif";

const CATS = ["Dimensional", "Treated", "Sheet Goods", "Drywall", "Doors", "Trim", "Siding", "Hardware"];
const UNITS = ["PC", "SHT", "EA", "LF", "BF", "BDL", "BX"];

const SEED = [
  { sku: "2X4X8-SPF", desc: "2x4x8 SPF Stud", cat: "Dimensional", unit: "PC", bin: "A-01", qty: 412, reorder: 150, cost: 3.18 },
  { sku: "2X4X16-SPF", desc: "2x4x16 SPF #2", cat: "Dimensional", unit: "PC", bin: "A-02", qty: 96, reorder: 60, cost: 7.85 },
  { sku: "2X6X12-SPF", desc: "2x6x12 SPF #2", cat: "Dimensional", unit: "PC", bin: "A-04", qty: 140, reorder: 80, cost: 9.4 },
  { sku: "2X10X16-SYP", desc: "2x10x16 SYP #2", cat: "Dimensional", unit: "PC", bin: "A-07", qty: 38, reorder: 40, cost: 24.6 },
  { sku: "4X4X8-PT", desc: "4x4x8 Treated Post GC", cat: "Treated", unit: "PC", bin: "B-01", qty: 75, reorder: 50, cost: 11.25 },
  { sku: "2X6X16-PT", desc: "2x6x16 Treated GC", cat: "Treated", unit: "PC", bin: "B-03", qty: 52, reorder: 40, cost: 18.9 },
  { sku: "OSB-716", desc: "7/16 OSB 4x8", cat: "Sheet Goods", unit: "SHT", bin: "C-01", qty: 210, reorder: 120, cost: 12.35 },
  { sku: "CDX-12", desc: "1/2 CDX Plywood 4x8", cat: "Sheet Goods", unit: "SHT", bin: "C-03", qty: 64, reorder: 80, cost: 31.5 },
  { sku: "DW-12-48", desc: "1/2 Drywall 4x8", cat: "Drywall", unit: "SHT", bin: "D-01", qty: 180, reorder: 100, cost: 10.8 },
  { sku: "DW-58-412", desc: "5/8 Type X Drywall 4x12", cat: "Drywall", unit: "SHT", bin: "D-02", qty: 88, reorder: 60, cost: 16.2 },
  { sku: "DR-INT-30", desc: '30" 6-Panel Interior Prehung', cat: "Doors", unit: "EA", bin: "E-02", qty: 14, reorder: 8, cost: 92 },
  { sku: "DR-EXT-36", desc: '36" Steel Exterior Prehung', cat: "Doors", unit: "EA", bin: "E-05", qty: 6, reorder: 6, cost: 168 },
  { sku: "HRD-825", desc: 'Hardie Plank 8.25" Cedarmill', cat: "Siding", unit: "PC", bin: "F-01", qty: 320, reorder: 200, cost: 9.15 },
  { sku: "TRM-CAS-356", desc: "356 Casing Primed MDF 7ft", cat: "Trim", unit: "PC", bin: "G-02", qty: 145, reorder: 100, cost: 5.4 },
];

const TX_STYLE = {
  RCV: { color: C.green, label: "RCV" },
  ISS: { color: C.red, label: "ISS" },
  ADJ: { color: C.amber, label: "ADJ" },
  NEW: { color: C.blue, label: "NEW" },
  DEL: { color: C.dim, label: "DEL" },
};
const TX_CODES = Object.keys(TX_STYLE);

/* ---------- primitives ---------- */
const now = () => Date.now();
const uid = () => `${now()}-${Math.random().toString(36).slice(2, 8)}`;
const clone = (o) => (typeof structuredClone === "function" ? structuredClone(o) : JSON.parse(JSON.stringify(o)));

const fmtTs = (ts) => {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
const isToday = (ts) => new Date(ts).toDateString() === new Date().toDateString();
const isLow = (it) => it.qty <= it.reorder;

/* ---------- sanitization ----------
   Everything read from shared storage is treated as untrusted:
   another device may have written a truncated blob, an older
   schema, or garbage. Normalize hard so renders and mutations
   always operate on well-formed data. */
const cleanStr = (s, max) =>
  String(s ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .slice(0, max)
    .trim();

const cleanInt = (n, min, max, fallback = min) => {
  const v = Math.trunc(Number(n));
  if (!Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, v));
};

const cleanMoney = (n) => {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return 0;
  return Math.min(9999999, Math.round(v * 100) / 100);
};

function sanitizeItem(raw) {
  if (!raw || typeof raw !== "object") return null;
  const sku = cleanStr(raw.sku, LEN.sku).toUpperCase();
  const desc = cleanStr(raw.desc, LEN.desc);
  if (!sku || !desc) return null;
  return {
    sku,
    desc,
    cat: CATS.includes(raw.cat) ? raw.cat : cleanStr(raw.cat, LEN.cat) || "Hardware",
    unit: UNITS.includes(raw.unit) ? raw.unit : cleanStr(raw.unit, LEN.unit).toUpperCase() || "EA",
    bin: cleanStr(raw.bin, LEN.bin).toUpperCase() || "—",
    qty: cleanInt(raw.qty, 0, MAX_QTY, 0),
    reorder: cleanInt(raw.reorder, 0, MAX_QTY, 0),
    cost: cleanMoney(raw.cost),
  };
}

function sanitizeTx(raw) {
  if (!raw || typeof raw !== "object") return null;
  const sku = cleanStr(raw.sku, LEN.sku).toUpperCase();
  if (!sku) return null;
  return {
    id: cleanStr(raw.id, 40) || uid(),
    ts: cleanInt(raw.ts, 0, 8640000000000000, now()),
    code: TX_CODES.includes(raw.code) ? raw.code : "ADJ",
    sku,
    qty: cleanInt(raw.qty, -MAX_QTY, MAX_QTY, 0),
    bal: cleanInt(raw.bal, 0, MAX_QTY, 0),
    unit: cleanStr(raw.unit, LEN.unit).toUpperCase() || "EA",
    ref: cleanStr(raw.ref, LEN.ref),
    note: cleanStr(raw.note, LEN.note),
    by: cleanStr(raw.by, LEN.op).toUpperCase(),
  };
}

const emptyStore = () => ({ items: [], tx: [], rev: 0, writeId: "", v: 2 });

function sanitizeStore(raw) {
  if (!raw || typeof raw !== "object") return null;
  const seen = new Set();
  const items = (Array.isArray(raw.items) ? raw.items : [])
    .map(sanitizeItem)
    .filter((it) => it && !seen.has(it.sku) && seen.add(it.sku));
  const tx = (Array.isArray(raw.tx) ? raw.tx : []).map(sanitizeTx).filter(Boolean).slice(0, TX_CAP);
  return {
    items,
    tx,
    rev: cleanInt(raw.rev, 0, Number.MAX_SAFE_INTEGER, 0),
    writeId: cleanStr(raw.writeId, 40),
    v: 2,
  };
}

/* ---------- storage ---------- */
async function readStore() {
  try {
    const r = await window.storage.get(STORE_KEY, true);
    if (r && r.value) return sanitizeStore(JSON.parse(r.value));
  } catch (e) {
    /* key missing, bad JSON, or storage down — caller treats as absent */
  }
  return null;
}

async function writeStore(data) {
  try {
    await window.storage.set(STORE_KEY, JSON.stringify(data), true);
    return true;
  } catch (e) {
    return false;
  }
}

async function readOperator() {
  try {
    const r = await window.storage.get(OP_KEY, false);
    if (r && r.value) return cleanStr(r.value, LEN.op).toUpperCase();
  } catch (e) {
    /* fine — gate will ask */
  }
  return "";
}

async function writeOperator(op) {
  try {
    await window.storage.set(OP_KEY, op, false);
  } catch (e) {
    /* non-fatal: initials just won't persist across reloads */
  }
}

/* ---------- exports ---------- */
function toCsv(rows) {
  const esc = (v) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return rows.map((r) => r.map(esc).join(",")).join("\r\n");
}

async function deliverFile(filename, text, mime, onDone, onFail) {
  try {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    onDone(`${filename} downloaded`);
    return;
  } catch (e) {
    /* downloads may be blocked in a sandboxed frame — fall back to clipboard */
  }
  try {
    await navigator.clipboard.writeText(text);
    onDone(`Download blocked — ${filename} copied to clipboard`);
  } catch (e) {
    onFail("EXPORT FAILED — downloads and clipboard both blocked");
  }
}

/* ---------- error boundary ---------- */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { err: null };
  }
  static getDerivedStateFromError(err) {
    return { err };
  }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div style={{ background: C.bg, color: C.text, minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, fontFamily: MONO, padding: 24, textAlign: "center" }}>
        <div style={{ color: C.red, fontSize: 15, fontWeight: 600, letterSpacing: 1 }}>WHSE-01 DISPLAY FAULT</div>
        <div style={{ color: C.dim, fontSize: 12, lineHeight: 1.6 }}>
          The screen hit an error. Your stock data lives in shared storage and is not affected.
        </div>
        <button
          onClick={() => this.setState({ err: null })}
          style={{ background: C.amber, color: "#14171B", border: "none", borderRadius: 8, padding: "14px 26px", fontSize: 15, fontWeight: 700, letterSpacing: 1, cursor: "pointer", fontFamily: COND }}
        >
          RELOAD SCREEN
        </button>
      </div>
    );
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <WarehouseApp />
    </ErrorBoundary>
  );
}

function WarehouseApp() {
  const [data, setData] = useState(null); // {items:[], tx:[], rev, writeId}
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [operator, setOperator] = useState("");
  const [opLoaded, setOpLoaded] = useState(false);
  const [askOperator, setAskOperator] = useState(false);
  const [tab, setTab] = useState("stock"); // stock | log | add
  const [query, setQuery] = useState("");
  const [cat, setCat] = useState("ALL");
  const [lowOnly, setLowOnly] = useState(false);
  const [sheetSku, setSheetSku] = useState(null);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);
  const busyRef = useRef(false);
  const revRef = useRef(-1);
  const operatorRef = useRef("");

  useEffect(() => {
    revRef.current = data ? data.rev : -1;
  }, [data]);
  useEffect(() => {
    operatorRef.current = operator;
  }, [operator]);

  /* initial load */
  useEffect(() => {
    (async () => {
      const [existing, op] = await Promise.all([readStore(), readOperator()]);
      if (existing) {
        setData(existing);
      } else {
        const fresh = emptyStore();
        setData(fresh);
        const ok = await writeStore(fresh);
        if (!ok) setOffline(true);
      }
      setOperator(op);
      setOpLoaded(true);
      if (!op) setAskOperator(true);
      setLoading(false);
    })();
  }, []);

  /* background sync: pull remote changes so every phone converges */
  useEffect(() => {
    const t = setInterval(async () => {
      if (busyRef.current || document.hidden) return;
      const remote = await readStore();
      if (remote && remote.rev !== revRef.current) {
        setData(remote);
        setOffline(false);
      }
    }, POLL_MS);
    return () => clearInterval(t);
  }, []);

  useEffect(() => () => clearTimeout(toastTimer.current), []);

  const flash = (msg, color = C.green) => {
    setToast({ msg, color });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2600);
  };

  /* ---------- mutation with write-verify-retry ----------
     fn(draft) returns:
       { store, msg, color }  — apply and announce
       { error, color }       — abort with a message
       null/undefined         — abort silently
     After writing we read back: if another device won the race
     our writeId won't be there, so we re-apply fn on the fresher
     copy. Not a true transaction, but it turns silent lost
     updates into converging retries. */
  async function mutate(fn) {
    if (busyRef.current) {
      flash("BUSY — previous entry still posting", C.amber);
      return;
    }
    busyRef.current = true;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const base = (await readStore()) || data || emptyStore();
        const res = fn(clone(base));
        if (!res) return;
        if (res.error) {
          flash(res.error, res.color || C.red);
          return;
        }
        const next = res.store;
        next.tx = (next.tx || []).slice(0, TX_CAP);
        next.rev = (Number(base.rev) || 0) + 1;
        next.writeId = uid();
        next.v = 2;
        const ok = await writeStore(next);
        if (!ok) {
          setData(next);
          setOffline(true);
          flash("STORAGE DOWN — saved on this device only", C.red);
          return;
        }
        const check = await readStore();
        if (!check || check.writeId === next.writeId) {
          setData(next);
          setOffline(false);
          if (res.msg) flash(res.msg, res.color);
          return;
        }
        /* lost the race — loop and re-apply on the newer copy */
      }
      flash("CONTENTION — another device is posting. Try again.", C.amber);
    } finally {
      busyRef.current = false;
    }
  }

  /* push this device's copy after an outage (last-write-wins) */
  async function retrySync() {
    if (!data) return;
    const ok = await writeStore({ ...data, rev: data.rev + 1, writeId: uid() });
    if (ok) {
      setOffline(false);
      flash("RECONNECTED — local changes pushed", C.green);
    } else {
      flash("STILL DOWN — try again in a minute", C.red);
    }
  }

  function postTx(d, code, item, delta, ref, note) {
    d.tx.unshift({
      id: uid(),
      ts: now(),
      code,
      sku: item.sku,
      qty: delta,
      bal: item.qty,
      unit: item.unit,
      ref: cleanStr(ref, LEN.ref),
      note: cleanStr(note, LEN.note),
      by: operatorRef.current,
    });
  }

  const doReceive = (sku, qty, ref) =>
    mutate((d) => {
      const it = d.items.find((i) => i.sku === sku);
      if (!it) return { error: `SKU ${sku} NOT ON FILE — removed on another device?` };
      qty = cleanInt(qty, 1, MAX_QTY, 0);
      if (!qty) return { error: "BAD QUANTITY" };
      it.qty = Math.min(MAX_QTY, it.qty + qty);
      postTx(d, "RCV", it, +qty, ref);
      return { store: d, msg: `RCV ${qty} ${it.unit} · ${it.sku} → ${it.qty}`, color: C.green };
    });

  const doIssue = (sku, qty, ref) =>
    mutate((d) => {
      const it = d.items.find((i) => i.sku === sku);
      if (!it) return { error: `SKU ${sku} NOT ON FILE — removed on another device?` };
      qty = cleanInt(qty, 1, MAX_QTY, 0);
      if (!qty) return { error: "BAD QUANTITY" };
      if (qty > it.qty) return { error: `SHORT — only ${it.qty} ${it.unit} on hand` };
      it.qty -= qty;
      postTx(d, "ISS", it, -qty, ref);
      return { store: d, msg: `ISS ${qty} ${it.unit} · ${it.sku} → ${it.qty}`, color: C.red };
    });

  const doCount = (sku, exact, ref) =>
    mutate((d) => {
      const it = d.items.find((i) => i.sku === sku);
      if (!it) return { error: `SKU ${sku} NOT ON FILE — removed on another device?` };
      exact = cleanInt(exact, 0, MAX_QTY, 0);
      const delta = exact - it.qty;
      it.qty = exact;
      postTx(d, "ADJ", it, delta, ref, "cycle count");
      return { store: d, msg: `COUNT SET ${it.sku} = ${exact} (${delta >= 0 ? "+" : ""}${delta})`, color: C.amber };
    });

  const addItem = (raw) =>
    mutate((d) => {
      const item = sanitizeItem(raw);
      if (!item) return { error: "SKU AND DESCRIPTION REQUIRED" };
      if (d.items.some((i) => i.sku === item.sku)) return { error: `SKU ${item.sku} already exists` };
      d.items.push(item);
      postTx(d, "NEW", item, item.qty, "", "item created");
      return { store: d, msg: `NEW SKU ${item.sku} added`, color: C.blue };
    });

  const updateItem = (sku, patch) =>
    mutate((d) => {
      const it = d.items.find((i) => i.sku === sku);
      if (!it) return { error: `SKU ${sku} NOT ON FILE` };
      const merged = sanitizeItem({ ...it, ...patch, sku: it.sku, qty: it.qty });
      if (!merged) return { error: "BAD ITEM DATA" };
      Object.assign(it, merged);
      return { store: d, msg: `SKU ${sku} updated`, color: C.amber };
    });

  const deleteItem = (sku) =>
    mutate((d) => {
      const it = d.items.find((i) => i.sku === sku);
      if (!it) return { error: `SKU ${sku} NOT ON FILE` };
      d.items = d.items.filter((i) => i.sku !== sku);
      postTx(d, "DEL", { ...it, qty: 0 }, -it.qty, "", "item removed");
      return { store: d, msg: `SKU ${sku} removed`, color: C.dim };
    });

  const loadSeed = () =>
    mutate((d) => {
      /* guard: never wipe a store that another device already stocked */
      if (d.items.length > 0) return { error: "FILE NOT EMPTY — refresh, crew already has stock on file" };
      d.items = clone(SEED);
      d.tx = [];
      SEED.forEach((it) => postTx(d, "NEW", it, it.qty, "", "opening stock"));
      return { store: d, msg: "Sample stock loaded", color: C.blue };
    });

  /* ---------- exports ---------- */
  const stamp = () => {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
  };

  const exportStock = () => {
    const rows = [["sku", "description", "category", "unit", "bin", "qty_on_hand", "reorder_point", "unit_cost", "low"]];
    (data?.items || []).forEach((i) => rows.push([i.sku, i.desc, i.cat, i.unit, i.bin, i.qty, i.reorder, i.cost.toFixed(2), isLow(i) ? "YES" : ""]));
    deliverFile(`whse01-stock-${stamp()}.csv`, toCsv(rows), "text/csv", (m) => flash(m, C.blue), (m) => flash(m, C.red));
  };

  const exportJournal = () => {
    const rows = [["timestamp", "code", "sku", "qty", "balance", "unit", "reference", "note", "operator"]];
    (data?.tx || []).forEach((t) => rows.push([new Date(t.ts).toISOString(), t.code, t.sku, t.qty, t.bal, t.unit, t.ref, t.note, t.by]));
    deliverFile(`whse01-journal-${stamp()}.csv`, toCsv(rows), "text/csv", (m) => flash(m, C.blue), (m) => flash(m, C.red));
  };

  const exportBackup = () => {
    deliverFile(`whse01-backup-${stamp()}.json`, JSON.stringify(data, null, 2), "application/json", (m) => flash(m, C.blue), (m) => flash(m, C.red));
  };

  /* ---------- derived ---------- */
  const items = data?.items || [];
  const tx = data?.tx || [];
  const lowCount = items.filter(isLow).length;
  const unitCount = items.reduce((s, i) => s + i.qty, 0);
  const todayTx = tx.filter((t) => isToday(t.ts)).length;

  const visible = items
    .filter((i) => cat === "ALL" || i.cat === cat)
    .filter((i) => !lowOnly || isLow(i))
    .filter((i) => {
      const q = query.trim().toUpperCase();
      if (!q) return true;
      return i.sku.toUpperCase().includes(q) || i.desc.toUpperCase().includes(q) || i.bin.toUpperCase().includes(q);
    })
    .sort((a, b) => a.sku.localeCompare(b.sku));

  const sheetItem = items.find((i) => i.sku === sheetSku) || null;

  /* ---------- render ---------- */
  if (loading) {
    return (
      <div style={{ background: C.bg, color: C.dim, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: MONO }}>
        <span>CONNECTING TO WHSE-01<Cursor /></span>
      </div>
    );
  }

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh", fontFamily: COND, paddingBottom: 84 }}>
      <style>{`
        * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        input, select { outline: none; }
        input:focus, select:focus, button:focus-visible { box-shadow: 0 0 0 2px ${C.amber}55; }
        ::placeholder { color: ${C.dim}; opacity: .7; }
        @keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
        .curs { display:inline-block; width:.55em; height:1em; background:${C.amber}; vertical-align:-0.12em; animation: blink 1.1s step-end infinite; }
        @media (prefers-reduced-motion: reduce) { .curs { animation: none; } }
        ::-webkit-scrollbar { height: 0; width: 0; }
      `}</style>

      {/* ===== session bar ===== */}
      <div style={{ position: "sticky", top: 0, zIndex: 30, background: C.bg, borderBottom: `1px solid ${C.line}` }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", padding: "10px 14px 6px" }}>
          <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: 1, color: C.amber }}>
            WHSE-01 · INVENTORY<Cursor />
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "baseline", fontFamily: MONO, fontSize: 11 }}>
            <button onClick={() => setAskOperator(true)} style={{ background: "none", border: "none", color: C.blue, fontFamily: MONO, fontSize: 11, cursor: "pointer", padding: 0 }}>
              OP:{operator || "—"}
            </button>
            {offline ? (
              <button onClick={retrySync} style={{ background: "none", border: `1px solid ${C.red}`, borderRadius: 4, color: C.red, fontFamily: MONO, fontSize: 10, fontWeight: 600, padding: "2px 6px", cursor: "pointer" }}>
                LOCAL ONLY · RETRY
              </button>
            ) : (
              <span style={{ color: C.dim }}>SHARED · LIVE</span>
            )}
          </div>
        </div>
        {/* stat strip */}
        <div style={{ display: "flex", gap: 8, padding: "0 14px 10px", fontFamily: MONO }}>
          <Stat label="SKUS" value={items.length} />
          <Stat label="UNITS" value={unitCount.toLocaleString()} />
          <Stat label="LOW" value={lowCount} color={lowCount ? C.red : C.green} onClick={() => { setTab("stock"); setLowOnly(true); }} />
          <Stat label="TX TODAY" value={todayTx} />
        </div>
      </div>

      {/* ===== STOCK ===== */}
      {tab === "stock" && (
        <div>
          <div style={{ padding: "12px 14px 4px" }}>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value.slice(0, LEN.desc))}
              placeholder="SEARCH SKU / DESC / BIN"
              inputMode="search"
              aria-label="Search stock"
              style={{
                width: "100%", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
                padding: "14px 14px", color: C.text, fontFamily: MONO,
                fontSize: 15, letterSpacing: 1,
              }}
            />
          </div>
          <div style={{ display: "flex", gap: 6, overflowX: "auto", padding: "10px 14px" }}>
            <Chip active={lowOnly} color={C.red} onClick={() => setLowOnly(!lowOnly)}>⚠ LOW</Chip>
            <Chip active={cat === "ALL"} onClick={() => setCat("ALL")}>ALL</Chip>
            {CATS.map((c) => (
              <Chip key={c} active={cat === c} onClick={() => setCat(cat === c ? "ALL" : c)}>{c.toUpperCase()}</Chip>
            ))}
          </div>

          {items.length === 0 ? (
            <Empty onSeed={loadSeed} />
          ) : visible.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 13 }}>
              NO MATCH. Clear filters or check the SKU.
            </div>
          ) : (
            <div style={{ padding: "2px 14px" }}>
              {visible.map((it) => (
                <button
                  key={it.sku}
                  onClick={() => setSheetSku(it.sku)}
                  style={{
                    width: "100%", textAlign: "left", background: C.panel, border: `1px solid ${isLow(it) ? C.red + "66" : C.line}`,
                    borderRadius: 8, padding: "12px 14px", marginBottom: 8, color: C.text, cursor: "pointer",
                    display: "flex", alignItems: "center", gap: 12,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: MONO, fontSize: 14, fontWeight: 600, color: C.amber, letterSpacing: 0.5 }}>
                      {it.sku}
                    </div>
                    <div style={{ fontSize: 17, fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {it.desc}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 11, color: C.dim, marginTop: 2 }}>
                      BIN {it.bin} · {it.cat.toUpperCase()}{isLow(it) && <span style={{ color: C.red }}> · REORDER ≤{it.reorder}</span>}
                    </div>
                  </div>
                  <div style={{ textAlign: "right", fontFamily: MONO }}>
                    <div style={{ fontSize: 22, fontWeight: 600, color: isLow(it) ? C.red : C.green }}>{it.qty}</div>
                    <div style={{ fontSize: 11, color: C.dim }}>{it.unit}</div>
                  </div>
                </button>
              ))}
              <div style={{ textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 11, padding: "8px 0 4px" }}>
                {visible.length} SKU{visible.length !== 1 ? "S" : ""} SHOWN
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===== ACTIVITY LOG ===== */}
      {tab === "log" && (
        <div style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
            <ToolBtn onClick={exportStock}>STOCK CSV</ToolBtn>
            <ToolBtn onClick={exportJournal}>JOURNAL CSV</ToolBtn>
            <ToolBtn onClick={exportBackup}>BACKUP JSON</ToolBtn>
          </div>
          {tx.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 13 }}>
              JOURNAL EMPTY. Receive or issue stock and it lands here.
            </div>
          ) : (
            <>
              {tx.map((t) => {
                const s = TX_STYLE[t.code] || TX_STYLE.ADJ;
                return (
                  <div key={t.id} style={{ display: "flex", gap: 10, alignItems: "flex-start", borderBottom: `1px solid ${C.line}`, padding: "10px 2px", fontFamily: MONO }}>
                    <span style={{ color: s.color, border: `1px solid ${s.color}66`, borderRadius: 4, fontSize: 11, fontWeight: 600, padding: "2px 6px", minWidth: 42, textAlign: "center" }}>
                      {s.label}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>
                        {t.sku} <span style={{ color: s.color }}>{t.qty > 0 ? `+${t.qty}` : t.qty}</span>
                        <span style={{ color: C.dim }}> → {t.bal} {t.unit}</span>
                      </div>
                      <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>
                        {fmtTs(t.ts)}{t.by ? ` · ${t.by}` : ""}{t.ref ? ` · REF ${t.ref}` : ""}{t.note ? ` · ${t.note}` : ""}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div style={{ textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 11, padding: "10px 0" }}>
                JOURNAL KEEPS LAST {TX_CAP} ENTRIES — EXPORT CSV REGULARLY FOR RECORDS
              </div>
            </>
          )}
        </div>
      )}

      {/* ===== ADD ITEM ===== */}
      {tab === "add" && <AddForm onAdd={(item) => { addItem(item); setTab("stock"); setQuery(item.sku); }} />}

      {/* ===== item action sheet ===== */}
      {sheetItem && (
        <ItemSheet
          item={sheetItem}
          onClose={() => setSheetSku(null)}
          onReceive={doReceive}
          onIssue={doIssue}
          onCount={doCount}
          onUpdate={updateItem}
          onDelete={(sku) => { deleteItem(sku); setSheetSku(null); }}
        />
      )}

      {/* ===== operator gate ===== */}
      {opLoaded && askOperator && (
        <OperatorGate
          current={operator}
          onSave={(op) => {
            setOperator(op);
            setAskOperator(false);
            writeOperator(op);
            flash(`OPERATOR SET: ${op}`, C.blue);
          }}
          onCancel={operator ? () => setAskOperator(false) : null}
        />
      )}

      {/* ===== toast ===== */}
      {toast && (
        <div role="status" style={{
          position: "fixed", left: 14, right: 14, bottom: 76, zIndex: 60,
          background: C.panel2, border: `1px solid ${toast.color}`, color: toast.color,
          borderRadius: 8, padding: "12px 14px", fontFamily: MONO,
          fontSize: 13, fontWeight: 600, textAlign: "center",
        }}>
          {toast.msg}
        </div>
      )}

      {/* ===== bottom nav ===== */}
      <div style={{
        position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 40,
        display: "flex", background: C.bg, borderTop: `1px solid ${C.line}`,
        paddingBottom: "env(safe-area-inset-bottom)",
      }}>
        <NavBtn active={tab === "stock"} onClick={() => setTab("stock")} label="STOCK" />
        <NavBtn active={tab === "log"} onClick={() => setTab("log")} label="JOURNAL" />
        <NavBtn active={tab === "add"} onClick={() => setTab("add")} label="+ NEW SKU" />
      </div>
    </div>
  );
}

/* ============ operator gate ============ */

function OperatorGate({ current, onSave, onCancel }) {
  const [val, setVal] = useState(current || "");
  const ok = /^[A-Z0-9]{2,6}$/.test(val);
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 70, background: "#000B", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ width: "100%", maxWidth: 340, background: C.panel, border: `1px solid ${C.amber}`, borderRadius: 12, padding: 20 }}>
        <div style={{ fontFamily: MONO, color: C.amber, fontSize: 13, fontWeight: 600, letterSpacing: 1, marginBottom: 6 }}>
          OPERATOR SIGN-ON
        </div>
        <div style={{ fontFamily: MONO, color: C.dim, fontSize: 11, lineHeight: 1.6, marginBottom: 14 }}>
          Enter your initials (2–6 letters/numbers). Every entry you post is stamped with them in the shared journal.
        </div>
        <input
          value={val}
          onChange={(e) => setVal(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, LEN.op))}
          placeholder="e.g. JD"
          autoFocus
          aria-label="Operator initials"
          style={{
            width: "100%", background: C.bg, border: `1px solid ${C.line}`, borderRadius: 6,
            padding: "14px 12px", color: C.text, fontFamily: MONO, fontSize: 18,
            letterSpacing: 3, textAlign: "center", marginBottom: 14,
          }}
        />
        <BigBtn color={C.amber} disabled={!ok} onClick={() => onSave(val)}>SIGN ON</BigBtn>
        {onCancel && (
          <button onClick={onCancel} style={{ width: "100%", marginTop: 10, background: "none", border: "none", color: C.dim, fontFamily: MONO, fontSize: 12, cursor: "pointer", padding: 8 }}>
            CANCEL
          </button>
        )}
      </div>
    </div>
  );
}

/* ============ small parts ============ */

function Cursor() {
  return <span className="curs" aria-hidden="true" />;
}

function Stat({ label, value, color, onClick }) {
  return (
    <button onClick={onClick} disabled={!onClick} style={{
      flex: 1, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
      padding: "6px 4px", textAlign: "center", cursor: onClick ? "pointer" : "default", color: C.text,
    }}>
      <div style={{ fontSize: 16, fontWeight: 600, color: color || C.text }}>{value}</div>
      <div style={{ fontSize: 9, letterSpacing: 1, color: C.dim }}>{label}</div>
    </button>
  );
}

function Chip({ children, active, onClick, color }) {
  const c = color || C.amber;
  return (
    <button onClick={onClick} style={{
      flexShrink: 0, background: active ? c : C.panel, color: active ? "#14171B" : C.dim,
      border: `1px solid ${active ? c : C.line}`, borderRadius: 999, padding: "7px 13px",
      fontSize: 13, fontWeight: 700, letterSpacing: 0.5, cursor: "pointer",
      fontFamily: COND,
    }}>
      {children}
    </button>
  );
}

function ToolBtn({ children, onClick }) {
  return (
    <button onClick={onClick} style={{
      flex: 1, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
      color: C.blue, padding: "10px 0", fontFamily: MONO, fontSize: 11, fontWeight: 600,
      letterSpacing: 0.5, cursor: "pointer",
    }}>
      ⭳ {children}
    </button>
  );
}

function NavBtn({ active, onClick, label }) {
  return (
    <button onClick={onClick} style={{
      flex: 1, padding: "16px 0 14px", background: "transparent", border: "none",
      borderTop: `2px solid ${active ? C.amber : "transparent"}`,
      color: active ? C.amber : C.dim, fontFamily: MONO,
      fontSize: 12, fontWeight: 600, letterSpacing: 1.5, cursor: "pointer",
    }}>
      {label}
    </button>
  );
}

function Empty({ onSeed }) {
  return (
    <div style={{ padding: "48px 24px", textAlign: "center" }}>
      <div style={{ fontFamily: MONO, color: C.dim, fontSize: 13, lineHeight: 1.7 }}>
        NO ITEMS ON FILE.<br />Add your first SKU, or load sample lumber stock to try the workflow.
      </div>
      <button onClick={onSeed} style={{
        marginTop: 20, background: C.amber, color: "#14171B", border: "none", borderRadius: 8,
        padding: "14px 22px", fontSize: 15, fontWeight: 700, letterSpacing: 1, cursor: "pointer",
        fontFamily: COND,
      }}>
        LOAD SAMPLE STOCK
      </button>
    </div>
  );
}

/* ============ item action sheet ============ */

function ItemSheet({ item, onClose, onReceive, onIssue, onCount, onUpdate, onDelete }) {
  const [mode, setMode] = useState("move"); // move | count | edit
  const [qty, setQty] = useState("");
  const [ref, setRef] = useState("");
  const [exact, setExact] = useState("");
  const [edit, setEdit] = useState({ desc: item.desc, bin: item.bin, reorder: item.reorder, cost: item.cost });
  const [confirmDel, setConfirmDel] = useState(false);

  useEffect(() => {
    setMode("move"); setQty(""); setRef(""); setExact("");
    setEdit({ desc: item.desc, bin: item.bin, reorder: item.reorder, cost: item.cost });
    setConfirmDel(false);
  }, [item.sku]);

  const q = parseInt(qty, 10);
  const validQty = Number.isInteger(q) && q > 0 && q <= MAX_QTY;
  const ex = parseInt(exact, 10);
  const validExact = Number.isInteger(ex) && ex >= 0 && ex <= MAX_QTY;

  const inputStyle = {
    width: "100%", background: C.bg, border: `1px solid ${C.line}`, borderRadius: 6,
    padding: "13px 12px", color: C.text, fontFamily: MONO, fontSize: 16,
  };
  const labelStyle = { fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, marginBottom: 4, display: "block" };

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 50, background: "#0009", display: "flex", alignItems: "flex-end" }}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: "100%", background: C.panel, borderTop: `2px solid ${C.amber}`,
        borderRadius: "14px 14px 0 0", padding: "16px 16px 28px", maxHeight: "86vh", overflowY: "auto",
      }}>
        {/* header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
          <div>
            <div style={{ fontFamily: MONO, color: C.amber, fontWeight: 600, fontSize: 15 }}>{item.sku}</div>
            <div style={{ fontSize: 19, fontWeight: 600 }}>{item.desc}</div>
            <div style={{ fontFamily: MONO, fontSize: 11, color: C.dim, marginTop: 2 }}>
              BIN {item.bin} · {item.cat.toUpperCase()} · ${Number(item.cost).toFixed(2)}/{item.unit}
            </div>
          </div>
          <div style={{ textAlign: "right", fontFamily: MONO }}>
            <div style={{ fontSize: 28, fontWeight: 600, color: isLow(item) ? C.red : C.green }}>{item.qty}</div>
            <div style={{ fontSize: 11, color: C.dim }}>{item.unit} ON HAND</div>
          </div>
        </div>

        {/* mode tabs */}
        <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
          {[["move", "MOVE"], ["count", "COUNT"], ["edit", "EDIT"]].map(([m, l]) => (
            <Chip key={m} active={mode === m} onClick={() => setMode(m)}>{l}</Chip>
          ))}
        </div>

        {mode === "move" && (
          <div>
            <label style={labelStyle}>QUANTITY ({item.unit})</label>
            <input value={qty} onChange={(e) => setQty(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" placeholder="0" style={inputStyle} />
            <div style={{ display: "flex", gap: 6, margin: "8px 0 12px" }}>
              {[1, 5, 10, 25, 50].map((n) => (
                <button key={n} onClick={() => setQty(String(Math.min(MAX_QTY, (Number.isInteger(q) ? q : 0) + n)))} style={{
                  flex: 1, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 6, color: C.text,
                  padding: "10px 0", fontFamily: MONO, fontSize: 14, cursor: "pointer",
                }}>+{n}</button>
              ))}
            </div>
            <label style={labelStyle}>REFERENCE — PO# / JOB# / CUSTOMER (OPTIONAL)</label>
            <input value={ref} onChange={(e) => setRef(e.target.value.slice(0, LEN.ref))} maxLength={LEN.ref} placeholder="PO-1042, SMITH JOB…" style={{ ...inputStyle, marginBottom: 16 }} />
            <div style={{ display: "flex", gap: 10 }}>
              <BigBtn color={C.green} disabled={!validQty} onClick={() => { onReceive(item.sku, q, ref.trim()); onClose(); }}>
                RECEIVE +{validQty ? q : ""}
              </BigBtn>
              <BigBtn color={C.red} disabled={!validQty || q > item.qty} onClick={() => { onIssue(item.sku, q, ref.trim()); onClose(); }}>
                ISSUE −{validQty ? q : ""}
              </BigBtn>
            </div>
            {validQty && q > item.qty && (
              <div style={{ color: C.red, fontFamily: MONO, fontSize: 12, marginTop: 10, textAlign: "center" }}>
                SHORT — only {item.qty} {item.unit} on hand. Run a COUNT if the shelf says otherwise.
              </div>
            )}
          </div>
        )}

        {mode === "count" && (
          <div>
            <label style={labelStyle}>PHYSICAL COUNT — SET EXACT ON-HAND ({item.unit})</label>
            <input value={exact} onChange={(e) => setExact(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" placeholder={String(item.qty)} style={{ ...inputStyle, marginBottom: 12 }} />
            <label style={labelStyle}>REFERENCE (OPTIONAL)</label>
            <input value={ref} onChange={(e) => setRef(e.target.value.slice(0, LEN.ref))} maxLength={LEN.ref} placeholder="CYCLE COUNT 07/16" style={{ ...inputStyle, marginBottom: 16 }} />
            <BigBtn color={C.amber} disabled={!validExact} onClick={() => { onCount(item.sku, ex, ref.trim()); onClose(); }}>
              POST COUNT{validExact ? ` (${ex - item.qty >= 0 ? "+" : ""}${ex - item.qty})` : ""}
            </BigBtn>
          </div>
        )}

        {mode === "edit" && (
          <div>
            <label style={labelStyle}>DESCRIPTION</label>
            <input value={edit.desc} onChange={(e) => setEdit({ ...edit, desc: e.target.value.slice(0, LEN.desc) })} maxLength={LEN.desc} style={{ ...inputStyle, marginBottom: 10 }} />
            <div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>BIN</label>
                <input value={edit.bin} onChange={(e) => setEdit({ ...edit, bin: e.target.value.toUpperCase().slice(0, LEN.bin) })} maxLength={LEN.bin} style={inputStyle} />
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>REORDER PT</label>
                <input value={edit.reorder} onChange={(e) => setEdit({ ...edit, reorder: e.target.value.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" style={inputStyle} />
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>COST $</label>
                <input value={edit.cost} onChange={(e) => setEdit({ ...edit, cost: e.target.value.replace(/[^0-9.]/g, "").slice(0, 10) })} inputMode="decimal" style={inputStyle} />
              </div>
            </div>
            <BigBtn color={C.amber} onClick={() => {
              onUpdate(item.sku, {
                desc: String(edit.desc).trim() || item.desc,
                bin: String(edit.bin).trim() || item.bin,
                reorder: parseInt(edit.reorder, 10) || 0,
                cost: parseFloat(edit.cost) || 0,
              });
              onClose();
            }}>
              SAVE CHANGES
            </BigBtn>
            <button onClick={() => (confirmDel ? onDelete(item.sku) : setConfirmDel(true))} style={{
              width: "100%", marginTop: 12, background: confirmDel ? C.red : "transparent", border: `1px solid ${C.red}${confirmDel ? "" : "66"}`,
              color: confirmDel ? "#14171B" : C.red, borderRadius: 8, padding: "12px 0", fontFamily: MONO,
              fontSize: 13, fontWeight: 600, letterSpacing: 1, cursor: "pointer",
            }}>
              {confirmDel ? `TAP AGAIN — WRITES OFF ${item.qty} ${item.unit}` : "REMOVE SKU FROM FILE"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function BigBtn({ children, color, disabled, onClick }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      flex: 1, width: "100%", background: disabled ? C.panel2 : color, color: disabled ? C.dim : "#14171B",
      border: "none", borderRadius: 8, padding: "16px 0", fontSize: 17, fontWeight: 700, letterSpacing: 1,
      cursor: disabled ? "default" : "pointer", fontFamily: COND,
    }}>
      {children}
    </button>
  );
}

/* ============ add item form ============ */

function AddForm({ onAdd }) {
  const [f, setF] = useState({ sku: "", desc: "", cat: CATS[0], unit: UNITS[0], bin: "", qty: "", reorder: "", cost: "" });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  const skuOk = /^[A-Z0-9][A-Z0-9-]{1,31}$/.test(f.sku.trim());
  const ready = skuOk && f.desc.trim();

  const inputStyle = {
    width: "100%", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
    padding: "13px 12px", color: C.text, fontFamily: MONO, fontSize: 15,
  };
  const labelStyle = { fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, margin: "12px 0 4px", display: "block" };

  return (
    <div style={{ padding: "6px 14px 20px" }}>
      <label style={labelStyle}>SKU * (LETTERS / NUMBERS / DASHES)</label>
      <input
        value={f.sku}
        onChange={(e) => setF({ ...f, sku: e.target.value.toUpperCase().replace(/\s/g, "-").replace(/[^A-Z0-9-]/g, "").slice(0, LEN.sku) })}
        maxLength={LEN.sku}
        placeholder="2X8X12-SPF"
        style={inputStyle}
      />
      {f.sku && !skuOk && (
        <div style={{ color: C.red, fontFamily: MONO, fontSize: 11, marginTop: 4 }}>
          SKU: 2–32 chars, letters/numbers/dashes, must start with a letter or number
        </div>
      )}
      <label style={labelStyle}>DESCRIPTION *</label>
      <input value={f.desc} onChange={(e) => setF({ ...f, desc: e.target.value.slice(0, LEN.desc) })} maxLength={LEN.desc} placeholder="2x8x12 SPF #2" style={inputStyle} />
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>CATEGORY</label>
          <select value={f.cat} onChange={set("cat")} style={inputStyle}>
            {CATS.map((c) => <option key={c}>{c}</option>)}
          </select>
        </div>
        <div style={{ width: 110 }}>
          <label style={labelStyle}>UNIT</label>
          <select value={f.unit} onChange={set("unit")} style={inputStyle}>
            {UNITS.map((u) => <option key={u}>{u}</option>)}
          </select>
        </div>
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>BIN</label>
          <input value={f.bin} onChange={(e) => setF({ ...f, bin: e.target.value.toUpperCase().slice(0, LEN.bin) })} maxLength={LEN.bin} placeholder="A-03" style={inputStyle} />
        </div>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>OPENING QTY</label>
          <input value={f.qty} onChange={(e) => setF({ ...f, qty: e.target.value.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" placeholder="0" style={inputStyle} />
        </div>
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>REORDER POINT</label>
          <input value={f.reorder} onChange={(e) => setF({ ...f, reorder: e.target.value.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" placeholder="0" style={inputStyle} />
        </div>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>UNIT COST $</label>
          <input value={f.cost} onChange={(e) => setF({ ...f, cost: e.target.value.replace(/[^0-9.]/g, "").slice(0, 10) })} inputMode="decimal" placeholder="0.00" style={inputStyle} />
        </div>
      </div>
      <div style={{ marginTop: 20 }}>
        <BigBtn color={C.amber} disabled={!ready} onClick={() => onAdd({
          sku: f.sku.trim(),
          desc: f.desc.trim(),
          cat: f.cat,
          unit: f.unit,
          bin: f.bin.trim() || "—",
          qty: parseInt(f.qty, 10) || 0,
          reorder: parseInt(f.reorder, 10) || 0,
          cost: parseFloat(f.cost) || 0,
        })}>
          ADD TO ITEM FILE
        </BigBtn>
      </div>
    </div>
  );
}
