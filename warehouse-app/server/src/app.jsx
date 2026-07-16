import React, { useState, useEffect, useRef, useCallback } from "react";
import { createRoot } from "react-dom/client";

/* ============================================================
   WHSE-01 — Lumber Warehouse Inventory (self-hosted frontend)

   AS/400 heritage:
   - Screen IDs per panel (INQ001 stock inquiry, JRN001 journal,
     REQ001 requisitions, ITM001 item entry, CRW001 crew)
   - Fast-path command line: RCV/ISS/CNT/REQ straight from the
     keyboard, plus GO <screen> navigation
   - Function keys: F3=Exit F5=Refresh F6=New SKU F9=Journal
     F10=Requisitions

   Stratton Warren heritage:
   - Issues carry a department / cost center code
   - Requisition queue: crew raises REQs, filler posts the issue
   - Par-level reorder report export

   All stock math and validation happen server-side inside
   transactions; this UI is just the terminal.
   ============================================================ */

const POLL_MS = 10000;
const MAX_QTY = 999999;
const LEN = { sku: 32, desc: 80, bin: 12, ref: 40, note: 60, op: 6, name: 40, dept: 8 };

const C = {
  bg: "#14171B",
  panel: "#1C2127",
  panel2: "#232A32",
  line: "#2A313A",
  text: "#EDE8DC",
  dim: "#8B94A3",
  amber: "#FFB000",
  green: "#4CD97B",
  red: "#FF5D45",
  blue: "#8FA6FF",
};
const MONO = "ui-monospace, 'IBM Plex Mono', Menlo, Consolas, monospace";
const COND = "'Barlow Condensed', 'Arial Narrow', system-ui, sans-serif";

const CATS = ["Dimensional", "Treated", "Sheet Goods", "Drywall", "Doors", "Trim", "Siding", "Hardware"];
const UNITS = ["PC", "SHT", "EA", "LF", "BF", "BDL", "BX"];

const SCREENS = {
  stock: "INQ001",
  log: "JRN001",
  reqs: "REQ001",
  add: "ITM001",
  crew: "CRW001",
};

const TX_STYLE = {
  RCV: { color: C.green, label: "RCV" },
  ISS: { color: C.red, label: "ISS" },
  ADJ: { color: C.amber, label: "ADJ" },
  NEW: { color: C.blue, label: "NEW" },
  DEL: { color: C.dim, label: "DEL" },
};

const fmtTs = (ts) => {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
const isToday = (ts) => new Date(ts).toDateString() === new Date().toDateString();
const isLow = (it) => it.qty <= it.reorder;
const age = (ts) => {
  const m = Math.max(0, Math.round((Date.now() - ts) / 60000));
  if (m < 60) return `${m}m`;
  if (m < 60 * 24) return `${Math.round(m / 60)}h`;
  return `${Math.round(m / 1440)}d`;
};

/* ---------- API ---------- */
async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(path, {
      credentials: "same-origin",
      headers: opts.body ? { "Content-Type": "application/json" } : {},
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    throw { status: 0, error: "NETWORK DOWN — CHECK WIFI" };
  }
  let json = null;
  try { json = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (!res.ok) throw { status: res.status, error: json?.error || `SERVER ERROR ${res.status}` };
  return json;
}

/* ---------- error boundary ---------- */
class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div style={{ background: C.bg, color: C.text, minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, fontFamily: MONO, padding: 24, textAlign: "center" }}>
        <div style={{ color: C.red, fontSize: 15, fontWeight: 600, letterSpacing: 1 }}>WHSE-01 DISPLAY FAULT</div>
        <div style={{ color: C.dim, fontSize: 12, lineHeight: 1.6 }}>The screen hit an error. Stock data on the server is not affected.</div>
        <button onClick={() => window.location.reload()} style={{ background: C.amber, color: "#14171B", border: "none", borderRadius: 8, padding: "14px 26px", fontSize: 15, fontWeight: 700, letterSpacing: 1, cursor: "pointer", fontFamily: COND }}>
          RELOAD
        </button>
      </div>
    );
  }
}

function App() {
  return <ErrorBoundary><Shell /></ErrorBoundary>;
}

function Shell() {
  const [user, setUser] = useState(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    api("/api/me").then((r) => setUser(r.user)).catch(() => {}).finally(() => setChecked(true));
  }, []);

  if (!checked) {
    return (
      <div style={{ background: C.bg, color: C.dim, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: MONO }}>
        <span>CONNECTING TO WHSE-01<Cursor /></span>
      </div>
    );
  }
  if (!user) return <Login onSignOn={setUser} />;
  return <WarehouseApp user={user} onSignOff={() => setUser(null)} />;
}

/* ============ sign-on ============ */

function Login({ onSignOn }) {
  const [initials, setInitials] = useState("");
  const [pin, setPin] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const ok = /^[A-Z0-9]{2,6}$/.test(initials) && /^[0-9]{4,8}$/.test(pin);

  const submit = async () => {
    if (!ok || busy) return;
    setBusy(true);
    setErr("");
    try {
      const r = await api("/api/login", { method: "POST", body: { initials, pin } });
      onSignOn(r.user);
    } catch (e) {
      setErr(e.error);
      setPin("");
    } finally {
      setBusy(false);
    }
  };

  const inputStyle = {
    width: "100%", background: C.bg, border: `1px solid ${C.line}`, borderRadius: 6,
    padding: "14px 12px", color: C.text, fontFamily: MONO, fontSize: 18,
    letterSpacing: 3, textAlign: "center", marginBottom: 12,
  };

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24, fontFamily: COND }}>
      <GlobalStyle />
      <div style={{ width: "100%", maxWidth: 340 }}>
        <div style={{ fontFamily: MONO, color: C.amber, fontSize: 15, letterSpacing: 1, marginBottom: 4, textAlign: "center" }}>
          WHSE-01 · SGN001<Cursor />
        </div>
        <div style={{ fontFamily: MONO, color: C.dim, fontSize: 11, textAlign: "center", marginBottom: 24 }}>OPERATOR SIGN-ON</div>
        <label style={{ fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, display: "block", marginBottom: 4 }}>INITIALS</label>
        <input value={initials} onChange={(e) => setInitials(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, LEN.op))}
          placeholder="JD" autoFocus autoComplete="username" style={inputStyle} />
        <label style={{ fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, display: "block", marginBottom: 4 }}>PIN</label>
        <input value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, "").slice(0, 8))}
          type="password" inputMode="numeric" autoComplete="current-password" placeholder="••••"
          onKeyDown={(e) => e.key === "Enter" && submit()} style={inputStyle} />
        {err && <div style={{ color: C.red, fontFamily: MONO, fontSize: 12, textAlign: "center", marginBottom: 12 }}>{err}</div>}
        <BigBtn color={C.amber} disabled={!ok || busy} onClick={submit}>{busy ? "SIGNING ON…" : "SIGN ON"}</BigBtn>
        <div style={{ color: C.dim, fontFamily: MONO, fontSize: 10, textAlign: "center", marginTop: 16, lineHeight: 1.6 }}>
          No account? Ask whoever runs the yard —<br />admins add crew under the CREW tab.
        </div>
      </div>
    </div>
  );
}

/* ============ main app ============ */

function WarehouseApp({ user, onSignOff }) {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("stock"); // stock | log | reqs | add | crew
  const [query, setQuery] = useState("");
  const [cat, setCat] = useState("ALL");
  const [lowOnly, setLowOnly] = useState(false);
  const [sheetSku, setSheetSku] = useState(null);
  const [toast, setToast] = useState(null);
  const [showHelp, setShowHelp] = useState(false);
  const toastTimer = useRef(null);

  const flash = useCallback((msg, color = C.green) => {
    setToast({ msg, color });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2600);
  }, []);

  /* sequence refreshes so a slow poll started before a mutation can't
     land late and overwrite fresher post-mutation state */
  const refreshSeq = useRef(0);
  const refresh = useCallback(async () => {
    const seq = ++refreshSeq.current;
    try {
      const next = await api("/api/state");
      if (seq === refreshSeq.current) setData(next);
    } catch (e) {
      if (seq !== refreshSeq.current) return;
      if (e.status === 401) onSignOff();
      else flash(e.error, C.red);
    }
  }, [onSignOff, flash]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const t = setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);
  useEffect(() => () => clearTimeout(toastTimer.current), []);

  /* run a mutation then re-pull authoritative state */
  const act = useCallback(async (path, body, msg, color) => {
    try {
      await api(path, { method: "POST", body });
      await refresh();
      if (msg) flash(msg, color);
      return true;
    } catch (e) {
      if (e.status === 401) onSignOff();
      else flash(e.error, C.red);
      await refresh().catch(() => {});
      return false;
    }
  }, [refresh, flash, onSignOff]);

  const items = data?.items || [];
  const tx = data?.tx || [];
  const depts = data?.depts || [];
  const reqs = data?.reqs || [];
  const openReqs = reqs.filter((r) => r.status === "OPEN");

  /* ---------- AS/400 fast-path command line ---------- */
  const runCmd = useCallback(async (raw) => {
    const parts = raw.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return;
    const verb = parts[0].toUpperCase();

    if (verb === "?" || verb === "HELP") { setShowHelp((h) => !h); return; }

    if (verb === "GO") {
      const dest = { STOCK: "stock", INQ: "stock", JRN: "log", JOURNAL: "log", REQ: "reqs", REQS: "reqs", ADD: "add", ITM: "add", CREW: "crew" }[(parts[1] || "").toUpperCase()];
      if (dest) { setTab(dest); flash(`GO ${SCREENS[dest]}`, C.blue); }
      else flash("GO WHERE? STOCK / JRN / REQ / ADD / CREW", C.red);
      return;
    }

    if (["RCV", "ISS", "CNT", "REQ"].includes(verb)) {
      const sku = (parts[1] || "").toUpperCase();
      /* whole token must be digits — "10X" is a typo, not a ten */
      const qtyOk = /^\d{1,6}$/.test(parts[2] || "");
      const qty = qtyOk ? parseInt(parts[2], 10) : NaN;
      const minQty = verb === "CNT" ? 0 : 1;
      if (!sku || !qtyOk || qty < minQty || qty > MAX_QTY) {
        flash(`USAGE: ${verb} SKU QTY${verb === "ISS" || verb === "REQ" ? " [DEPT]" : ""} — ? FOR HELP`, C.red);
        return;
      }
      /* for ISS/REQ, a third arg matching a dept code is the cost center;
         anything after that is the reference */
      let dept = "";
      let restFrom = 3;
      if ((verb === "ISS" || verb === "REQ") && parts[3] && depts.some((d) => d.code === parts[3].toUpperCase())) {
        dept = parts[3].toUpperCase();
        restFrom = 4;
      }
      const rest = parts.slice(restFrom).join(" ").slice(0, LEN.ref);

      if (verb === "RCV") await act("/api/receive", { sku, qty, ref: rest }, `RCV ${qty} · ${sku}`, C.green);
      if (verb === "ISS") await act("/api/issue", { sku, qty, dept, ref: rest }, `ISS ${qty} · ${sku}${dept ? ` → ${dept}` : ""}`, C.red);
      if (verb === "CNT") await act("/api/count", { sku, exact: qty, ref: rest }, `COUNT SET ${sku} = ${qty}`, C.amber);
      if (verb === "REQ") await act("/api/reqs", { sku, qty, dept, note: rest }, `REQ RAISED · ${qty} × ${sku}`, C.blue);
      return;
    }

    /* anything else is a stock search */
    setQuery(raw.trim());
    setTab("stock");
  }, [act, depts, flash]);

  /* ---------- function keys ---------- */
  useEffect(() => {
    const h = (e) => {
      if (!["F3", "F5", "F6", "F9", "F10"].includes(e.key)) return;
      e.preventDefault();
      if (e.key === "F3") { setSheetSku(null); setShowHelp(false); setTab("stock"); }
      if (e.key === "F5") { refresh(); flash("REFRESHED", C.blue); }
      if (e.key === "F6") setTab("add");
      if (e.key === "F9") setTab("log");
      if (e.key === "F10") setTab("reqs");
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [refresh, flash]);

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
    });

  const sheetItem = items.find((i) => i.sku === sheetSku) || null;

  if (!data) {
    return (
      <div style={{ background: C.bg, color: C.dim, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: MONO }}>
        <GlobalStyle />
        <span>LOADING STOCK FILE<Cursor /></span>
      </div>
    );
  }

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh", fontFamily: COND, paddingBottom: 104 }}>
      <GlobalStyle />

      {/* ===== session bar ===== */}
      <div style={{ position: "sticky", top: 0, zIndex: 30, background: C.bg, borderBottom: `1px solid ${C.line}` }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", padding: "10px 14px 6px" }}>
          <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: 1, color: C.amber }}>
            WHSE-01 · {SCREENS[tab]}<Cursor />
          </div>
          <div style={{ fontFamily: MONO, fontSize: 11, color: C.dim }}>
            OP:<span style={{ color: C.blue }}>{user.initials}</span>{user.role === "admin" ? " · ADMIN" : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, padding: "0 14px 8px", fontFamily: MONO }}>
          <Stat label="SKUS" value={items.length} />
          <Stat label="UNITS" value={unitCount.toLocaleString()} />
          <Stat label="LOW" value={lowCount} color={lowCount ? C.red : C.green} onClick={() => { setTab("stock"); setLowOnly(true); }} />
          <Stat label="REQS" value={openReqs.length} color={openReqs.length ? C.amber : C.dim} onClick={() => setTab("reqs")} />
          <Stat label="TX" value={todayTx} />
        </div>
        {/* command line */}
        <div style={{ padding: "0 14px 10px" }}>
          <CmdLine onRun={runCmd} />
          {showHelp && (
            <div style={{ marginTop: 8, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6, padding: "10px 12px", fontFamily: MONO, fontSize: 11, color: C.dim, lineHeight: 1.9 }}>
              <span style={{ color: C.amber }}>FAST PATH COMMANDS</span><br />
              RCV SKU QTY [REF] — receive stock<br />
              ISS SKU QTY [DEPT] [REF] — issue to a cost center<br />
              CNT SKU QTY — post a physical count<br />
              REQ SKU QTY [DEPT] [NOTE] — raise a requisition<br />
              GO STOCK / JRN / REQ / ADD / CREW — jump screens<br />
              anything else — search stock · <span style={{ color: C.amber }}>F3</span> exit <span style={{ color: C.amber }}>F5</span> refresh <span style={{ color: C.amber }}>F6</span> new <span style={{ color: C.amber }}>F9</span> journal <span style={{ color: C.amber }}>F10</span> reqs
            </div>
          )}
        </div>
      </div>

      {/* ===== STOCK / INQ001 ===== */}
      {tab === "stock" && (
        <div>
          <div style={{ padding: "12px 14px 4px" }}>
            <input value={query} onChange={(e) => setQuery(e.target.value.slice(0, LEN.desc))}
              placeholder="SEARCH SKU / DESC / BIN" inputMode="search" aria-label="Search stock"
              style={{ width: "100%", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6, padding: "14px 14px", color: C.text, fontFamily: MONO, fontSize: 15, letterSpacing: 1 }} />
          </div>
          <div style={{ display: "flex", gap: 6, overflowX: "auto", padding: "10px 14px" }}>
            <Chip active={lowOnly} color={C.red} onClick={() => setLowOnly(!lowOnly)}>⚠ LOW</Chip>
            <Chip active={cat === "ALL"} onClick={() => setCat("ALL")}>ALL</Chip>
            {CATS.map((c) => (
              <Chip key={c} active={cat === c} onClick={() => setCat(cat === c ? "ALL" : c)}>{c.toUpperCase()}</Chip>
            ))}
          </div>

          {items.length === 0 ? (
            <div style={{ padding: "48px 24px", textAlign: "center" }}>
              <div style={{ fontFamily: MONO, color: C.dim, fontSize: 13, lineHeight: 1.7 }}>
                NO ITEMS ON FILE.<br />Add your first SKU, or load sample lumber stock to try the workflow.
              </div>
              <button onClick={() => act("/api/seed", {}, "Sample stock loaded", C.blue)} style={{
                marginTop: 20, background: C.amber, color: "#14171B", border: "none", borderRadius: 8,
                padding: "14px 22px", fontSize: 15, fontWeight: 700, letterSpacing: 1, cursor: "pointer", fontFamily: COND,
              }}>
                LOAD SAMPLE STOCK
              </button>
            </div>
          ) : visible.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 13 }}>
              NO MATCH. Clear filters or check the SKU.
            </div>
          ) : (
            <div style={{ padding: "2px 14px" }}>
              {visible.map((it) => (
                <button key={it.sku} onClick={() => setSheetSku(it.sku)} style={{
                  width: "100%", textAlign: "left", background: C.panel, border: `1px solid ${isLow(it) ? C.red + "66" : C.line}`,
                  borderRadius: 8, padding: "12px 14px", marginBottom: 8, color: C.text, cursor: "pointer",
                  display: "flex", alignItems: "center", gap: 12,
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: MONO, fontSize: 14, fontWeight: 600, color: C.amber, letterSpacing: 0.5 }}>{it.sku}</div>
                    <div style={{ fontSize: 17, fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{it.desc}</div>
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

      {/* ===== JOURNAL / JRN001 ===== */}
      {tab === "log" && (
        <div style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
            <ToolLink href="/api/export/stock.csv">STOCK CSV</ToolLink>
            <ToolLink href="/api/export/journal.csv">JOURNAL CSV</ToolLink>
            <ToolLink href="/api/export/reorder.csv">REORDER CSV</ToolLink>
            {user.role === "admin" && <ToolLink href="/api/export/backup.json">BACKUP</ToolLink>}
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
                    <span style={{ color: s.color, border: `1px solid ${s.color}66`, borderRadius: 4, fontSize: 11, fontWeight: 600, padding: "2px 6px", minWidth: 42, textAlign: "center" }}>{s.label}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>
                        {t.sku} <span style={{ color: s.color }}>{t.qty > 0 ? `+${t.qty}` : t.qty}</span>
                        <span style={{ color: C.dim }}> → {t.bal} {t.unit}</span>
                        {t.dept && <span style={{ color: C.blue }}> · {t.dept}</span>}
                      </div>
                      <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>
                        {fmtTs(t.ts)}{t.by ? ` · ${t.by}` : ""}{t.ref ? ` · REF ${t.ref}` : ""}{t.note ? ` · ${t.note}` : ""}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div style={{ textAlign: "center", color: C.dim, fontFamily: MONO, fontSize: 11, padding: "10px 0" }}>
                SHOWING LAST {tx.length} — FULL HISTORY IN JOURNAL CSV
              </div>
            </>
          )}
        </div>
      )}

      {/* ===== REQUISITIONS / REQ001 ===== */}
      {tab === "reqs" && (
        <ReqsTab reqs={reqs} items={items} depts={depts} user={user} act={act} />
      )}

      {/* ===== ADD ITEM / ITM001 ===== */}
      {tab === "add" && (
        <AddForm onAdd={async (item) => {
          const ok = await act("/api/items", item, `NEW SKU ${item.sku} added`, C.blue);
          if (ok) { setTab("stock"); setQuery(item.sku); }
        }} />
      )}

      {/* ===== CREW / CRW001 ===== */}
      {tab === "crew" && <CrewTab user={user} flash={flash} onSignOff={async () => {
        /* only leave the authenticated screen once the server has
           actually cleared the session cookie */
        try {
          await api("/api/logout", { method: "POST", body: {} });
          onSignOff();
        } catch (e) {
          if (e.status === 401) onSignOff();
          else flash(e.error || "SIGN-OFF FAILED — STILL SIGNED ON", C.red);
        }
      }} />}

      {/* ===== item action sheet ===== */}
      {sheetItem && (
        <ItemSheet
          item={sheetItem}
          depts={depts}
          isAdmin={user.role === "admin"}
          onClose={() => setSheetSku(null)}
          onReceive={(sku, qty, ref) => act("/api/receive", { sku, qty, ref }, `RCV ${qty} · ${sku}`, C.green)}
          onIssue={(sku, qty, ref, dept) => act("/api/issue", { sku, qty, ref, dept }, `ISS ${qty} · ${sku}${dept ? ` → ${dept}` : ""}`, C.red)}
          onCount={(sku, exact, ref) => act("/api/count", { sku, exact, ref }, `COUNT SET ${sku} = ${exact}`, C.amber)}
          onUpdate={async (sku, patch) => {
            try {
              await api(`/api/items/${encodeURIComponent(sku)}`, { method: "PATCH", body: patch });
              await refresh();
              flash(`SKU ${sku} updated`, C.amber);
              return true;
            } catch (e) {
              flash(e.error, C.red);
              return false;
            }
          }}
          onDelete={async (sku) => {
            try {
              await api(`/api/items/${encodeURIComponent(sku)}`, { method: "DELETE" });
              await refresh();
              flash(`SKU ${sku} removed`, C.dim);
              setSheetSku(null);
            } catch (e) { flash(e.error, C.red); }
          }}
        />
      )}

      {/* ===== toast ===== */}
      {toast && (
        <div role="status" style={{
          position: "fixed", left: 14, right: 14, bottom: 96, zIndex: 60,
          background: C.panel2, border: `1px solid ${toast.color}`, color: toast.color,
          borderRadius: 8, padding: "12px 14px", fontFamily: MONO, fontSize: 13, fontWeight: 600, textAlign: "center",
        }}>
          {toast.msg}
        </div>
      )}

      {/* ===== function key bar (wide screens) ===== */}
      <div className="fkeys" style={{
        position: "fixed", bottom: 54, left: 0, right: 0, zIndex: 39,
        justifyContent: "center", gap: 18, background: C.bg, borderTop: `1px solid ${C.line}`,
        padding: "5px 0", fontFamily: MONO, fontSize: 10, color: C.dim, letterSpacing: 1,
      }}>
        <span><b style={{ color: C.amber }}>F3</b>=EXIT</span>
        <span><b style={{ color: C.amber }}>F5</b>=REFRESH</span>
        <span><b style={{ color: C.amber }}>F6</b>=NEW SKU</span>
        <span><b style={{ color: C.amber }}>F9</b>=JOURNAL</span>
        <span><b style={{ color: C.amber }}>F10</b>=REQS</span>
      </div>

      {/* ===== bottom nav ===== */}
      <div style={{
        position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 40,
        display: "flex", background: C.bg, borderTop: `1px solid ${C.line}`,
        paddingBottom: "env(safe-area-inset-bottom)",
      }}>
        <NavBtn active={tab === "stock"} onClick={() => setTab("stock")} label="STOCK" />
        <NavBtn active={tab === "log"} onClick={() => setTab("log")} label="JRN" />
        <NavBtn active={tab === "reqs"} onClick={() => setTab("reqs")} label={openReqs.length ? `REQ·${openReqs.length}` : "REQ"} />
        <NavBtn active={tab === "add"} onClick={() => setTab("add")} label="+SKU" />
        <NavBtn active={tab === "crew"} onClick={() => setTab("crew")} label="CREW" />
      </div>
    </div>
  );
}

/* ============ command line ============ */

function CmdLine({ onRun }) {
  const [val, setVal] = useState("");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6, padding: "0 12px" }}>
      <span style={{ fontFamily: MONO, color: C.amber, fontSize: 14, fontWeight: 600 }}>===&gt;</span>
      <input
        value={val}
        onChange={(e) => setVal(e.target.value.slice(0, 120))}
        onKeyDown={(e) => {
          if (e.key === "Enter" && val.trim()) { onRun(val); setVal(""); }
        }}
        placeholder="RCV SKU QTY · ISS SKU QTY DEPT · ? = HELP"
        aria-label="Command line"
        autoCapitalize="characters"
        autoCorrect="off"
        spellCheck={false}
        style={{ flex: 1, background: "transparent", border: "none", padding: "11px 0", color: C.text, fontFamily: MONO, fontSize: 13, letterSpacing: 0.5 }}
      />
    </div>
  );
}

/* ============ requisitions ============ */

function ReqsTab({ reqs, items, depts, user, act }) {
  const [f, setF] = useState({ sku: "", qty: "", dept: "", note: "" });
  const open = reqs.filter((r) => r.status === "OPEN");
  const closed = reqs.filter((r) => r.status !== "OPEN");
  const q = parseInt(f.qty, 10);
  const ready = /^[A-Z0-9][A-Z0-9-]{1,31}$/.test(f.sku) && Number.isInteger(q) && q > 0;

  const inputStyle = {
    width: "100%", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
    padding: "12px 12px", color: C.text, fontFamily: MONO, fontSize: 15,
  };
  const labelStyle = { fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, margin: "10px 0 4px", display: "block" };

  const reqRow = (r, actions) => (
    <div key={r.id} style={{ display: "flex", gap: 10, alignItems: "center", borderBottom: `1px solid ${C.line}`, padding: "10px 2px", fontFamily: MONO }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600 }}>
          <span style={{ color: C.dim }}>#{r.id}</span> {r.sku} <span style={{ color: C.amber }}>×{r.qty}</span>
          {r.dept && <span style={{ color: C.blue }}> · {r.dept}</span>}
        </div>
        <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>
          {r.status === "OPEN"
            ? `${age(r.ts)} ago · BY ${r.by}${r.note ? ` · ${r.note}` : ""}`
            : `${r.status} BY ${r.filled_by} · RAISED BY ${r.by}`}
        </div>
      </div>
      {actions}
    </div>
  );

  return (
    <div style={{ padding: "12px 14px 24px" }}>
      <div style={{ fontFamily: MONO, color: C.amber, fontSize: 12, fontWeight: 600, letterSpacing: 1, marginBottom: 4 }}>RAISE REQUISITION</div>
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ flex: 2 }}>
          <label style={labelStyle}>SKU</label>
          <input value={f.sku} list="req-skus"
            onChange={(e) => setF({ ...f, sku: e.target.value.toUpperCase().replace(/[^A-Z0-9-]/g, "").slice(0, LEN.sku) })}
            placeholder="2X4X8-SPF" style={inputStyle} />
          <datalist id="req-skus">
            {items.map((i) => <option key={i.sku} value={i.sku}>{i.desc}</option>)}
          </datalist>
        </div>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>QTY</label>
          <input value={f.qty} onChange={(e) => setF({ ...f, qty: e.target.value.replace(/\D/g, "").slice(0, 6) })} inputMode="numeric" placeholder="0" style={inputStyle} />
        </div>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>DEPT</label>
          <select value={f.dept} onChange={(e) => setF({ ...f, dept: e.target.value })} style={inputStyle}>
            <option value="">—</option>
            {depts.map((d) => <option key={d.code} value={d.code}>{d.code}</option>)}
          </select>
        </div>
      </div>
      <label style={labelStyle}>NOTE (OPTIONAL)</label>
      <input value={f.note} onChange={(e) => setF({ ...f, note: e.target.value.slice(0, LEN.note) })} placeholder="SMITH JOB FRIDAY AM" style={{ ...inputStyle, marginBottom: 12 }} />
      <BigBtn color={C.blue} disabled={!ready} onClick={async () => {
        const ok = await act("/api/reqs", { sku: f.sku, qty: q, dept: f.dept, note: f.note.trim() }, `REQ RAISED · ${q} × ${f.sku}`, C.blue);
        if (ok) setF({ sku: "", qty: "", dept: "", note: "" });
      }}>
        SUBMIT REQ
      </BigBtn>

      <div style={{ fontFamily: MONO, color: C.amber, fontSize: 12, fontWeight: 600, letterSpacing: 1, margin: "24px 0 2px" }}>
        OPEN REQS ({open.length})
      </div>
      {open.length === 0 ? (
        <div style={{ padding: "18px 0", color: C.dim, fontFamily: MONO, fontSize: 12 }}>QUEUE CLEAR.</div>
      ) : (
        open.map((r) => reqRow(r, (
          <>
            <button onClick={() => act(`/api/reqs/${r.id}/fill`, {}, `REQ #${r.id} FILLED — ISS POSTED`, C.green)}
              style={{ background: "none", border: `1px solid ${C.green}66`, borderRadius: 6, color: C.green, fontFamily: MONO, fontSize: 11, fontWeight: 600, padding: "8px 12px", cursor: "pointer" }}>
              FILL
            </button>
            {(r.by === user.initials || user.role === "admin") && (
              <button onClick={() => act(`/api/reqs/${r.id}/cancel`, {}, `REQ #${r.id} CANCELLED`, C.dim)}
                style={{ background: "none", border: `1px solid ${C.line}`, borderRadius: 6, color: C.dim, fontFamily: MONO, fontSize: 11, padding: "8px 10px", cursor: "pointer" }}>
                ✕
              </button>
            )}
          </>
        )))
      )}

      {closed.length > 0 && (
        <>
          <div style={{ fontFamily: MONO, color: C.dim, fontSize: 11, fontWeight: 600, letterSpacing: 1, margin: "22px 0 2px" }}>
            RECENT — LAST 7 DAYS
          </div>
          {closed.map((r) => reqRow(r, null))}
        </>
      )}
    </div>
  );
}

/* ============ crew tab ============ */

function CrewTab({ user, flash, onSignOff }) {
  const isAdmin = user.role === "admin";
  const [users, setUsers] = useState(null);
  const [allDepts, setAllDepts] = useState(null);
  const [oldPin, setOldPin] = useState("");
  const [newPin, setNewPin] = useState("");
  const [nu, setNu] = useState({ initials: "", name: "", pin: "", role: "operator" });
  const [nd, setNd] = useState({ code: "", name: "" });

  const loadAdmin = useCallback(() => {
    if (!isAdmin) return;
    api("/api/users").then((r) => setUsers(r.users)).catch((e) => flash(e.error, C.red));
    api("/api/depts").then((r) => setAllDepts(r.depts)).catch((e) => flash(e.error, C.red));
  }, [isAdmin, flash]);
  useEffect(loadAdmin, [loadAdmin]);

  const inputStyle = {
    width: "100%", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 6,
    padding: "12px 12px", color: C.text, fontFamily: MONO, fontSize: 15,
  };
  const labelStyle = { fontSize: 11, letterSpacing: 1, color: C.dim, fontFamily: MONO, margin: "12px 0 4px", display: "block" };
  const sectionStyle = { fontFamily: MONO, color: C.amber, fontSize: 12, fontWeight: 600, letterSpacing: 1, margin: "22px 0 4px" };
  const smallBtn = (color) => ({
    background: "none", border: `1px solid ${color}66`, borderRadius: 6, color,
    fontFamily: MONO, fontSize: 11, padding: "6px 10px", cursor: "pointer",
  });

  return (
    <div style={{ padding: "12px 14px 24px" }}>
      <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: 14, fontFamily: MONO }}>
        <div style={{ fontSize: 14, fontWeight: 600 }}>{user.initials} <span style={{ color: C.dim, fontWeight: 400 }}>{user.name}</span></div>
        <div style={{ fontSize: 11, color: user.role === "admin" ? C.amber : C.dim, marginTop: 2 }}>{user.role.toUpperCase()}</div>
      </div>

      <div style={sectionStyle}>CHANGE MY PIN</div>
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>CURRENT PIN</label>
          <input value={oldPin} onChange={(e) => setOldPin(e.target.value.replace(/\D/g, "").slice(0, 8))} type="password" inputMode="numeric" style={inputStyle} />
        </div>
        <div style={{ flex: 1 }}>
          <label style={labelStyle}>NEW PIN (4–8 DIGITS)</label>
          <input value={newPin} onChange={(e) => setNewPin(e.target.value.replace(/\D/g, "").slice(0, 8))} type="password" inputMode="numeric" style={inputStyle} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <BigBtn color={C.amber} disabled={!/^[0-9]{4,8}$/.test(newPin) || !oldPin} onClick={async () => {
          try {
            await api("/api/me/pin", { method: "POST", body: { oldPin, newPin } });
            setOldPin(""); setNewPin("");
            flash("PIN CHANGED", C.green);
          } catch (e) { flash(e.error, C.red); }
        }}>
          UPDATE PIN
        </BigBtn>
      </div>

      {isAdmin && (
        <>
          <div style={sectionStyle}>ADD CREW MEMBER</div>
          <div style={{ display: "flex", gap: 10 }}>
            <div style={{ width: 110 }}>
              <label style={labelStyle}>INITIALS</label>
              <input value={nu.initials} onChange={(e) => setNu({ ...nu, initials: e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, LEN.op) })} style={inputStyle} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>NAME</label>
              <input value={nu.name} onChange={(e) => setNu({ ...nu, name: e.target.value.slice(0, LEN.name) })} style={inputStyle} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>PIN (4–8 DIGITS)</label>
              <input value={nu.pin} onChange={(e) => setNu({ ...nu, pin: e.target.value.replace(/\D/g, "").slice(0, 8) })} inputMode="numeric" style={inputStyle} />
            </div>
            <div style={{ width: 140 }}>
              <label style={labelStyle}>ROLE</label>
              <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })} style={inputStyle}>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <BigBtn color={C.blue} disabled={!/^[A-Z0-9]{2,6}$/.test(nu.initials) || !/^[0-9]{4,8}$/.test(nu.pin)} onClick={async () => {
              try {
                await api("/api/users", { method: "POST", body: nu });
                setNu({ initials: "", name: "", pin: "", role: "operator" });
                flash(`${nu.initials} ADDED TO CREW`, C.blue);
                loadAdmin();
              } catch (e) { flash(e.error, C.red); }
            }}>
              ADD TO CREW
            </BigBtn>
          </div>

          <div style={sectionStyle}>CREW ROSTER</div>
          {(users || []).map((u) => (
            <div key={u.id} style={{ display: "flex", alignItems: "center", gap: 10, borderBottom: `1px solid ${C.line}`, padding: "10px 2px", fontFamily: MONO }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: u.active ? C.text : C.dim, textDecoration: u.active ? "none" : "line-through" }}>{u.initials}</span>
                <span style={{ fontSize: 11, color: C.dim }}> {u.name}</span>
                {u.role === "admin" && <span style={{ fontSize: 10, color: C.amber }}> · ADMIN</span>}
              </div>
              <button onClick={async () => {
                const pin = window.prompt(`New PIN for ${u.initials} (4–8 digits):`);
                if (pin == null) return;
                try {
                  await api(`/api/users/${u.id}`, { method: "PATCH", body: { pin } });
                  flash(`PIN RESET FOR ${u.initials}`, C.amber);
                } catch (e) { flash(e.error, C.red); }
              }} style={smallBtn(C.blue)}>
                RESET PIN
              </button>
              <button onClick={async () => {
                try {
                  await api(`/api/users/${u.id}`, { method: "PATCH", body: { active: !u.active } });
                  flash(`${u.initials} ${u.active ? "DEACTIVATED" : "REACTIVATED"}`, C.amber);
                  loadAdmin();
                } catch (e) { flash(e.error, C.red); }
              }} style={smallBtn(u.active ? C.red : C.green)}>
                {u.active ? "DISABLE" : "ENABLE"}
              </button>
            </div>
          ))}

          <div style={sectionStyle}>DEPARTMENTS / COST CENTERS</div>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
            <div style={{ width: 120 }}>
              <label style={labelStyle}>CODE</label>
              <input value={nd.code} onChange={(e) => setNd({ ...nd, code: e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, LEN.dept) })} placeholder="PAINT" style={inputStyle} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>NAME</label>
              <input value={nd.name} onChange={(e) => setNd({ ...nd, name: e.target.value.slice(0, LEN.name) })} placeholder="Paint shop" style={inputStyle} />
            </div>
            <button disabled={!/^[A-Z0-9]{2,8}$/.test(nd.code)} onClick={async () => {
              try {
                await api("/api/depts", { method: "POST", body: nd });
                setNd({ code: "", name: "" });
                flash(`DEPT ${nd.code} ADDED`, C.blue);
                loadAdmin();
              } catch (e) { flash(e.error, C.red); }
            }} style={{ ...smallBtn(C.blue), padding: "13px 14px", opacity: /^[A-Z0-9]{2,8}$/.test(nd.code) ? 1 : 0.4 }}>
              ADD
            </button>
          </div>
          {(allDepts || []).map((d) => (
            <div key={d.code} style={{ display: "flex", alignItems: "center", gap: 10, borderBottom: `1px solid ${C.line}`, padding: "10px 2px", fontFamily: MONO }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: d.active ? C.blue : C.dim, textDecoration: d.active ? "none" : "line-through" }}>{d.code}</span>
                <span style={{ fontSize: 11, color: C.dim }}> {d.name}</span>
              </div>
              <button onClick={async () => {
                try {
                  await api(`/api/depts/${encodeURIComponent(d.code)}`, { method: "PATCH", body: { active: !d.active } });
                  flash(`DEPT ${d.code} ${d.active ? "DISABLED" : "ENABLED"}`, C.amber);
                  loadAdmin();
                } catch (e) { flash(e.error, C.red); }
              }} style={smallBtn(d.active ? C.red : C.green)}>
                {d.active ? "DISABLE" : "ENABLE"}
              </button>
            </div>
          ))}
        </>
      )}

      <button onClick={onSignOff} style={{
        width: "100%", marginTop: 28, background: "transparent", border: `1px solid ${C.line}`,
        color: C.dim, borderRadius: 8, padding: "12px 0", fontFamily: MONO, fontSize: 13,
        fontWeight: 600, letterSpacing: 1, cursor: "pointer",
      }}>
        SIGN OFF
      </button>
    </div>
  );
}

/* ============ small parts ============ */

function GlobalStyle() {
  return (
    <style>{`
      * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
      body { margin: 0; background: ${C.bg}; }
      input, select { outline: none; }
      input:focus, select:focus, button:focus-visible { box-shadow: 0 0 0 2px ${C.amber}55; }
      ::placeholder { color: ${C.dim}; opacity: .7; }
      @keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
      .curs { display:inline-block; width:.55em; height:1em; background:${C.amber}; vertical-align:-0.12em; animation: blink 1.1s step-end infinite; }
      @media (prefers-reduced-motion: reduce) { .curs { animation: none; } }
      .fkeys { display: none; }
      @media (min-width: 700px) { .fkeys { display: flex; } }
      ::-webkit-scrollbar { height: 0; width: 0; }
    `}</style>
  );
}

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
      fontSize: 13, fontWeight: 700, letterSpacing: 0.5, cursor: "pointer", fontFamily: COND,
    }}>
      {children}
    </button>
  );
}

function ToolLink({ children, href }) {
  return (
    <a href={href} style={{
      flex: 1, display: "block", textAlign: "center", background: C.panel, border: `1px solid ${C.line}`,
      borderRadius: 6, color: C.blue, padding: "10px 0", fontFamily: MONO, fontSize: 11,
      fontWeight: 600, letterSpacing: 0.5, textDecoration: "none",
    }}>
      ⭳ {children}
    </a>
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

/* ============ item action sheet ============ */

function ItemSheet({ item, depts, isAdmin, onClose, onReceive, onIssue, onCount, onUpdate, onDelete }) {
  const [mode, setMode] = useState("move");
  const [qty, setQty] = useState("");
  const [ref, setRef] = useState("");
  const [dept, setDept] = useState("");
  const [exact, setExact] = useState("");
  const [edit, setEdit] = useState({ desc: item.desc, bin: item.bin, reorder: item.reorder, cost: item.cost });
  const [confirmDel, setConfirmDel] = useState(false);

  useEffect(() => {
    setMode("move"); setQty(""); setRef(""); setDept(""); setExact("");
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
            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <div style={{ flex: 2 }}>
                <label style={labelStyle}>REFERENCE — PO# / JOB# (OPTIONAL)</label>
                <input value={ref} onChange={(e) => setRef(e.target.value.slice(0, LEN.ref))} maxLength={LEN.ref} placeholder="PO-1042, SMITH JOB…" style={inputStyle} />
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>DEPT (ISSUE)</label>
                <select value={dept} onChange={(e) => setDept(e.target.value)} style={inputStyle}>
                  <option value="">—</option>
                  {depts.map((d) => <option key={d.code} value={d.code}>{d.code}</option>)}
                </select>
              </div>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <BigBtn color={C.green} disabled={!validQty} onClick={async () => { if (await onReceive(item.sku, q, ref.trim())) onClose(); }}>
                RECEIVE +{validQty ? q : ""}
              </BigBtn>
              <BigBtn color={C.red} disabled={!validQty || q > item.qty} onClick={async () => { if (await onIssue(item.sku, q, ref.trim(), dept)) onClose(); }}>
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
            <input value={ref} onChange={(e) => setRef(e.target.value.slice(0, LEN.ref))} maxLength={LEN.ref} placeholder="CYCLE COUNT" style={{ ...inputStyle, marginBottom: 16 }} />
            <BigBtn color={C.amber} disabled={!validExact} onClick={async () => { if (await onCount(item.sku, ex, ref.trim())) onClose(); }}>
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
            <BigBtn color={C.amber} onClick={async () => {
              /* Number() validates the whole token — "1.2.3" is NaN, not 1.2;
                 malformed input keeps the stored value instead of mutating it */
              const nr = Number(edit.reorder);
              const nc = Number(edit.cost);
              const ok = await onUpdate(item.sku, {
                desc: String(edit.desc).trim() || item.desc,
                cat: item.cat,
                unit: item.unit,
                bin: String(edit.bin).trim() || item.bin,
                reorder: Number.isInteger(nr) && nr >= 0 ? nr : item.reorder,
                cost: Number.isFinite(nc) && nc >= 0 ? nc : item.cost,
              });
              if (ok) onClose();
            }}>
              SAVE CHANGES
            </BigBtn>
            {isAdmin ? (
              <button onClick={() => (confirmDel ? onDelete(item.sku) : setConfirmDel(true))} style={{
                width: "100%", marginTop: 12, background: confirmDel ? C.red : "transparent", border: `1px solid ${C.red}${confirmDel ? "" : "66"}`,
                color: confirmDel ? "#14171B" : C.red, borderRadius: 8, padding: "12px 0", fontFamily: MONO,
                fontSize: 13, fontWeight: 600, letterSpacing: 1, cursor: "pointer",
              }}>
                {confirmDel ? `TAP AGAIN — WRITES OFF ${item.qty} ${item.unit}` : "REMOVE SKU FROM FILE"}
              </button>
            ) : (
              <div style={{ color: C.dim, fontFamily: MONO, fontSize: 11, marginTop: 12, textAlign: "center" }}>
                REMOVING A SKU NEEDS AN ADMIN
              </div>
            )}
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
      <input value={f.sku}
        onChange={(e) => setF({ ...f, sku: e.target.value.toUpperCase().replace(/\s/g, "-").replace(/[^A-Z0-9-]/g, "").slice(0, LEN.sku) })}
        maxLength={LEN.sku} placeholder="2X8X12-SPF" style={inputStyle} />
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
        <BigBtn color={C.amber} disabled={!ready} onClick={() => {
          const nc = Number(f.cost);
          onAdd({
            sku: f.sku.trim(),
            desc: f.desc.trim(),
            cat: f.cat,
            unit: f.unit,
            bin: f.bin.trim(),
            qty: parseInt(f.qty, 10) || 0,
            reorder: parseInt(f.reorder, 10) || 0,
            cost: Number.isFinite(nc) && nc >= 0 ? nc : 0,
          });
        }}>
          ADD TO ITEM FILE
        </BigBtn>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
