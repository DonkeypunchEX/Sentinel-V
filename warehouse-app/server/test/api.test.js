"use strict";
/* End-to-end API tests: auth, movements, dept coding, requisitions,
   permissions, rate limiting, exports, and concurrent-issue safety.
   Run with: npm test */

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

process.env.WHSE_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "whse-test-"));

/* capture the first-run admin PIN that bootstrap prints */
let adminPin = null;
const origLog = console.log;
console.log = (...a) => {
  const m = String(a.join(" ")).match(/PIN:\s+(\d{8})/);
  if (m) adminPin = m[1];
};
const app = require("../server.js");
console.log = origLog;

let base;
let adminCookie = "";
let opCookie = "";

async function req(method, p, body, cookie) {
  const res = await fetch(base + p, {
    method,
    headers: { "Content-Type": "application/json", cookie: cookie ?? adminCookie },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.clone().json(); } catch (_) { /* csv or empty */ }
  return { status: res.status, json, res };
}

const grabCookie = (res) => res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

test("WHSE-01 API", async (t) => {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.on("listening", r));
  base = `http://127.0.0.1:${server.address().port}`;

  await t.test("unauthenticated requests are rejected", async () => {
    const r = await req("GET", "/api/state", null, "");
    assert.strictEqual(r.status, 401);
  });

  await t.test("bootstrap admin signs on with printed PIN", async () => {
    assert.ok(adminPin, "bootstrap PIN was printed");
    const r = await req("POST", "/api/login", { initials: "ADMIN", pin: adminPin }, "");
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.user.role, "admin");
    adminCookie = grabCookie(r.res);
    assert.match(adminCookie, /whse_sid=/);
  });

  await t.test("seed loads once, then refuses", async () => {
    assert.strictEqual((await req("POST", "/api/seed", {})).status, 200);
    assert.strictEqual((await req("POST", "/api/seed", {})).status, 409);
    const s = await req("GET", "/api/state");
    assert.strictEqual(s.json.items.length, 14);
    assert.ok(s.json.depts.length >= 6, "default cost centers seeded");
  });

  await t.test("receive, issue with dept, count", async () => {
    let r = await req("POST", "/api/receive", { sku: "2X4X8-SPF", qty: 88, ref: "PO-1" });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.item.qty, 500);

    r = await req("POST", "/api/issue", { sku: "2X4X8-SPF", qty: 100, dept: "YARD", ref: "JOB-9" });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.item.qty, 400);

    r = await req("POST", "/api/count", { sku: "2X4X8-SPF", exact: 399, ref: "CYCLE" });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.delta, -1);

    const s = await req("GET", "/api/state");
    const iss = s.json.tx.find((x) => x.code === "ISS");
    assert.strictEqual(iss.dept, "YARD");
    assert.strictEqual(iss.by, "ADMIN");
  });

  await t.test("issue is short-checked and dept-validated", async () => {
    let r = await req("POST", "/api/issue", { sku: "DR-EXT-36", qty: 9999 });
    assert.strictEqual(r.status, 409);
    assert.match(r.json.error, /SHORT/);
    r = await req("POST", "/api/issue", { sku: "DR-EXT-36", qty: 1, dept: "NOPE" });
    assert.strictEqual(r.status, 400);
    assert.match(r.json.error, /NOT ON FILE/);
  });

  await t.test("bad payloads are rejected, not crashed on", async () => {
    assert.strictEqual((await req("POST", "/api/receive", { sku: "../etc", qty: 1 })).status, 400);
    assert.strictEqual((await req("POST", "/api/receive", { sku: "OSB-716", qty: "1e99" })).status, 400);
    assert.strictEqual((await req("POST", "/api/receive", { sku: "OSB-716", qty: -5 })).status, 400);
    const raw = await fetch(base + "/api/receive", {
      method: "POST",
      headers: { "Content-Type": "application/json", cookie: adminCookie },
      body: "{not json",
    });
    assert.strictEqual(raw.status, 400);
  });

  await t.test("cross-origin mutation is blocked", async () => {
    const raw = await fetch(base + "/api/receive", {
      method: "POST",
      headers: { "Content-Type": "application/json", cookie: adminCookie, origin: "https://evil.example" },
      body: JSON.stringify({ sku: "OSB-716", qty: 1 }),
    });
    assert.strictEqual(raw.status, 403);
  });

  await t.test("admin creates operator; operator has limited powers", async () => {
    let r = await req("POST", "/api/users", { initials: "JD", name: "Crew Member", pin: "4321", role: "operator" });
    assert.strictEqual(r.status, 200);

    r = await req("POST", "/api/login", { initials: "JD", pin: "4321" }, "");
    assert.strictEqual(r.status, 200);
    opCookie = grabCookie(r.res);

    /* operators can move stock */
    r = await req("POST", "/api/issue", { sku: "OSB-716", qty: 5, dept: "SHOP" }, opCookie);
    assert.strictEqual(r.status, 200);
    /* but not manage users, depts, or delete items */
    assert.strictEqual((await req("GET", "/api/users", null, opCookie)).status, 403);
    assert.strictEqual((await req("POST", "/api/depts", { code: "XX" }, opCookie)).status, 403);
    assert.strictEqual((await req("DELETE", "/api/items/OSB-716", null, opCookie)).status, 403);
  });

  await t.test("requisition lifecycle: raise → fill posts ISS; cancel is guarded", async () => {
    let r = await req("POST", "/api/reqs", { sku: "CDX-12", qty: 10, dept: "DELIV", note: "friday load" }, opCookie);
    assert.strictEqual(r.status, 200);
    const reqId = r.json.req.id;

    /* admin fills it — stock drops, journal shows REQ# + dept + both parties */
    const before = (await req("GET", "/api/state")).json.items.find((i) => i.sku === "CDX-12").qty;
    r = await req("POST", `/api/reqs/${reqId}/fill`, {});
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.item.qty, before - 10);
    assert.strictEqual((await req("POST", `/api/reqs/${reqId}/fill`, {})).status, 409);

    const s = await req("GET", "/api/state");
    const iss = s.json.tx.find((x) => x.ref === `REQ#${reqId}`);
    assert.ok(iss, "fill posted an ISS journal entry");
    assert.strictEqual(iss.dept, "DELIV");
    assert.match(iss.note, /JD/);

    /* an unrelated operator cannot cancel someone else's req */
    r = await req("POST", "/api/reqs", { sku: "CDX-12", qty: 2 }, adminCookie);
    const otherId = r.json.req.id;
    assert.strictEqual((await req("POST", `/api/reqs/${otherId}/cancel`, {}, opCookie)).status, 403);
    assert.strictEqual((await req("POST", `/api/reqs/${otherId}/cancel`, {}, adminCookie)).status, 200);

    /* oversize req cannot be filled */
    r = await req("POST", "/api/reqs", { sku: "DR-EXT-36", qty: 5000 }, opCookie);
    assert.strictEqual((await req("POST", `/api/reqs/${r.json.req.id}/fill`, {})).status, 409);
  });

  await t.test("PIN change revokes old sessions; admin reset revokes target's", async () => {
    /* JD changes their own PIN: this device gets a fresh cookie, the old one dies */
    const staleCookie = opCookie;
    const r = await req("POST", "/api/me/pin", { oldPin: "4321", newPin: "9876" }, opCookie);
    assert.strictEqual(r.status, 200);
    opCookie = grabCookie(r.res);
    assert.strictEqual((await req("GET", "/api/state", null, opCookie)).status, 200);
    assert.strictEqual((await req("GET", "/api/state", null, staleCookie)).status, 401);

    /* admin resets JD's PIN: JD's sessions all die until they sign back on */
    const users = (await req("GET", "/api/users")).json.users;
    const jd = users.find((u) => u.initials === "JD");
    assert.strictEqual((await req("PATCH", `/api/users/${jd.id}`, { pin: "1111" })).status, 200);
    assert.strictEqual((await req("GET", "/api/state", null, opCookie)).status, 401);
    const back = await req("POST", "/api/login", { initials: "JD", pin: "1111" }, "");
    assert.strictEqual(back.status, 200);
    opCookie = grabCookie(back.res);
  });

  await t.test("full backup export is admin-only and complete", async () => {
    assert.strictEqual((await req("GET", "/api/export/backup.json", null, opCookie)).status, 403);
    const r = await req("GET", "/api/export/backup.json");
    assert.strictEqual(r.status, 200);
    assert.ok(r.json.items.length > 0 && r.json.tx.length > 0 && r.json.depts.length > 0);
    assert.ok(r.json.users.length >= 2);
    assert.ok(!JSON.stringify(r.json).includes("pin_hash"), "backup never contains PIN hashes");
  });

  await t.test("login rate limiting locks out brute force", async () => {
    for (let i = 0; i < 8; i++) {
      const r = await req("POST", "/api/login", { initials: "ZZ", pin: "0000" }, "");
      assert.strictEqual(r.status, 401);
    }
    const r = await req("POST", "/api/login", { initials: "ZZ", pin: "0000" }, "");
    assert.strictEqual(r.status, 429);
  });

  await t.test("CSV exports are populated and journal carries dept", async () => {
    for (const p of ["/api/export/stock.csv", "/api/export/journal.csv", "/api/export/reorder.csv"]) {
      const res = await fetch(base + p, { headers: { cookie: adminCookie } });
      assert.strictEqual(res.status, 200);
      assert.match(res.headers.get("content-type"), /text\/csv/);
      const body = await res.text();
      assert.ok(body.split("\r\n").length > 1, `${p} has rows`);
      if (p.includes("journal")) assert.match(body.split("\r\n")[0], /dept/);
    }
  });

  await t.test("30 concurrent issues against 20 on hand never oversell", async () => {
    await req("POST", "/api/count", { sku: "4X4X8-PT", exact: 20, ref: "RACE-SETUP" });
    const results = await Promise.all(
      Array.from({ length: 30 }, () => req("POST", "/api/issue", { sku: "4X4X8-PT", qty: 1 }))
    );
    const okCount = results.filter((r) => r.status === 200).length;
    const shortCount = results.filter((r) => r.status === 409).length;
    assert.strictEqual(okCount, 20, "exactly the available stock was issued");
    assert.strictEqual(shortCount, 10, "the rest were refused as SHORT");
    const s = await req("GET", "/api/state");
    assert.strictEqual(s.json.items.find((i) => i.sku === "4X4X8-PT").qty, 0);
  });

  await t.test("frontend is served with security headers", async () => {
    const res = await fetch(base + "/", { headers: { cookie: adminCookie } });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get("content-security-policy"), /default-src 'self'/);
    assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");
    assert.match(await res.text(), /WHSE-01/);
  });

  server.close();
});
