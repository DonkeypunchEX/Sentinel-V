"use strict";
/* WHSE-01 database layer — node:sqlite (built-in, zero native deps).
   All stock movements run inside real transactions, which is the point
   of graduating from shared-blob storage: two forklifts posting the
   same SKU in the same second can no longer lose an entry.

   Stratton Warren-inspired tables:
   - depts: cost centers / departments that issues get charged to
   - reqs:  requisition queue (crew requests stock, gets filled or
            cancelled; filling posts a real ISS transaction) */

const { DatabaseSync } = require("node:sqlite");
const fs = require("fs");
const path = require("path");

const DEFAULT_DEPTS = [
  ["YARD", "Yard operations"],
  ["SHOP", "Shop / fabrication"],
  ["DELIV", "Delivery loads"],
  ["JOBSITE", "Direct to jobsite"],
  ["MAINT", "Building maintenance"],
  ["WASTE", "Damage / write-off"],
];

function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, "whse01.db"));
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      initials TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL DEFAULT '',
      pin_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('admin','operator')),
      active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS items (
      sku TEXT PRIMARY KEY,
      desc TEXT NOT NULL,
      cat TEXT NOT NULL DEFAULT 'Hardware',
      unit TEXT NOT NULL DEFAULT 'EA',
      bin TEXT NOT NULL DEFAULT '—',
      qty INTEGER NOT NULL DEFAULT 0 CHECK (qty >= 0),
      reorder INTEGER NOT NULL DEFAULT 0 CHECK (reorder >= 0),
      cost REAL NOT NULL DEFAULT 0 CHECK (cost >= 0),
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tx (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      code TEXT NOT NULL CHECK (code IN ('RCV','ISS','ADJ','NEW','DEL')),
      sku TEXT NOT NULL,
      qty INTEGER NOT NULL,
      bal INTEGER NOT NULL,
      unit TEXT NOT NULL,
      ref TEXT NOT NULL DEFAULT '',
      note TEXT NOT NULL DEFAULT '',
      by TEXT NOT NULL DEFAULT '',
      dept TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS tx_ts ON tx (ts DESC);
    CREATE INDEX IF NOT EXISTS tx_sku ON tx (sku);
    CREATE TABLE IF NOT EXISTS depts (
      code TEXT PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS reqs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      sku TEXT NOT NULL,
      qty INTEGER NOT NULL CHECK (qty > 0),
      dept TEXT NOT NULL DEFAULT '',
      note TEXT NOT NULL DEFAULT '',
      by TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','FILLED','CANCELLED')),
      filled_by TEXT NOT NULL DEFAULT '',
      filled_ts INTEGER
    );
    CREATE INDEX IF NOT EXISTS reqs_status ON reqs (status, ts DESC);
  `);

  /* migration for databases created before dept coding existed */
  const txCols = db.prepare("PRAGMA table_info(tx)").all().map((c) => c.name);
  if (!txCols.includes("dept")) {
    db.exec("ALTER TABLE tx ADD COLUMN dept TEXT NOT NULL DEFAULT ''");
  }

  /* migration: token version — bumping it revokes a user's sessions */
  const userCols = db.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
  if (!userCols.includes("tok")) {
    db.exec("ALTER TABLE users ADD COLUMN tok INTEGER NOT NULL DEFAULT 0");
  }

  if (db.prepare("SELECT COUNT(*) AS c FROM depts").get().c === 0) {
    const ins = db.prepare("INSERT INTO depts (code, name) VALUES (?,?)");
    for (const [code, name] of DEFAULT_DEPTS) ins.run(code, name);
  }

  return db;
}

/* node:sqlite has no transaction helper — wrap manually. */
function inTransaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const out = fn();
    db.exec("COMMIT");
    return out;
  } catch (e) {
    try { db.exec("ROLLBACK"); } catch (_) { /* already rolled back */ }
    throw e;
  }
}

module.exports = { openDb, inTransaction };
