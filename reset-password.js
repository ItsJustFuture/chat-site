"use strict";

require("dotenv").config();
const path = require("path");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");
const saltRounds = Number(process.env.BCRYPT_ROUNDS || 10);

const CANDIDATE_TABLES = ["users", "user", "accounts", "account"];
const USERNAME_COLS = ["username", "user", "name", "handle"];
const PASS_COLS = ["passhash", "password_hash", "passwordhash", "hash", "pw_hash", "password", "pass"];

function openDb() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_FILE, (err) => (err ? reject(err) : resolve(db)));
  });
}
function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ changes: this.changes });
    });
  });
}

async function findUsersTableAndCols(db) {
  const tables = await all(
    db,
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
  );
  const tableNames = new Set(tables.map((t) => t.name));

  const candidates = CANDIDATE_TABLES.filter((t) => tableNames.has(t));
  const toTry = candidates.length ? candidates : Array.from(tableNames);

  for (const table of toTry) {
    const cols = await all(db, `PRAGMA table_info(${table})`);
    const colNames = cols.map((c) => c.name);

    const usernameCol = USERNAME_COLS.find((c) => colNames.includes(c));
    const passCol = PASS_COLS.find((c) => colNames.includes(c));

    if (usernameCol && passCol) {
      return { table, usernameCol, passCol, colNames };
    }
  }

  throw new Error(
    `Could not find a users table with (username + password hash) columns.\n` +
      `Checked tables: ${Array.from(tableNames).join(", ")}`
  );
}

async function main() {
  const username = process.argv[2];
  const newPassword = process.argv[3];

  if (!username || !newPassword) {
    console.error("Usage: node reset-password.js <username> <newPassword>");
    process.exit(1);
  }

  const hash = await bcrypt.hash(newPassword, saltRounds);

  const db = await openDb();
  try {
    const { table, usernameCol, passCol } = await findUsersTableAndCols(db);

    const sql = `UPDATE ${table} SET ${passCol} = ? WHERE ${usernameCol} = ?`;
    const res = await run(db, sql, [hash, username]);

    if (res.changes === 0) {
      console.warn(`[SQLite] No user found for ${username} in ${table}.${usernameCol}`);
      console.warn(`[SQLite] Try checking exact casing/spelling of the username.`);
      process.exitCode = 2;
    } else {
      console.log(`[SQLite] Updated password for ${username} in table '${table}' (column '${passCol}')`);
    }
  } finally {
    db.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
