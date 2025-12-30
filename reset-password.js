"use strict";

require("dotenv").config();
const path = require("path");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const sqlite3 = require("sqlite3").verbose();

const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");
const saltRounds = Number(process.env.BCRYPT_ROUNDS || 10);

async function main() {
  const username = process.argv[2];
  const newPassword = process.argv[3];

  if (!username || !newPassword) {
    console.error("Usage: node reset-password.js <username> <newPassword>");
    process.exit(1);
  }

  const hash = await bcrypt.hash(newPassword, saltRounds);

  // --- Postgres update (if configured)
  const pgUrl =
    process.env.DATABASE_URL ||
    (process.env.PGHOST ? "configured via PGHOST/PGUSER/PGDATABASE" : null);

  if (pgUrl) {
    const pool = new Pool(
      process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false } }
        : {}
    );

    const pgRes = await pool.query(
      `UPDATE users SET passhash = $1 WHERE username = $2 RETURNING id`,
      [hash, username]
    );

    if (pgRes.rowCount === 0) {
      console.warn(`[PG] No user found with username: ${username}`);
    } else {
      console.log(`[PG] Updated password for ${username} (id=${pgRes.rows[0].id})`);
    }

    await pool.end();
  } else {
    console.log("[PG] Skipped (no Postgres env vars found).");
  }

  // --- SQLite update (legacy)
  await new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_FILE, (err) => (err ? reject(err) : resolve(db)));
  }).then((db) => {
    return new Promise((resolve, reject) => {
      db.run(
        `UPDATE users SET passhash = ? WHERE username = ?`,
        [hash, username],
        function (err) {
          if (err) return reject(err);
          if (this.changes === 0) console.warn(`[SQLite] No user found with username: ${username}`);
          else console.log(`[SQLite] Updated password for ${username}`);
          db.close(() => resolve());
        }
      );
    });
  });

  console.log("Done.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});