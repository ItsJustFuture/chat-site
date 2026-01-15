"use strict";

const path = require("path");
const os = require("os");
const fs = require("fs");

const tmpPath = path.join(os.tmpdir(), `chat-memory-sanity-${Date.now()}.db`);
process.env.DB_FILE = tmpPath;

const { db, migrationsReady } = require("../database");

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

async function main() {
  await migrationsReady;

  const tables = await dbAll("SELECT name FROM sqlite_master WHERE type='table'");
  const names = new Set(tables.map((t) => t.name));
  if (!names.has("memories")) throw new Error("Missing memories table");
  if (!names.has("memory_settings")) throw new Error("Missing memory_settings table");

  const now = Date.now();
  await dbRun(
    "INSERT INTO memories (user_id, type, key, title, created_at) VALUES (?, ?, ?, ?, ?)",
    [1, "media", "first_image_upload", "First image", now]
  );
  await dbRun(
    "INSERT OR IGNORE INTO memories (user_id, type, key, title, created_at) VALUES (?, ?, ?, ?, ?)",
    [1, "media", "first_image_upload", "First image", now]
  );
  const countRow = await dbGet(
    "SELECT COUNT(*) AS count FROM memories WHERE user_id = ? AND key = ?",
    [1, "first_image_upload"]
  );
  if (Number(countRow?.count || 0) !== 1) throw new Error("Memory idempotency failed");

  await dbRun(
    "UPDATE memories SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE user_id = ? AND key = ?",
    [1, "first_image_upload"]
  );
  const pinRow = await dbGet(
    "SELECT pinned FROM memories WHERE user_id = ? AND key = ?",
    [1, "first_image_upload"]
  );
  if (!pinRow) throw new Error("Pinned memory not found");

  console.log("Memory sanity checks passed.");
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => {
    db.close();
    try {
      fs.unlinkSync(tmpPath);
    } catch {}
  });
