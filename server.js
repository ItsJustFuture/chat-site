// server.js
"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const multer = require("multer");
const { Pool } = require("pg");
const http = require("http");
const { Server } = require("socket.io");
const sqlite3 = require("sqlite3").verbose();

const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");
const DATABASE_URL = process.env.DATABASE_URL || "";
const PG_ENABLED = !!DATABASE_URL;
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const AVATARS_DIR = path.join(__dirname, "avatars");

// ---- Ensure folders exist
for (const dir of [UPLOADS_DIR, AVATARS_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---- App + Server
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  // Render uses HTTPS -> allow websocket upgrade
  cors: { origin: true, credentials: true },

  // More tolerant of mobile/background + Render sleep
  pingInterval: 30_000,  // send pings every 30s
  pingTimeout: 120_000,  // wait 120s for pong before disconnect
  upgradeTimeout: 30_000,
});
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
let pgPool = {
  query: async () => {
    throw new Error("Postgres disabled (DATABASE_URL not set)");
  },
};

if (PG_ENABLED) {
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL === "true" || process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  });
}
const USE_PG = !!process.env.DATABASE_URL;
// ---- Postgres: helpers to keep legacy schemas compatible
async function pgGetColumnType(tableName, columnName) {
  const { rows } = await pgPool.query(
    `SELECT udt_name, data_type
     FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = $1
       AND column_name = $2
     LIMIT 1`,
    [tableName, columnName]
  );
  return rows[0] || null;
}
async function ensurePgDmSchema() {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS dm_threads (
      id BIGSERIAL PRIMARY KEY,
      title TEXT,
      is_group BOOLEAN NOT NULL DEFAULT FALSE,
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dm_participants (
      thread_id BIGINT NOT NULL,
      user_id TEXT NOT NULL,
      added_by TEXT,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (thread_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS dm_messages (
  id BIGSERIAL PRIMARY KEY,
  thread_id BIGINT NOT NULL,
  sender_id TEXT NOT NULL,
  text TEXT NOT NULL,
  ts BIGINT NOT NULL,
  reply_to_id BIGINT,
  reply_to_user TEXT,
  reply_to_text TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


    -- Backfill/upgrade columns for existing installs
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='dm_messages' AND column_name='reply_to_id'
  ) THEN
    ALTER TABLE dm_messages ADD COLUMN reply_to_id BIGINT;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='dm_messages' AND column_name='reply_to_user'
  ) THEN
    ALTER TABLE dm_messages ADD COLUMN reply_to_user TEXT;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='dm_messages' AND column_name='reply_to_text'
  ) THEN
    ALTER TABLE dm_messages ADD COLUMN reply_to_text TEXT;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_dm_participants_user ON dm_participants (user_id);
    CREATE INDEX IF NOT EXISTS idx_dm_messages_thread_ts ON dm_messages (thread_id, ts DESC);
  `);
}
async function pgEnsureCamelColumn(tableName, camelName, typeSql = "BIGINT") {
  // If exact camelCase column already exists, we're good
  const exact = await pgGetColumnType(tableName, camelName);
  if (exact) return;

  // If a lowercased version exists (created without quotes), rename it to the camelCase quoted form
  const lower = camelName.toLowerCase();
  const lowerInfo = await pgGetColumnType(tableName, lower);
  if (lowerInfo) {
    await pgPool.query(`ALTER TABLE ${tableName} RENAME COLUMN ${lower} TO "${camelName}"`);
    return;
  }

  // Otherwise just add the camelCase column
  await pgPool.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS "${camelName}" ${typeSql}`);
}
async function pgEnsureEpochMsBigint(tableName, columnName) {
  const info = await pgGetColumnType(tableName, columnName);
  if (!info) return;

  const udt = String(info.udt_name || "").toLowerCase();
  const dataType = String(info.data_type || "").toLowerCase();

  if (udt === "int8" || dataType === "bigint") return;

  if (udt === "timestamp" || udt === "timestamptz" || dataType.includes("timestamp")) {
    await pgPool.query(
      `ALTER TABLE ${tableName}
       ALTER COLUMN ${columnName}
       TYPE BIGINT
       USING (EXTRACT(EPOCH FROM ${columnName}) * 1000)::BIGINT`
    );
    return;
  }

  if (udt === "int4" || dataType === "integer") {
    await pgPool.query(
      `ALTER TABLE ${tableName}
       ALTER COLUMN ${columnName}
       TYPE BIGINT
       USING (${columnName})::BIGINT`
    );
  }
}

// ---- Postgres schema flags
let PG_USERS_CREATED_AT_IS_TIMESTAMP = false;
// ---- Postgres table setup
// Run once on boot, and start the server only after this finishes (so schema/type fixes apply before /register).
const pgInitPromise = (async () => {
  if (!PG_ENABLED) {
    console.log("[pg] DATABASE_URL not set; running in SQLite-only mode");
    return;
  }
  try {
    // Base tables (SQL only)
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'User',
        created_at BIGINT,
        avatar TEXT,
        bio TEXT,
        mood TEXT,
        age INTEGER,
        gender TEXT,
        last_seen BIGINT,
        last_room TEXT,
        last_status TEXT,
        theme TEXT NOT NULL DEFAULT 'Minimal Dark',
        gold INTEGER NOT NULL DEFAULT 0,
        xp INTEGER NOT NULL DEFAULT 0,
        lastXpMessageAt BIGINT,
        lastDailyLoginAt BIGINT,
        lastGoldTickAt BIGINT,
        lastMessageGoldAt BIGINT,
        lastDailyLoginGoldAt BIGINT,
        lastDiceRollAt BIGINT,
        dice_sixes INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS session (
        sid TEXT PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP NOT NULL
      );
    `);

    // DM schema
    await ensurePgDmSchema();

// Fix camelCase columns that Postgres lowercased previously
// ---- Fix camelCase timestamp columns Postgres lowercased
try {
  await pgEnsureCamelColumn("users", "lastGoldTickAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastMessageGoldAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastDailyLoginGoldAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastXpMessageAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastDailyLoginAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastDiceRollAt", "BIGINT");
} catch (e) {
  console.warn("[pg camelCase migrate]", e?.message || e);
}
    // If your table already existed (older minimal schema), ensure columns exist
    const addCols = [
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'User'`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS mood TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS age INTEGER`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_room TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_status TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT NOT NULL DEFAULT 'Minimal Dark'`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS gold INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastXpMessageAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastGoldTickAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastMessageGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDiceRollAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS dice_sixes INTEGER NOT NULL DEFAULT 0`,
    ];
    for (const q of addCols) {
      try { await pgPool.query(q); } catch (_) {}
    }

    // Migrate legacy timestamp/int columns to epoch-ms BIGINT so inserts don't fail.
    const epochMsCols = [
      "created_at",
      "last_seen",
      "lastXpMessageAt",
      "lastDailyLoginAt",
      "lastGoldTickAt",
      "lastMessageGoldAt",
      "lastDailyLoginGoldAt",
      "lastDiceRollAt",
    ];
    for (const col of epochMsCols) {
      try {
        await pgEnsureEpochMsBigint("users", col);
      } catch (e) {
        console.warn("[pg-migrate]", "users."+col, e?.message || e);
      }
    }

    // Detect actual column types (useful on legacy DBs)
    try {
      const t = await pgGetColumnType("users", "created_at");
      const udt = String(t?.udt_name || "").toLowerCase();
      const dt = String(t?.data_type || "").toLowerCase();
      PG_USERS_CREATED_AT_IS_TIMESTAMP = udt.includes("timestamp") || dt.includes("timestamp");
      console.log("[pg-schema] users.created_at =", t?.data_type || t?.udt_name);
    } catch (e) {
      console.warn("[pg-schema] failed to read users.created_at type", e?.message || e);
    }

    console.log("Postgres tables ready");
  } catch (err) {
    console.error("Postgres init error:", err);
  }
})();
// IMPORTANT for Render/any reverse proxy so secure cookies work
app.set("trust proxy", 1);
// ---- DB
const db = new sqlite3.Database(DB_FILE);

// ---- Basic migrations
function addColumnIfMissing(table, column, definition) {
  db.all(`PRAGMA table_info(${table})`, [], (err, rows) => {
    if (err) return;
    const exists = rows.some((r) => r.name === column);
    if (!exists) db.run(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
  });
}
async function pgUserExists(userId) {
  const { rows } = await pgPool.query("SELECT 1 FROM users WHERE id=$1 LIMIT 1", [userId]);
  return !!rows[0];
}
function migrateLegacyPasswords() {
  db.all("PRAGMA table_info(users)", [], (err, rows) => {
    if (err) return;
    const hasPasswordHash = rows.some((r) => r.name === "password_hash");
    const hasLegacyPassword = rows.some((r) => r.name === "password");
    if (!hasPasswordHash) return;
    if (!hasLegacyPassword) return;

    db.all(
      `SELECT id, password, password_hash FROM users
       WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL`,
      [],
      async (_e, legacyRows) => {
        if (!legacyRows?.length) return;
        for (const row of legacyRows) {
          const legacy = String(row.password || "");
          if (!legacy) continue;
          const hash = legacy.startsWith("$2") ? legacy : await bcrypt.hash(legacy, 10);
          db.run("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [hash, row.id]);
        }
      }
    );
  });
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      role TEXT NOT NULL DEFAULT 'User',
      created_at INTEGER NOT NULL,
      avatar TEXT,
      bio TEXT,
      mood TEXT,
      age INTEGER,
      gender TEXT,
      last_seen INTEGER,
      last_room TEXT,
      last_status TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS rooms (
      name TEXT PRIMARY KEY,
      created_by INTEGER,
      created_at INTEGER NOT NULL
    )
  `);

  addColumnIfMissing("rooms", "slowmode_seconds", "slowmode_seconds INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing("rooms", "is_locked", "is_locked INTEGER NOT NULL DEFAULT 0");
  addColumnIfMissing("rooms", "pinned_message_ids", "pinned_message_ids TEXT");
  addColumnIfMissing("rooms", "maintenance_mode", "maintenance_mode INTEGER NOT NULL DEFAULT 0");

  // seed default rooms
  const seedRooms = ["main", "nsfw", "music", "diceroom"];
  for (const r of seedRooms) {
    db.run(`INSERT OR IGNORE INTO rooms (name, created_by, created_at) VALUES (?, NULL, ?)`, [r, Date.now()]);
  }
  // ensure all expected columns exist even if DB was created by older code
  const userColumns = [
    ["password_hash", "password_hash TEXT"],
    ["role", "role TEXT NOT NULL DEFAULT 'User'"],
    ["created_at", "created_at INTEGER"],
    ["avatar", "avatar TEXT"],
    ["bio", "bio TEXT"],
    ["mood", "mood TEXT"],
    ["age", "age INTEGER"],
    ["gender", "gender TEXT"],
    ["last_seen", "last_seen INTEGER"],
    ["last_room", "last_room TEXT"],
    ["last_status", "last_status TEXT"],
    ["theme", "theme TEXT NOT NULL DEFAULT 'Minimal Dark'"],
    ["gold", "gold INTEGER NOT NULL DEFAULT 0"],
    ["xp", "xp INTEGER NOT NULL DEFAULT 0"],
    ["lastXpMessageAt", "lastXpMessageAt INTEGER"],
    ["lastDailyLoginAt", "lastDailyLoginAt INTEGER"],
    ["lastGoldTickAt", "lastGoldTickAt INTEGER"],
    ["lastMessageGoldAt", "lastMessageGoldAt INTEGER"],
    ["lastDailyLoginGoldAt", "lastDailyLoginGoldAt INTEGER"],
    ["lastDiceRollAt", "lastDiceRollAt INTEGER"],
    ["dice_sixes", "dice_sixes INTEGER NOT NULL DEFAULT 0"],
  ];
  for (const [col, ddl] of userColumns) addColumnIfMissing("users", col, ddl);

  migrateLegacyPasswords();

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      role TEXT NOT NULL,
      avatar TEXT,
      text TEXT,
      ts INTEGER NOT NULL,
      deleted INTEGER NOT NULL DEFAULT 0,
      attachment_url TEXT,
      attachment_type TEXT,
      attachment_mime TEXT,
      attachment_size INTEGER
    )
  `);

  ensureColumns("messages", [
    ["reply_to_id", "reply_to_id INTEGER"],
    ["reply_to_user", "reply_to_user TEXT"],
    ["reply_to_text", "reply_to_text TEXT"],
  ]);

  db.run(`
    CREATE TABLE IF NOT EXISTS reactions (
      message_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      emoji TEXT NOT NULL,
      PRIMARY KEY (message_id, username)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS punishments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,                 -- 'mute' | 'ban'
      expires_at INTEGER,                 -- null => permanent
      reason TEXT,
      by_user_id INTEGER,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS mod_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      actor_user_id INTEGER,
      actor_username TEXT,
      actor_role TEXT,
      action TEXT NOT NULL,
      target_user_id INTEGER,
      target_username TEXT,
      room TEXT,
      details TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS profile_likes (
      user_id INTEGER NOT NULL,
      target_user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, target_user_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS changelog_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seq INTEGER NOT NULL UNIQUE,
      title TEXT NOT NULL,
      body TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      author_id INTEGER NOT NULL
    )
  `);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_changelog_seq ON changelog_entries(seq)`);

  db.run(`
    CREATE TABLE IF NOT EXISTS command_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      executor_id INTEGER NOT NULL,
      executor_username TEXT NOT NULL,
      executor_role TEXT NOT NULL,
      command_name TEXT NOT NULL,
      args_json TEXT,
      target_ids TEXT,
      room TEXT,
      success INTEGER NOT NULL,
      error TEXT,
      ts INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);
    // ---- DM tables (make sure these exist at startup)
  db.run(`
    CREATE TABLE IF NOT EXISTS dm_threads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      is_group INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS dm_participants (
      thread_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      added_by INTEGER,
      joined_at INTEGER NOT NULL,
      UNIQUE(thread_id, user_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS dm_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      text TEXT,
      ts INTEGER NOT NULL
    )
  `);

  ensureColumns("dm_messages", [
    ["reply_to_id", "reply_to_id INTEGER"],
    ["reply_to_user", "reply_to_user TEXT"],
    ["reply_to_text", "reply_to_text TEXT"],
  ]);

  ensureColumns("dm_threads", [
    ["title", "title TEXT"],
    ["is_group", "is_group INTEGER NOT NULL DEFAULT 0"],
    ["created_by", "created_by INTEGER NOT NULL DEFAULT 0"],
    ["created_at", "created_at INTEGER NOT NULL DEFAULT 0"],
  ]);

  ensureColumns("dm_participants", [
    ["added_by", "added_by INTEGER"],
    ["joined_at", "joined_at INTEGER NOT NULL DEFAULT 0"],
  ]);

  // Helpful indexes
  db.run(`CREATE INDEX IF NOT EXISTS idx_dm_participants_user ON dm_participants(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_dm_participants_thread ON dm_participants(thread_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_dm_messages_thread_ts ON dm_messages(thread_id, ts)`);

  // Ensure Iri is always Owner
  db.run("UPDATE users SET role='Owner' WHERE lower(username)='iri'");
});

// ---- Security + parsing
app.disable("x-powered-by");
// IMPORTANT: CSP for the app (allows our /public assets; includes 'unsafe-inline' for legacy client scripts)
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
      "script-src-elem 'self' 'unsafe-eval' 'unsafe-inline'",
      // Inline style attributes are set by the client JS (e.g. show/hide panels),
      // so allow them alongside our external stylesheet.
      "style-src 'self' 'unsafe-inline'",
      // allow avatars/uploads + blob previews on client
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      // socket.io
      "connect-src 'self' ws: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  next();
});

// ---- Sessions (single source of truth)
// If DATABASE_URL is set: store sessions in Postgres.
// Otherwise: store sessions in SQLite (sessions.sqlite) so local/dev works without PG.
let sessionStore;
if (PG_ENABLED) {
  sessionStore = new PgSession({
    pool: pgPool,
    tableName: "session",
    createTableIfMissing: true,
  });
} else {
  const SQLiteStore = require("connect-sqlite3")(session);
  sessionStore = new SQLiteStore({
    dir: __dirname,
    db: "sessions.sqlite",
    table: "sessions",
  });
}

const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || "dev_secret_change_me",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
});


app.use(sessionMiddleware);
app.get("/__recover_owner__", async (req, res) => {
  try {
    const username = sanitizeUsername(req.query.username);
    const newPassword = String(req.query.newPassword || "");
    const secret = String(req.query.secret || "");

    if (!process.env.OWNER_RECOVERY_SECRET) {
      return res.status(500).send("OWNER_RECOVERY_SECRET is not set");
    }
    if (secret !== process.env.OWNER_RECOVERY_SECRET) {
      return res.status(403).send("Forbidden");
    }
    if (!username || newPassword.length < 6) {
      return res.status(400).send("Missing username or newPassword (6+ chars)");
    }

    const hash = await bcrypt.hash(newPassword, 10);

    // Update Postgres (your real schema uses password_hash)
    await pgPool.query(
      "UPDATE users SET password_hash=$1 WHERE lower(username)=lower($2)",
      [hash, username]
    );

    // Update SQLite too (keeps legacy features consistent)
    await dbRunAsync(
      "UPDATE users SET password_hash=? WHERE lower(username)=lower(?)",
      [hash, username]
    ).catch(() => {});

    return res.send("Password reset OK");
  } catch (e) {
    return res.status(500).send(String(e && e.stack ? e.stack : e));
  }
});

// ---- Static
app.use("/uploads", express.static(UPLOADS_DIR));
app.use("/avatars", express.static(AVATARS_DIR));
app.use(express.static(PUBLIC_DIR));

// ---- Helpers
function normalizeUsername(u) {
  return String(u || "").trim();
}
function normKey(u) {
  return normalizeUsername(u).toLowerCase();
}
function sanitizeUsername(u) {
  u = normalizeUsername(u);
  // allow spaces, letters, digits, some punctuation; trim length
  u = u.replace(/[^\p{L}\p{N} _.'-]/gu, "").trim();
  return u.slice(0, 24);
}
function sanitizeThemeNameServer(name){
  const n = String(name || "").trim();
  return ALLOWED_THEMES.includes(n) ? n : DEFAULT_THEME;
}
function clamp(n, a, b) {
  n = Number(n);
  if (!Number.isFinite(n)) return a;
  return Math.max(a, Math.min(b, n));
}
function pgRowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    // Needed for login() bcrypt.compare. Keep server-side only.
    password_hash: row.password_hash || null,
    role: row.role || "User",
    theme: sanitizeThemeNameServer(row.theme),
    avatar: row.avatar || null,
    bio: row.bio || "",
    mood: row.mood || "",
    age: row.age ?? null,
    gender: row.gender || "",
    gold: row.gold ?? 0,
    xp: row.xp ?? 0,
    dice_sixes: row.dice_sixes ?? 0,
    last_seen: row.last_seen ?? null,
    last_room: row.last_room || null,
    last_status: row.last_status || null,
    lastXpMessageAt: row.lastXpMessageAt ?? null,
    lastDailyLoginAt: row.lastDailyLoginAt ?? null,
    lastGoldTickAt: row.lastGoldTickAt ?? null,
    lastMessageGoldAt: row.lastMessageGoldAt ?? null,
    lastDailyLoginGoldAt: row.lastDailyLoginGoldAt ?? null,
    lastDiceRollAt: row.lastDiceRollAt ?? null,
  };
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

async function syncGoldXpThemeToPg(uid) {
  // Pull from SQLite (source of truth for tick logic right now)
  const row = await dbGet("SELECT gold, xp, theme, role, username FROM users WHERE id = ?", [uid]);
  if (!row) return;

  const theme = sanitizeThemeNameServer(row.theme);

  // Push into Postgres (so /api/me/* can read from PG)
  await pgPool.query(
    `UPDATE users
       SET gold = $1,
           xp = $2,
           theme = $3,
           role = COALESCE(role, $4)
     WHERE id = $5`,
    [Number(row.gold || 0), Number(row.xp || 0), theme, row.role || "User", uid]
  );
}

async function pgGetUserByUsername(username) {
  const { rows } = await pgPool.query(
    "SELECT * FROM users WHERE lower(username) = lower($1) LIMIT 1",
    [username]
  );
  return pgRowToUser(rows[0]);
}

async function pgGetUserById(id) {
  const { rows } = await pgPool.query(
    "SELECT * FROM users WHERE id = $1 LIMIT 1",
    [id]
  );
  return pgRowToUser(rows[0]);
}



// Fetch a raw Postgres user row by id, selecting only requested columns.
// NOTE: This returns the raw row object (snake_case keys), not the mapped pgRowToUser().
async function pgGetUserRowById(id, columns) {
  const allow = new Set([
    "id","username","password_hash","role","created_at","avatar","bio","mood","age","gender",
    "last_seen","last_room","last_status","theme","gold","xp",
    "lastXpMessageAt","lastDailyLoginAt","lastGoldTickAt","lastMessageGoldAt","lastDailyLoginGoldAt",
    "lastDiceRollAt","dice_sixes"
  ]);
  const cols = (Array.isArray(columns) && columns.length)
    ? columns.filter((c) => allow.has(String(c)))
    : ["*"];

  const selectSql = cols[0] === "*" ? "*" : cols.map((c) => `"${c}"`).join(", ");
  const { rows } = await pgPool.query(`SELECT ${selectSql} FROM users WHERE id = $1 LIMIT 1`, [id]);
  return rows[0] || null;
}
async function pgUpsertFromSqliteRow(row) {
  // row is your SQLite users table row
  const username = row.username;
  const createdAt = row.created_at ?? Date.now();

  // Normalize role auto rules (your existing sets)
  const norm = normKey(username);
  let role = row.role || "User";
  if (AUTO_OWNER.has(norm)) role = "Owner";
  else if (AUTO_COOWNERS.has(norm)) role = "Co-owner";

  const theme = sanitizeThemeNameServer(row.theme);

  const passwordHash = row.password_hash || null;

  const q = `
    INSERT INTO users (
      username, password_hash, role, created_at,
      avatar, bio, mood, age, gender,
      last_seen, last_room, last_status,
      theme, gold, xp,
      "lastXpMessageAt", "lastDailyLoginAt", "lastGoldTickAt", "lastMessageGoldAt", "lastDailyLoginGoldAt",
      "lastDiceRollAt", dice_sixes
    )
    VALUES (
      $1,$2,$3,$4,
      $5,$6,$7,$8,$9,
      $10,$11,$12,
      $13,$14,$15,
      $16,$17,$18,$19,$20,
      $21,$22
    )
    ON CONFLICT (username) DO UPDATE SET
      password_hash = COALESCE(EXCLUDED.password_hash, users.password_hash),
      role = EXCLUDED.role,
      avatar = COALESCE(EXCLUDED.avatar, users.avatar),
      bio = COALESCE(EXCLUDED.bio, users.bio),
      mood = COALESCE(EXCLUDED.mood, users.mood),
      age = COALESCE(EXCLUDED.age, users.age),
      gender = COALESCE(EXCLUDED.gender, users.gender),
      last_seen = COALESCE(EXCLUDED.last_seen, users.last_seen),
      last_room = COALESCE(EXCLUDED.last_room, users.last_room),
      last_status = COALESCE(EXCLUDED.last_status, users.last_status),
      theme = COALESCE(EXCLUDED.theme, users.theme),
      gold = GREATEST(users.gold, EXCLUDED.gold),
      xp = GREATEST(users.xp, EXCLUDED.xp),
      dice_sixes = GREATEST(users.dice_sixes, EXCLUDED.dice_sixes)
    RETURNING *;
  `;

  const { rows } = await pgPool.query(q, [
    username, passwordHash, role, createdAt,
    row.avatar || null, row.bio || "", row.mood || "", row.age ?? null, row.gender || "",
    row.last_seen ?? null, row.last_room || null, row.last_status || null,
    theme, row.gold ?? 0, row.xp ?? 0,
    row.lastXpMessageAt ?? null, row.lastDailyLoginAt ?? null, row.lastGoldTickAt ?? null, row.lastMessageGoldAt ?? null, row.lastDailyLoginGoldAt ?? null,
    row.lastDiceRollAt ?? null, row.dice_sixes ?? 0
  ]);

  return pgRowToUser(rows[0]);
}
function ensureColumns(table, cols) {
  db.all(`PRAGMA table_info(${table})`, [], (err, rows) => {
    if (err) return;
    const existing = new Set((rows || []).map(r => r.name));
    for (const [colName, ddl] of cols) {
      if (!existing.has(colName)) {
        db.run(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
      }
    }
  });
}
const ROLES = ["Guest", "User", "VIP", "Moderator", "Admin", "Co-owner", "Owner"];
function roleRank(role) {
  const idx = ROLES.indexOf(role);
  return idx === -1 ? 1 : idx;
}
const STATUS_ALIASES = {
  "Do Not Disturb": "DnD",
  "Listening to Music": "Music",
  "Looking to Chat": "Chatting",
  "Invisible": "Lurking",
};
function normalizeStatus(status, fallback = "Online") {
  const raw = String(status || "").trim();
  if (!raw) return fallback;
  const normalized = STATUS_ALIASES[raw] || raw;
  return normalized.slice(0, 32);
}
function requireMinRole(role, minRole) {
  return roleRank(role) >= roleRank(minRole);
}
function canModerate(actorRole, targetRole) {
  // can only moderate lower roles
  return roleRank(actorRole) > roleRank(targetRole);
}
const ROLE_DISPLAY = {
  Moderator: "Moderator",
  Admin: "Admin",
  "Co-owner": "Co-Owner",
  Owner: "Owner",
};

function findUserByMention(raw, cb) {
  const name = sanitizeUsername(String(raw || "").replace(/^@+/, ""));
  if (!name) return cb(new Error("User not found"));
  db.get(
    `SELECT id, username, role FROM users
     WHERE lower(username)=lower(?)
     ORDER BY CASE WHEN username=? THEN 0 ELSE 1 END LIMIT 1`,
    [name, name],
    (err, row) => {
      if (err || !row) return cb(new Error("User not found"));
      cb(null, row);
    }
  );
}

function logCommandAudit({ executor, commandName, args, targets, room, success, error }) {
  db.run(
    `INSERT INTO command_audit (executor_id, executor_username, executor_role, command_name, args_json, target_ids, room, success, error, ts)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      executor.id,
      executor.username,
      executor.role,
      commandName,
      args ? JSON.stringify(args).slice(0, 2000) : null,
      targets ? String(targets).slice(0, 500) : null,
      room || null,
      success ? 1 : 0,
      error ? String(error).slice(0, 500) : null,
      Date.now(),
    ]
  );
}

function parseCommand(text) {
  const raw = String(text || "").trim();
  if (!raw.startsWith("/")) return null;
  const parts = raw.slice(1).split(/\s+/).filter(Boolean);
  if (!parts.length) return null;
  const [name, ...args] = parts;
  return { name: name.toLowerCase(), args };
}

const slowmodeTracker = new Map(); // key `${room}:${userId}` -> last ts
const godmodeUsers = new Set();
const maintenanceState = { enabled: false };
const DEFAULT_THEME = "Minimal Dark";
const ALLOWED_THEMES = [
  "Minimal Dark",
  "Minimal Dark (High Contrast)",
  "Cyberpunk Neon",
  "Cyberpunk Neon (Midnight)",
  "Fantasy Tavern",
  "Fantasy Tavern (Ember)",
  "Space Explorer",
  "Space Explorer (Nebula)",
  "Minimal Light",
  "Minimal Light (High Contrast)",
  "Pastel Light",
  "Paper / Parchment",
  "Sky Light",
];

// Passive gold accrues slowly over time. 5s ticks were far too fast.
// 1 gold per minute = 60 gold/hour.
const GOLD_TICK_MS = 60_000;

// Prevent double-awarding gold due to overlapping async timers/events for the same user.
const goldInFlight = new Set();
const MESSAGE_GOLD_COOLDOWN_MS = 5 * 60 * 1000;
const DAILY_GOLD_COOLDOWN_MS = 24 * 60 * 60 * 1000;
// ---- Real-time presence tracking
const onlineState = new Map(); // userId -> { room, status }
const socketIdByUserId = new Map(); // userId -> socket.id
const typingByRoom = new Map(); // room -> Set(username)
const msgRate = new Map(); // socket.id -> { lastTs, count }
const onlineXpTrack = new Map(); // userId -> { lastTs, carryMs }

db.get(`SELECT value FROM config WHERE key='maintenance'`, [], (_e, row) => {
  maintenanceState.enabled = row?.value === "on";
});

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAllAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

const commandRegistry = {
  help: {
    minRole: "User",
    description: "Show commands you can use",
    usage: "/help",
    example: "/help",
    handler: async ({ socket }) => {
      const actorRole = godmodeUsers.has(socket.user.id) ? "Owner" : socket.user.role;
      const commands = Object.entries(commandRegistry)
        .filter(([_k, v]) => requireMinRole(actorRole, v.minRole || "User"))
        .map(([name, meta]) => ({
          name,
          description: meta.description,
          usage: meta.usage,
          example: meta.example,
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
      return { ok: true, type: "help", commands, role: ROLE_DISPLAY[actorRole] || actorRole };
    },
  },
  mute: {
    minRole: "Moderator",
    description: "Temporarily block a user from chatting",
    usage: "/mute @user [minutes] [reason]",
    example: "/mute @Sam 15 spam",
    handler: async ({ args, actorRole, actor, room }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const minsRaw = Number(args[1] || 10);
      const mins = clamp(minsRaw, 1, 1440);
      const reason = args.slice(2).join(" ").slice(0, 180);
      const expiresAt = Date.now() + mins * 60 * 1000;
      await dbRunAsync(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at) VALUES (?, 'mute', ?, ?, ?, ?)`,
        [target.id, expiresAt, reason || null, actor.id, Date.now()]
      );
      return { ok: true, message: `Muted ${target.username} for ${mins} minutes${reason ? ` (${reason})` : ""}`, targets: target.id };
    },
  },
  unmute: {
    minRole: "Moderator",
    description: "Remove mute from a user",
    usage: "/unmute @user",
    example: "/unmute @Sam",
    handler: async ({ args, actorRole }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      await dbRunAsync(`DELETE FROM punishments WHERE user_id=? AND type='mute'`, [target.id]);
      return { ok: true, message: `Unmuted ${target.username}`, targets: target.id };
    },
  },
  warn: {
    minRole: "Moderator",
    description: "Send a private warning",
    usage: "/warn @user [reason]",
    example: "/warn @Alex please chill",
    handler: async ({ args, actorRole, actor }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const reason = args.slice(1).join(" ").slice(0, 180) || "No reason provided";
      const sid = socketIdByUserId.get(target.id);
      if (sid) io.to(sid).emit("system", `You were warned by ${actor.username}: ${reason}`);
      logModAction({ actor, action: "WARN_COMMAND", targetUserId: target.id, targetUsername: target.username, room: null, details: reason });
      return { ok: true, message: `Warned ${target.username}: ${reason}`, targets: target.id };
    },
  },
  slowmode: {
    minRole: "Moderator",
    description: "Set room slowmode seconds",
    usage: "/slowmode [seconds]",
    example: "/slowmode 15",
    handler: async ({ args, room }) => {
      const sec = clamp(Number(args[0] || 0), 0, 3600);
      await dbRunAsync(`UPDATE rooms SET slowmode_seconds=? WHERE name=?`, [sec, room]);
      return { ok: true, message: `Slowmode set to ${sec} seconds for #${room}` };
    },
  },
  clear: {
    minRole: "Moderator",
    description: "Delete last X messages",
    usage: "/clear [amount]",
    example: "/clear 5",
    handler: async ({ args, room }) => {
      const amt = clamp(Number(args[0] || 0), 1, 100);
      const rows = await dbAllAsync(`SELECT id FROM messages WHERE room=? AND deleted=0 ORDER BY ts DESC LIMIT ?`, [room, amt]);
      for (const r of rows) {
        await dbRunAsync(`UPDATE messages SET deleted=1 WHERE id=?`, [r.id]);
        io.to(room).emit("message deleted", { messageId: r.id });
      }
      return { ok: true, message: `Cleared ${rows.length} messages in #${room}` };
    },
  },
  lockroom: {
    minRole: "Moderator",
    description: "Lock room for staff only",
    usage: "/lockroom",
    example: "/lockroom",
    handler: async ({ room }) => {
      await dbRunAsync(`UPDATE rooms SET is_locked=1 WHERE name=?`, [room]);
      return { ok: true, message: `Room #${room} locked` };
    },
  },
  unlockroom: {
    minRole: "Moderator",
    description: "Unlock room",
    usage: "/unlockroom",
    example: "/unlockroom",
    handler: async ({ room }) => {
      await dbRunAsync(`UPDATE rooms SET is_locked=0 WHERE name=?`, [room]);
      return { ok: true, message: `Room #${room} unlocked` };
    },
  },
  report: {
    minRole: "Moderator",
    description: "File a report",
    usage: "/report @user [reason]",
    example: "/report @BadUser harassment",
    handler: async ({ args, actor, actorRole }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (roleRank(target.role) >= roleRank(actorRole)) return { ok: false, message: "Permission denied" };
      const reason = args.slice(1).join(" ").slice(0, 180) || "No reason";
      logModAction({ actor, action: "REPORT", targetUserId: target.id, targetUsername: target.username, room: null, details: reason });
      return { ok: true, message: `Reported ${target.username}: ${reason}` };
    },
  },
  kick: {
    minRole: "Admin",
    description: "Kick a user",
    usage: "/kick @user [reason]",
    example: "/kick @Alex spam",
    handler: async ({ args, actorRole }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.disconnect(true);
      return { ok: true, message: `Kicked ${target.username}` };
    },
  },
  ban: {
    minRole: "Admin",
    description: "Ban a user",
    usage: "/ban @user [hours|days|perm] [reason]",
    example: "/ban @alex 24h spam",
    handler: async ({ args, actorRole, actor }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const dur = (args[1] || "perm").toLowerCase();
      let expiresAt = null;
      if (dur.endsWith("h")) expiresAt = Date.now() + clamp(Number(dur.replace(/h$/, "")), 1, 240) * 60 * 60 * 1000;
      else if (dur.endsWith("d")) expiresAt = Date.now() + clamp(Number(dur.replace(/d$/, "")), 1, 30) * 24 * 60 * 60 * 1000;
      const reason = args.slice(expiresAt ? 2 : 1).join(" ").slice(0, 180) || null;
      await dbRunAsync(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at) VALUES (?, 'ban', ?, ?, ?, ?)`,
        [target.id, expiresAt, reason, actor.id, Date.now()]
      );
      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.disconnect(true);
      return { ok: true, message: `Banned ${target.username}${expiresAt ? " temporarily" : " permanently"}` };
    },
  },
  unban: {
    minRole: "Admin",
    description: "Remove a ban",
    usage: "/unban @user",
    example: "/unban @alex",
    handler: async ({ args, actorRole }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      await dbRunAsync(`DELETE FROM punishments WHERE user_id=? AND type='ban'`, [target.id]);
      return { ok: true, message: `Unbanned ${target.username}` };
    },
  },
  banlist: {
    minRole: "Admin",
    description: "List bans",
    usage: "/banlist",
    example: "/banlist",
    handler: async () => {
      const rows = await dbAllAsync(
        `SELECT p.user_id, u.username, p.expires_at, p.reason FROM punishments p JOIN users u ON u.id = p.user_id WHERE type='ban'`
      );
      const lines = rows.map((r) => `${r.username}${r.expires_at ? ` (until ${new Date(r.expires_at).toISOString()})` : " (perm)"}`);
      return { ok: true, message: lines.join("\n") || "No active bans" };
    },
  },
  rename: {
    minRole: "Admin",
    description: "Rename a user",
    usage: "/rename @user newName",
    example: "/rename @alex Alex2",
    handler: async ({ args, actorRole }) => {
      if (args.length < 2) return { ok: false, message: "Usage: /rename @user newName" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const newName = sanitizeUsername(args.slice(1).join(" "));
      if (!newName) return { ok: false, message: "Invalid name" };
      await dbRunAsync(`UPDATE users SET username=? WHERE id=?`, [newName, target.id]);
      return { ok: true, message: `Renamed to ${newName}` };
    },
  },
  createroom: {
    minRole: "Admin",
    description: "Create room",
    usage: "/createroom room-name",
    example: "/createroom chill",
    handler: async ({ args, actor }) => {
      const name = sanitizeRoomName(args[0] || "");
      if (!name) return { ok: false, message: "Invalid room" };
      await dbRunAsync(`INSERT OR IGNORE INTO rooms (name, created_by, created_at) VALUES (?, ?, ?)`, [name, actor.id, Date.now()]);
      io.emit("rooms update", (await dbAllAsync(`SELECT name FROM rooms ORDER BY name ASC`)).map((r) => r.name));
      return { ok: true, message: `Created room #${name}` };
    },
  },
  deleteroom: {
    minRole: "Admin",
    description: "Delete room",
    usage: "/deleteroom room-name",
    example: "/deleteroom chill",
    handler: async ({ args }) => {
      const name = sanitizeRoomName(args[0] || "");
      if (!name) return { ok: false, message: "Invalid room" };
      await dbRunAsync(`DELETE FROM rooms WHERE name=?`, [name]);
      await dbRunAsync(`DELETE FROM messages WHERE room=?`, [name]);
      io.emit("rooms update", (await dbAllAsync(`SELECT name FROM rooms ORDER BY name ASC`)).map((r) => r.name));
      return { ok: true, message: `Deleted room #${name}` };
    },
  },
  movemsg: {
    minRole: "Admin",
    description: "Move a message",
    usage: "/movemsg messageId room",
    example: "/movemsg 12 general",
    handler: async ({ args }) => {
      const msgId = Number(args[0]);
      const dest = sanitizeRoomName(args[1] || "");
      if (!msgId || !dest) return { ok: false, message: "Missing arguments" };
      await dbRunAsync(`UPDATE messages SET room=? WHERE id=?`, [dest, msgId]);
      return { ok: true, message: `Moved message ${msgId} to #${dest}` };
    },
  },
  staffnote: {
    minRole: "Admin",
    description: "Add staff note",
    usage: "/staffnote @user [note]",
    example: "/staffnote @alex good contributor",
    handler: async ({ args, actorRole, actor }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      const note = args.slice(1).join(" ").slice(0, 400) || "(no note)";
      logModAction({ actor, action: "STAFF_NOTE", targetUserId: target.id, targetUsername: target.username, details: note });
      return { ok: true, message: `Noted: ${note}` };
    },
  },
  giverole: {
    minRole: "Co-owner",
    description: "Grant role up to Admin",
    usage: "/giverole @user role",
    example: "/giverole @sam Admin",
    handler: async ({ args, actorRole }) => {
      if (args.length < 2) return { ok: false, message: "Missing arguments" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      const role = args[1].replace(/-/g, " ");
      if (!ROLES.includes(role)) return { ok: false, message: "Unknown role" };
      if (roleRank(role) >= roleRank("Owner")) return { ok: false, message: "Cannot grant Owner" };
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      await dbRunAsync(`UPDATE users SET role=? WHERE id=?`, [role, target.id]);
      return { ok: true, message: `Role set to ${role} for ${target.username}` };
    },
  },
  removerole: {
    minRole: "Co-owner",
    description: "Remove a role",
    usage: "/removerole @user role",
    example: "/removerole @sam Moderator",
    handler: async ({ args, actorRole }) => {
      if (args.length < 2) return { ok: false, message: "Missing arguments" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      const role = args[1].replace(/-/g, " ");
      if (!canModerate(actorRole, target.role)) return { ok: false, message: "Permission denied" };
      if (roleRank(role) >= roleRank(actorRole)) return { ok: false, message: "Cannot remove equal role" };
      await dbRunAsync(`UPDATE users SET role='User' WHERE id=?`, [target.id]);
      return { ok: true, message: `Removed role from ${target.username}` };
    },
  },
  givegold: {
    minRole: "Co-owner",
    description: "Add gold",
    usage: "/givegold @user amount",
    example: "/givegold @sam 50",
    handler: async ({ args }) => {
      const amt = Number(args[1]);
      if (!args[0] || !Number.isFinite(amt)) return { ok: false, message: "Missing arguments" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      await dbRunAsync(`UPDATE users SET gold = gold + ? WHERE id=?`, [amt, target.id]);
      emitProgressionUpdate(target.id);
      return { ok: true, message: `Gave ${amt} gold to ${target.username}` };
    },
  },
  setgold: {
    minRole: "Co-owner",
    description: "Set user gold",
    usage: "/setgold @user amount",
    example: "/setgold @sam 0",
    handler: async ({ args }) => {
      const amt = Number(args[1]);
      if (!args[0] || !Number.isFinite(amt)) return { ok: false, message: "Missing arguments" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      await dbRunAsync(`UPDATE users SET gold=? WHERE id=?`, [amt, target.id]);
      emitProgressionUpdate(target.id);
      return { ok: true, message: `Set gold for ${target.username} to ${amt}` };
    },
  },
  resetxp: {
    minRole: "Co-owner",
    description: "Reset XP",
    usage: "/resetxp @user",
    example: "/resetxp @sam",
    handler: async ({ args }) => {
      if (!args[0]) return { ok: false, message: "Missing user" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      await dbRunAsync(`UPDATE users SET xp=0 WHERE id=?`, [target.id]);
      return { ok: true, message: `Reset XP for ${target.username}` };
    },
  },
  setlevel: {
    minRole: "Co-owner",
    description: "Set level",
    usage: "/setlevel @user level",
    example: "/setlevel @sam 5",
    handler: async ({ args }) => {
      const level = Number(args[1]);
      if (!args[0] || !Number.isFinite(level) || level < 1) return { ok: false, message: "Missing arguments" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      let xpNeeded = 0;
      for (let i = 1; i < Math.floor(level); i++) xpNeeded += i * 100;
      await dbRunAsync(`UPDATE users SET xp=? WHERE id=?`, [xpNeeded, target.id]);
      return { ok: true, message: `Set level ${level} for ${target.username}` };
    },
  },
  pinmsg: {
    minRole: "Co-owner",
    description: "Pin message",
    usage: "/pinmsg messageId",
    example: "/pinmsg 12",
    handler: async ({ args, room }) => {
      const mid = Number(args[0]);
      if (!mid) return { ok: false, message: "Missing message id" };
      const row = await dbGetAsync(`SELECT pinned_message_ids FROM rooms WHERE name=?`, [room]);
      let arr = [];
      if (row?.pinned_message_ids) {
        try {
          arr = JSON.parse(row.pinned_message_ids) || [];
        } catch (e) {
          arr = [];
        }
      }
      if (!arr.includes(mid)) arr.push(mid);
      await dbRunAsync(`UPDATE rooms SET pinned_message_ids=? WHERE name=?`, [JSON.stringify(arr.slice(-20)), room]);
      return { ok: true, message: `Pinned message ${mid} in #${room}` };
    },
  },
  announcement: {
    minRole: "Co-owner",
    description: "Broadcast message",
    usage: "/announcement message",
    example: "/announcement Maintenance soon",
    handler: async ({ args }) => {
      const msg = args.join(" ").trim();
      if (!msg) return { ok: false, message: "Missing message" };
      io.emit("system", `[Announcement] ${msg}`);
      return { ok: true, message: "Announcement sent" };
    },
  },
  maintenance: {
    minRole: "Co-owner",
    description: "Toggle maintenance mode",
    usage: "/maintenance on|off",
    example: "/maintenance on",
    handler: async ({ args }) => {
      const val = (args[0] || "").toLowerCase();
      if (val !== "on" && val !== "off") return { ok: false, message: "Use on|off" };
      maintenanceState.enabled = val === "on";
      await dbRunAsync(`INSERT INTO config (key, value) VALUES ('maintenance', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [val]);
      io.emit("system", `Maintenance mode ${val}`);
      return { ok: true, message: `Maintenance ${val}` };
    },
  },
  wipeuser: {
    minRole: "Owner",
    description: "Delete a user",
    usage: "/wipeuser @user confirm",
    example: "/wipeuser @alex confirm",
    handler: async ({ args }) => {
      if (args[1] !== "confirm") return { ok: false, message: "Missing confirm" };
      const target = await new Promise((resolve, reject) => findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u))));
      await dbRunAsync(`DELETE FROM users WHERE id=?`, [target.id]);
      await dbRunAsync(`DELETE FROM messages WHERE user_id=?`, [target.id]);
      await dbRunAsync(`DELETE FROM punishments WHERE user_id=?`, [target.id]);
      return { ok: true, message: `Wiped user ${target.username}` };
    },
  },
  wipegold: {
    minRole: "Owner",
    description: "Reset all gold",
    usage: "/wipegold confirm",
    example: "/wipegold confirm",
    handler: async ({ args }) => {
      if (args[0] !== "confirm") return { ok: false, message: "Missing confirm" };
      await dbRunAsync(`UPDATE users SET gold=0`);
      for (const uid of socketIdByUserId.keys()) emitProgressionUpdate(uid);
      return { ok: true, message: "All gold reset" };
    },
  },
  wipelevels: {
    minRole: "Owner",
    description: "Reset all XP",
    usage: "/wipelevels confirm",
    example: "/wipelevels confirm",
    handler: async ({ args }) => {
      if (args[0] !== "confirm") return { ok: false, message: "Missing confirm" };
      await dbRunAsync(`UPDATE users SET xp=0`);
      return { ok: true, message: "All levels reset" };
    },
  },
  forcereload: {
    minRole: "Owner",
    description: "Reload server state",
    usage: "/forcereload",
    example: "/forcereload",
    handler: async () => ({ ok: true, message: "Reloaded config" }),
  },
  setconfig: {
    minRole: "Owner",
    description: "Set config flag",
    usage: "/setconfig key value",
    example: "/setconfig maintenance off",
    handler: async ({ args }) => {
      if (args.length < 2) return { ok: false, message: "Missing key/value" };
      const key = args[0];
      const val = args.slice(1).join(" ");
      await dbRunAsync(`INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [key, val]);
      if (key === "maintenance") maintenanceState.enabled = val === "on";
      return { ok: true, message: `Config ${key} set` };
    },
  },
  auditlog: {
    minRole: "Owner",
    description: "View command log",
    usage: "/auditlog",
    example: "/auditlog",
    handler: async () => {
      const rows = await dbAllAsync(
        `SELECT executor_username, command_name, success, error, ts FROM command_audit ORDER BY ts DESC LIMIT 50`
      );
      const lines = rows.map((r) => `${new Date(r.ts).toISOString()} - ${r.executor_username}: ${r.command_name} ${r.success ? "ok" : "fail"}${r.error ? ` (${r.error})` : ""}`);
      return { ok: true, message: lines.join("\n") || "No audit entries" };
    },
  },
  godmode: {
    minRole: "Owner",
    description: "Toggle godmode",
    usage: "/godmode on|off",
    example: "/godmode on",
    handler: async ({ args, actor }) => {
      const val = (args[0] || "").toLowerCase();
      if (val !== "on" && val !== "off") return { ok: false, message: "Use on|off" };
      if (val === "on") godmodeUsers.add(actor.id);
      else godmodeUsers.delete(actor.id);
      return { ok: true, message: `Godmode ${val}` };
    },
  },
};

async function executeCommand(socket, rawText, room) {
  const parsed = parseCommand(rawText);
  if (!parsed) return false;
  const actor = socket.user;
  const actorRole = godmodeUsers.has(actor.id) ? "Owner" : socket.request.session.user.role;
  const meta = commandRegistry[parsed.name];
  if (!meta) {
    socket.emit("command response", { ok: false, message: "Unknown command" });
    logCommandAudit({ executor: actor, commandName: parsed.name, args: parsed.args, room, success: false, error: "Unknown" });
    return true;
  }
  if (!requireMinRole(actorRole, meta.minRole || "User")) {
    const msg = "Permission denied";
    socket.emit("command response", { ok: false, message: msg });
    logCommandAudit({ executor: actor, commandName: parsed.name, args: parsed.args, room, success: false, error: msg });
    return true;
  }

  try {
    const result = await meta.handler({ args: parsed.args, room, socket, actor, actorRole });
    const payload = { ok: !!result.ok, message: result.message, type: result.type || "info" };
    if (result.commands) payload.commands = result.commands;
    if (result.role) payload.role = result.role;
    socket.emit("command response", payload);
    logCommandAudit({ executor: actor, commandName: parsed.name, args: parsed.args, room, success: !!result.ok, targets: result.targets });
  } catch (err) {
    socket.emit("command response", { ok: false, message: err.message || "Command failed" });
    logCommandAudit({ executor: actor, commandName: parsed.name, args: parsed.args, room, success: false, error: err.message });
  }
  return true;
}
const AUTO_OWNER = new Set(["iri"]);
const AUTO_COOWNERS = new Set(["lola henderson", "amelia"]);

function levelInfo(xpRaw) {
  let xp = Math.max(0, Math.floor(Number(xpRaw) || 0));
  let level = 1;
  let remaining = xp;
  while (remaining >= level * 100) {
    remaining -= level * 100;
    level += 1;
  }
  const xpForNextLevel = level * 100;
  return { level, xpIntoLevel: remaining, xpForNextLevel };
}

function emitLevelUp(userId, newLevel) {
  const sid = socketIdByUserId.get(userId);
  if (sid) io.to(sid).emit("level up", { level: newLevel });
}

function applyXpGain(userId, delta, cb) {
  const amount = Math.max(0, Math.floor(Number(delta) || 0));
  if (!amount) return cb?.(null, null);

  db.get("SELECT xp FROM users WHERE id = ?", [userId], (err, row) => {
    if (err || !row) return cb?.(err || new Error("missing"));

    const prevXp = Math.max(0, Math.floor(Number(row.xp) || 0));
    const prevLevel = levelInfo(prevXp).level;
    const newXp = prevXp + amount;
    const info = levelInfo(newXp);

    db.run("UPDATE users SET xp = ? WHERE id = ?", [newXp, userId], () => {
      if (info.level > prevLevel) emitLevelUp(userId, info.level);
      cb?.(null, { xp: newXp, ...info });
    });
  });
}

function awardMessageXp(userId) {
  const now = Date.now();
  db.get("SELECT xp, lastXpMessageAt FROM users WHERE id = ?", [userId], (err, row) => {
    if (err || !row) return;
    if (row.lastXpMessageAt && now - row.lastXpMessageAt < 30_000) return;

    const prevXp = Math.max(0, Math.floor(Number(row.xp) || 0));
    const prevLevel = levelInfo(prevXp).level;
    const newXp = prevXp + 5;
    const info = levelInfo(newXp);

    db.run(
      "UPDATE users SET xp = ?, lastXpMessageAt = ? WHERE id = ?",
      [newXp, now, userId],
      () => {
        if (info.level > prevLevel) emitLevelUp(userId, info.level);
      }
    );
  });
}

function awardDailyLoginXp(user) {
  const now = Date.now();
  const last = Number(user.lastDailyLoginAt || 0);
  if (last && now - last < 24 * 60 * 60 * 1000) return;

  const prevXp = Math.max(0, Math.floor(Number(user.xp) || 0));
  const prevLevel = levelInfo(prevXp).level;
  const newXp = prevXp + 25;
  const info = levelInfo(newXp);

  db.run(
    "UPDATE users SET xp = ?, lastDailyLoginAt = ? WHERE id = ?",
    [newXp, now, user.id],
    () => {
      if (info.level > prevLevel) emitLevelUp(user.id, info.level);
    }
  );
}

function initGoldTick(userId, now = Date.now()) {
  (async () => {
    try {
      if (await pgUserExists(userId)) {
        // IMPORTANT: camelCase columns must be quoted in Postgres.
        await pgPool.query('UPDATE users SET "lastGoldTickAt" = $1 WHERE id = $2', [now, userId]);
        return;
      }
    } catch (e) {
      console.warn("[initGoldTick][pg] failed, falling back to sqlite:", e?.message || e);
    }
    db.run("UPDATE users SET lastGoldTickAt = ? WHERE id = ?", [now, userId]);
  })();
}


function awardPassiveGold(userId, cb) {
  const now = Date.now();

  // Avoid double-awards when multiple async triggers fire at once for the same user.
  if (goldInFlight.has(userId)) return cb?.(null, 0);
  goldInFlight.add(userId);
  const done = (err, gained) => {
    goldInFlight.delete(userId);
    cb?.(err, gained);
  };

  (async () => {
    try {
      if (await pgUserExists(userId)) {
        const row = await pgGetUserRowById(userId, ["lastGoldTickAt"]);
        if (!row) return cb?.(new Error("missing"));

        const last = Number(row.lastGoldTickAt || 0);
        if (!last) {
              await pgPool.query('UPDATE users SET "lastGoldTickAt" = $1 WHERE id = $2', [now, userId]);
          // Best-effort mirror to SQLite to prevent double-award if we fall back later.
          db.run("UPDATE users SET lastGoldTickAt = ? WHERE id = ?", [now, userId], () => {});
          return done(null, 0);
        }

        const elapsed = now - last;
        const ticks = Math.floor(elapsed / GOLD_TICK_MS);
        if (ticks <= 0) return done(null, 0);

        const newTickTs = last + ticks * GOLD_TICK_MS;
          await pgPool.query(
            'UPDATE users SET gold = gold + $1, "lastGoldTickAt" = $2 WHERE id = $3',
            [ticks, newTickTs, userId]
          );
        // Best-effort mirror to SQLite so a transient PG/SQLite flip doesn't double-award.
        db.run(
          "UPDATE users SET gold = gold + ?, lastGoldTickAt = ? WHERE id = ?",
          [ticks, newTickTs, userId],
          () => {}
        );
        if (ticks > 0) emitProgressionUpdate(userId);
        return done(null, ticks);
      }
    } catch (e) {
      console.warn("[passiveGold][pg] failed, falling back to sqlite:", e?.message || e);
    }

    // SQLite fallback (original behavior)
    db.get("SELECT lastGoldTickAt FROM users WHERE id = ?", [userId], (err, row) => {
      if (err || !row) return done(err || new Error("missing"), 0);

      const last = Number(row.lastGoldTickAt || 0);
      if (!last) {
        db.run(
          "UPDATE users SET lastGoldTickAt = ? WHERE id = ?",
          [now, userId],
          async () => {
            // Best-effort mirror to Postgres to prevent double-award if PG becomes available again.
            try {
              if (await pgUserExists(userId)) {
                await pgPool.query('UPDATE users SET "lastGoldTickAt" = $1 WHERE id = $2', [now, userId]);
              }
            } catch {}
            done(null, 0);
          }
        );
        return;
      }

      const elapsed = now - last;
      const ticks = Math.floor(elapsed / GOLD_TICK_MS);
      if (ticks <= 0) return done(null, 0);

      const newTickTs = last + ticks * GOLD_TICK_MS;
      db.run(
        "UPDATE users SET gold = gold + ?, lastGoldTickAt = ? WHERE id = ?",
        [ticks, newTickTs, userId],
        async (updateErr) => {
          if (updateErr) return done(updateErr, 0);

          // Best-effort mirror to Postgres to prevent double-award if PG becomes available again.
          try {
            if (await pgUserExists(userId)) {
              await pgPool.query(
                'UPDATE users SET gold = gold + $1, "lastGoldTickAt" = $2 WHERE id = $3',
                [ticks, newTickTs, userId]
              );
            }
          } catch {}

          if (ticks > 0) emitProgressionUpdate(userId);
          done(null, ticks);
        }
      );
    });
  })();
}


function awardMessageGold(userId, cb) {
  const now = Date.now();

  if (goldInFlight.has(userId)) return cb?.(null, 0);
  goldInFlight.add(userId);
  const done = (err, gained) => {
    goldInFlight.delete(userId);
    cb?.(err, gained);
  };

  (async () => {
    try {
      if (await pgUserExists(userId)) {
        const row = await pgGetUserRowById(userId, ["lastMessageGoldAt"]);
        if (!row) return done(new Error("missing"));

        const last = Number(row.lastMessageGoldAt || 0);
        if (last && now - last < MESSAGE_GOLD_COOLDOWN_MS) return done(null, 0);

        // Award message gold in Postgres
        await pgPool.query(
          'UPDATE users SET gold = gold + 5, "lastMessageGoldAt" = $1 WHERE id = $2',
          [now, userId]
        );

        // Best-effort mirror to SQLite so a transient PG/SQLite flip doesn't double-award
        db.run(
          "UPDATE users SET gold = gold + 5, lastMessageGoldAt = ? WHERE id = ?",
          [now, userId],
          () => {}
        );

        emitProgressionUpdate(userId);
        return done(null, 5);
      }
    } catch (e) {
      console.warn("[messageGold][pg] failed, falling back to sqlite:", e?.message || e);
    }

    // SQLite fallback
    db.get("SELECT lastMessageGoldAt FROM users WHERE id = ?", [userId], (err, row) => {
      if (err || !row) return done(err || new Error("missing"));
      const last = Number(row.lastMessageGoldAt || 0);
      if (last && now - last < MESSAGE_GOLD_COOLDOWN_MS) return done(null, 0);

      db.run(
        "UPDATE users SET gold = gold + 5, lastMessageGoldAt = ? WHERE id = ?",
        [now, userId],
        async (err2) => {
          if (err2) return done(err2);

          // Best-effort mirror to Postgres to prevent double-awarding if PG becomes available again
          try {
            if (await pgUserExists(userId)) {
              await pgPool.query(
                'UPDATE users SET gold = gold + 5, "lastMessageGoldAt" = $1 WHERE id = $2',
                [now, userId]
              );
            }
          } catch {}

          emitProgressionUpdate(userId);
          return done(null, 5);
        }
      );
    });
  })();
}

function awardDailyLoginGold(user) {
  const now = Date.now();
  const last = Number(user.lastDailyLoginGoldAt || 0);
  if (last && now - last < DAILY_GOLD_COOLDOWN_MS) return;

  db.run(
    "UPDATE users SET gold = gold + 50, lastDailyLoginGoldAt = ? WHERE id = ?",
    [now, user.id],
    () => emitProgressionUpdate(user.id)
  );
}

function progressionFromRow(row, includePrivate) {
  const info = levelInfo(row?.xp || 0);
  const base = { level: info.level };
  if (includePrivate) {
    base.gold = Number(row?.gold || 0);
    base.xp = Number(row?.xp || 0);
    base.xpIntoLevel = info.xpIntoLevel;
    base.xpForNextLevel = info.xpForNextLevel;
  }
  return base;
}

function emitProgressionUpdate(userId) {
  const sid = socketIdByUserId.get(userId);
  if (!sid) return;

  (async () => {
    try {
      if (await pgUserExists(userId)) {
        const row = await pgGetUserRowById(userId, ["gold", "xp"]);
        if (!row) return;
        io.to(sid).emit("progression:update", progressionFromRow(row, true));
        return;
      }
    } catch (e) {
      console.warn("[progression][pg] failed, falling back to sqlite:", e?.message || e);
    }

    db.get("SELECT gold, xp FROM users WHERE id = ?", [userId], (err, row) => {
      if (err || !row) return;
      io.to(sid).emit("progression:update", progressionFromRow(row, true));
    });
  })();
}


function fetchUsersByNames(usernames, cb) {
  const cleaned = Array.from(
    new Set(
      (usernames || [])
        .map((u) => sanitizeUsername(u))
        .filter(Boolean)
        .map((u) => normKey(u))
    )
  );
  if (!cleaned.length) return cb(null, []);

  const placeholders = cleaned.map(() => "?").join(",");
  db.all(
    `SELECT id, username FROM users WHERE lower(username) IN (${placeholders})`,
    cleaned,
    (err, rows) => cb(err, rows || [])
  );
}
function sanitizeRoomName(r) {
  r = String(r || "").trim();
  r = r.replace(/^#+/, "");      // drop leading '#'
  r = r.toLowerCase();
  r = r.replace(/[^a-z0-9_-]/g, "");
  return r.slice(0, 24);
}
function loadThreadForUser(threadId, userId, cb) {
  db.get(
    `SELECT id, title, is_group FROM dm_threads WHERE id = ?`,
    [threadId],
    (err, thread) => {
      if (err || !thread) return cb(err || new Error("missing"));

      db.get(
        `SELECT 1 FROM dm_participants WHERE thread_id=? AND user_id=?`,
        [threadId, userId],
        (err2, member) => {
          if (err2 || !member) return cb(err2 || new Error("forbidden"));

          db.all(
            `SELECT u.username FROM dm_participants dp JOIN users u ON u.id = dp.user_id WHERE dp.thread_id = ?`,
            [threadId],
            (err3, parts) => {
              if (err3) return cb(err3);
              cb(null, {
                ...thread,
                participants: (parts || []).map((p) => p.username),
              });
            }
          );
        }
      );
    }
  );
}

function logModAction({ actor, action, targetUserId, targetUsername, room, details }) {
  db.run(
    `INSERT INTO mod_logs (ts, actor_user_id, actor_username, actor_role, action, target_user_id, target_username, room, details)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      Date.now(),
      actor?.id || null,
      actor?.username || null,
      actor?.role || null,
      action,
      targetUserId || null,
      targetUsername || null,
      room || null,
      details || null,
    ]
  );
}

function requireLogin(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  next();
}

const CHANGELOG_TITLE_MAX = 120;
const CHANGELOG_BODY_MAX = 8000;

function requireOwner(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  if (!requireMinRole(req.session.user.role, "Owner")) return res.status(403).send("Forbidden");
  next();
}

function toChangelogPayload(row) {
  if (!row) return null;
  return {
    id: row.id,
    seq: row.seq,
    title: row.title,
    body: row.body || "",
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    authorId: row.author_id,
  };
}

function cleanChangelogInput(title, body) {
  const cleanTitle = String(title || "").trim();
  const cleanBody = String(body || "").trimEnd();
  if (!cleanTitle) return { error: "Title is required" };
  if (cleanTitle.length > CHANGELOG_TITLE_MAX) return { error: `Title must be at most ${CHANGELOG_TITLE_MAX} characters` };
  if (cleanBody.length > CHANGELOG_BODY_MAX) return { error: `Body must be at most ${CHANGELOG_BODY_MAX} characters` };
  return { title: cleanTitle, body: cleanBody };
}

function createChangelogEntry({ title, body, authorId }) {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run("BEGIN IMMEDIATE TRANSACTION", (beginErr) => {
        if (beginErr) return reject(beginErr);

        db.get("SELECT COALESCE(MAX(seq), 0) AS maxSeq FROM changelog_entries", [], (maxErr, row) => {
          if (maxErr) return db.run("ROLLBACK", () => reject(maxErr));

          const nextSeq = Number(row?.maxSeq || 0) + 1;
          const now = Date.now();

          db.run(
            `INSERT INTO changelog_entries (seq, title, body, created_at, updated_at, author_id) VALUES (?, ?, ?, ?, ?, ?)`,
            [nextSeq, title, body, now, now, authorId],
            function (insErr) {
              if (insErr) return db.run("ROLLBACK", () => reject(insErr));

              db.run("COMMIT", (commitErr) => {
                if (commitErr) return db.run("ROLLBACK", () => reject(commitErr));
                resolve({
                  id: this.lastID,
                  seq: nextSeq,
                  title,
                  body,
                  created_at: now,
                  updated_at: now,
                  author_id: authorId,
                });
              });
            }
          );
        });
      });
    });
  });
}

// ---- Auth routes
// ---- Auth routes
app.post("/register", async (req, res) => {
  try {
    const username = sanitizeUsername(req.body?.username);
    const password = String(req.body?.password || "");

    if (!username || username.length < 2) return res.status(400).send("Invalid username");
    if (!password || password.length < 6) return res.status(400).send("Password must be 6+ chars");

    // Prevent duplicates (PG is canonical)
    const existingPg = await pgGetUserByUsername(username);
    if (existingPg) return res.status(409).send("Username already taken");

    const hash = await bcrypt.hash(password, 10);
    const createdAt = Date.now();

    const norm = normKey(username);
    let role = "User";
    if (AUTO_OWNER.has(norm)) role = "Owner";
    else if (AUTO_COOWNERS.has(norm)) role = "Co-owner";

    const theme = DEFAULT_THEME;

    // 1) Create user in Postgres
    const createdAtValue = PG_USERS_CREATED_AT_IS_TIMESTAMP ? new Date(createdAt) : createdAt;
    const { rows } = await pgPool.query(
      `INSERT INTO users (username, password_hash, role, created_at, theme)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, username, role, theme`,
      [username, hash, role, createdAtValue, theme]
    );

    const user = rows[0];
    if (!user) return res.status(500).send("Registration failed");

    // 2) Mirror into SQLite
    try {
      await dbRunAsync(
        `INSERT INTO users (id, username, password_hash, role, created_at, gold, xp, theme)
         VALUES (?,?,?,?,?,?,?,?)`,
        [user.id, username, hash, role, createdAt, 0, 0, sanitizeThemeNameServer(theme)]
      );
    } catch (_e) {
      await dbRunAsync(
        `UPDATE users
            SET username = ?, password_hash = ?, role = ?,
                created_at = COALESCE(created_at, ?),
                theme = COALESCE(theme, ?)
          WHERE id = ?`,
        [username, hash, role, createdAt, sanitizeThemeNameServer(theme), user.id]
      );
    }

    // 3) Create session
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      theme: sanitizeThemeNameServer(user.theme),
    };

    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).send("Session save failed");
      return res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("Registration failed");
  }
});
app.post("/login", async (req, res) => {
  try {
    const username = sanitizeUsername(req.body?.username);
    const password = String(req.body?.password || "");
    if (!username || !password) return res.status(400).send("Missing credentials");

    // 1) Prefer Postgres users (new registrations land here)
    const pgUser = await pgGetUserByUsername(username);
    if (pgUser && pgUser.password_hash) {
      const ok = await bcrypt.compare(password, String(pgUser.password_hash || ""));
      if (!ok) return res.status(401).send("Invalid username or password");

      const theme = sanitizeThemeNameServer(pgUser.theme || DEFAULT_THEME);

      // Mirror into SQLite if missing (some UI/profile/dice logic still reads SQLite)
      const srow = await dbGetAsync("SELECT id FROM users WHERE id = ?", [pgUser.id]).catch(() => null);
      if (!srow) {
        await dbRunAsync(
          `INSERT INTO users (id, username, password_hash, role, created_at, gold, xp, theme)
           VALUES (?,?,?,?,?,?,?,?)`,
          [
            pgUser.id,
            pgUser.username,
            pgUser.password_hash,
            pgUser.role || "User",
            Number(pgUser.created_at || Date.now()),
            Number(pgUser.gold || 0),
            Number(pgUser.xp || 0),
            theme,
          ]
        );
      }

      req.session.user = { id: pgUser.id, username: pgUser.username, role: pgUser.role, theme };
      await dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", pgUser.id]).catch(() => {});

      initGoldTick(pgUser.id);

      return req.session.save((saveErr) => {
        if (saveErr) return res.status(500).send("Session save failed");
        return res.json({ ok: true });
      });
    }

    // 2) Fallback to SQLite (legacy accounts)
    const row = await dbGetAsync("SELECT * FROM users WHERE lower(username) = lower(?)", [username]);
    if (!row) return res.status(401).send("Invalid username or password");

    // Handle legacy password column (if present)
    let passwordHash = typeof row.password_hash === "string" ? row.password_hash : "";

    if (!passwordHash) {
      const legacyPassword = typeof row.password === "string" ? row.password : "";
      if (!legacyPassword) return res.status(401).send("Invalid username or password");

      const legacyMatches = legacyPassword.startsWith("$2")
        ? await bcrypt.compare(password, legacyPassword)
        : legacyPassword === password;

      if (!legacyMatches) return res.status(401).send("Invalid username or password");

      passwordHash = legacyPassword.startsWith("$2") ? legacyPassword : await bcrypt.hash(password, 10);

      await dbRunAsync("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [passwordHash, row.id]);
      row.password_hash = passwordHash;
    }

    const ok = await bcrypt.compare(password, String(row.password_hash || ""));
    if (!ok) return res.status(401).send("Invalid username or password");

    // Apply your auto-role rules (keep both stores aligned)
    const norm = normKey(row.username);
    if (AUTO_OWNER.has(norm) && row.role !== "Owner") {
      await dbRunAsync("UPDATE users SET role = 'Owner' WHERE id = ?", [row.id]);
      row.role = "Owner";
    } else if (AUTO_COOWNERS.has(norm) && row.role !== "Co-owner") {
      await dbRunAsync("UPDATE users SET role = 'Co-owner' WHERE id = ?", [row.id]);
      row.role = "Co-owner";
    }

    const theme = sanitizeThemeNameServer(row.theme || DEFAULT_THEME);
    if (!row.theme) await dbRunAsync("UPDATE users SET theme = ? WHERE id = ?", [theme, row.id]).catch(() => {});

    // Mirror into Postgres (so /me + progression + persistent systems work)
    await pgPool.query(
      `INSERT INTO users (id, username, password_hash, role, created_at, theme, gold, xp)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (username) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             role = EXCLUDED.role,
             theme = COALESCE(users.theme, EXCLUDED.theme),
             gold = COALESCE(users.gold, EXCLUDED.gold),
             xp = COALESCE(users.xp, EXCLUDED.xp)`,
      [
        row.id,
        row.username,
        passwordHash,
        row.role || "User",
        Number(row.created_at || Date.now()),
        theme,
        Number(row.gold || 0),
        Number(row.xp || 0),
      ]
    ).catch((e) => console.error("PG mirror on login failed:", e));

    req.session.user = { id: row.id, username: row.username, role: row.role, theme };

    await dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", row.id]).catch(() => {});
    awardDailyLoginXp(row);
    awardDailyLoginGold(row);
    initGoldTick(row.id);

    return req.session.save((saveErr) => {
      if (saveErr) return res.status(500).send("Session save failed");
      return res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Login failed");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/me", async (req, res) => {
  try {
    if (!req.session?.user?.id) return res.json(null);

    // Prefer Postgres
    const { rows } = await pgPool.query(
      "SELECT id, username, role, theme FROM users WHERE id = $1 LIMIT 1",
      [req.session.user.id]
    );

    let row = rows[0];

    // If not in Postgres yet, fallback to SQLite and (optionally) sync
    if (!row) {
      const srow = await dbGet(
        "SELECT id, username, role, theme FROM users WHERE id = ?",
        [req.session.user.id]
      );
      if (!srow) return res.json(null);

      const theme = sanitizeThemeNameServer(srow.theme);
      if (!srow.theme) db.run("UPDATE users SET theme = ? WHERE id = ?", [theme, srow.id]);

      // Try to mirror minimal fields into Postgres if the user exists there by id
      // (If your login migration creates PG users with matching ids, this will work;
      // otherwise we’ll handle it during login migration.)
      try {
        await pgPool.query(
          "UPDATE users SET theme = $1, role = $2 WHERE id = $3",
          [theme, srow.role, srow.id]
        );
      } catch (_) {}

      req.session.user = { id: srow.id, username: srow.username, role: srow.role, theme };
      return res.json(req.session.user);
    }

    const theme = sanitizeThemeNameServer(row.theme);
    if (!row.theme) await pgPool.query("UPDATE users SET theme = $1 WHERE id = $2", [theme, row.id]);

    req.session.user = { id: row.id, username: row.username, role: row.role, theme };
    return res.json(req.session.user);
  } catch (e) {
    console.error(e);
    return res.json(null);
  }
});

// Back-compat alias used by some clients
app.get("/api/me", (req, res) => res.redirect(307, "/me"));

app.get("/api/me/progression", requireLogin, async (req, res) => {
  const uid = req.session.user.id;

  const finish = async () => {
    try {
      // Keep current tick logic (SQLite) but mirror results into Postgres
      await syncGoldXpThemeToPg(uid);

      const { rows } = await pgPool.query(
        "SELECT gold, xp FROM users WHERE id = $1 LIMIT 1",
        [uid]
      );
      const row = rows[0];
      if (!row) return res.status(404).send("Not found");

      return res.json(progressionFromRow(row, true));
    } catch (e) {
      console.error(e);
      return res.status(500).send("Failed");
    }
  };

  if (onlineState.has(uid)) {
    awardPassiveGold(uid, () => {
      finish();
    });
  } else {
    finish();
  }
});

app.get("/api/me/gold", requireLogin, async (req, res) => {
  const uid = req.session.user.id;

  const finish = async () => {
    try {
      await syncGoldXpThemeToPg(uid);

      const { rows } = await pgPool.query(
        "SELECT gold FROM users WHERE id = $1 LIMIT 1",
        [uid]
      );
      const row = rows[0];
      if (!row) return res.status(404).send("Not found");

      return res.json({ gold: Number(row.gold || 0) });
    } catch (e) {
      console.error(e);
      return res.status(500).send("Failed");
    }
  };

  if (onlineState.has(uid)) {
    awardPassiveGold(uid, () => { finish(); });
  } else {
    finish();
  }
});

app.get("/api/me/theme", requireLogin, async (req, res) => {
  try {
    // Prefer Postgres
    const { rows } = await pgPool.query(
      "SELECT theme FROM users WHERE id = $1 LIMIT 1",
      [req.session.user.id]
    );
    const row = rows[0];
    if (!row) return res.status(404).send("Not found");

    const theme = sanitizeThemeNameServer(row.theme);
    if (!row.theme) await pgPool.query("UPDATE users SET theme = $1 WHERE id = $2", [theme, req.session.user.id]);

    req.session.user.theme = theme;
    return res.json({ theme });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Failed");
  }
});


app.post("/api/me/theme", requireLogin, async (req, res) => {
  try {
    const theme = sanitizeThemeNameServer(req.body?.theme);

    // Update Postgres (new source of truth for theme)
    await pgPool.query("UPDATE users SET theme = $1 WHERE id = $2", [theme, req.session.user.id]);

    // Keep SQLite in sync until login/user migration is fully done
    db.run("UPDATE users SET theme = ? WHERE id = ?", [theme, req.session.user.id]);

    req.session.user.theme = theme;
    return res.json({ theme });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Failed");
  }
});

app.get("/api/leaderboards", requireLogin, async (_req, res) => {
  try {
    const [xpRows, goldRows, diceRows, likeRows] = await Promise.all([
      dbAllAsync(`SELECT username, xp FROM users ORDER BY xp DESC LIMIT 20`),
      dbAllAsync(`SELECT username, gold FROM users ORDER BY gold DESC LIMIT 20`),
      dbAllAsync(`SELECT username, dice_sixes FROM users ORDER BY dice_sixes DESC LIMIT 20`),
      dbAllAsync(
        `SELECT u.username, COUNT(pl.user_id) AS likes
         FROM users u
         LEFT JOIN profile_likes pl ON pl.target_user_id = u.id
         GROUP BY u.id
         ORDER BY likes DESC
         LIMIT 20`
      ),
    ]);

    const xp = xpRows.map((r) => ({ username: r.username, level: levelInfo(r.xp || 0).level, xp: Number(r.xp || 0) }));
    const gold = goldRows.map((r) => ({ username: r.username, gold: Number(r.gold || 0) }));
    const dice = diceRows.map((r) => ({ username: r.username, sixes: Number(r.dice_sixes || 0) }));
    const likes = likeRows.map((r) => ({ username: r.username, likes: Number(r.likes || 0) }));

    return res.json({ xp, gold, dice, likes });
  } catch (err) {
    return res.status(500).json({ ok: false });
  }
});

app.post("/api/me/award-gold", requireLogin, (req, res) => {
  if (process.env.ALLOW_DEV_AWARD_GOLD !== "1") return res.status(404).send("Not found");
  const amount = clamp(req.body?.amount ?? req.body?.gold ?? 0, 1, 100000);
  if (!amount) return res.status(400).send("Invalid amount");

  db.run("UPDATE users SET gold = gold + ? WHERE id = ?", [amount, req.session.user.id], (err) => {
    if (err) return res.status(500).send("Failed");
    emitProgressionUpdate(req.session.user.id);
    db.get("SELECT gold FROM users WHERE id = ?", [req.session.user.id], (_e, row) => {
      return res.json({ ok: true, gold: row?.gold || 0 });
    });
  });
});
// ---- Rooms API
app.get("/rooms", requireLogin, (_req, res) => {
  db.all(`SELECT name FROM rooms ORDER BY name ASC`, [], (err, rows) => {
    if (err) return res.status(500).send("Failed");
    return res.json((rows || []).map(r => r.name));
  });
});

// Co-owner+ can create rooms
app.post("/rooms", requireLogin, (req, res) => {
  const actor = req.session.user;
  if (!requireMinRole(actor.role, "Co-owner")) return res.status(403).send("Forbidden");

  const name = sanitizeRoomName(req.body?.name || req.body?.room || "");
  if (!name) return res.status(400).send("Invalid room name");

  db.get(`SELECT name FROM rooms WHERE name=?`, [name], (err, row) => {
    if (err) return res.status(500).send("Failed");
    if (row) return res.status(409).send("Room already exists");

    db.run(
      `INSERT INTO rooms (name, created_by, created_at) VALUES (?, ?, ?)`,
      [name, actor.id, Date.now()],
      (insErr) => {
        if (insErr) return res.status(500).send("Failed to create room");

        logModAction({ actor, action: "room.create", room: name, details: null });

        db.all(`SELECT name FROM rooms ORDER BY name ASC`, [], (_e2, rows2) => {
          io.emit("rooms update", (rows2 || []).map(r => r.name));
        });

        return res.json({ ok: true, name });
      }
    );
  });
});

// ---- Changelog API
app.get("/api/changelog", requireLogin, async (req, res) => {
  try {
    const limit = clamp(req.query?.limit || 0, 0, 200);
    const sql =
      "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries ORDER BY seq DESC" +
      (limit ? " LIMIT ?" : "");
    const rows = await dbAllAsync(sql, limit ? [limit] : []);
    return res.json(rows.map((r) => toChangelogPayload(r)));
  } catch (err) {
    return res.status(500).send("Failed to load changelog");
  }
});

app.post("/api/changelog", requireOwner, async (req, res) => {
  const cleaned = cleanChangelogInput(req.body?.title, req.body?.body);
  if (cleaned.error) return res.status(400).send(cleaned.error);

  try {
    const entry = await createChangelogEntry({
      title: cleaned.title,
      body: cleaned.body,
      authorId: req.session.user.id,
    });
    const payload = toChangelogPayload(entry);
    io.emit("changelog updated");
    return res.json(payload);
  } catch (err) {
    return res.status(500).send("Failed to create changelog entry");
  }
});

app.put("/api/changelog/:id", requireOwner, async (req, res) => {
  const id = Number(req.params?.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).send("Invalid entry id");

  const cleaned = cleanChangelogInput(req.body?.title, req.body?.body);
  if (cleaned.error) return res.status(400).send(cleaned.error);

  try {
    const now = Date.now();
    const result = await dbRunAsync(
      `UPDATE changelog_entries SET title=?, body=?, updated_at=? WHERE id=?`,
      [cleaned.title, cleaned.body, now, id]
    );
    if (!result?.changes) return res.status(404).send("Entry not found");

    const row = await dbGetAsync(
      `SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries WHERE id=?`,
      [id]
    );
    io.emit("changelog updated");
    return res.json(toChangelogPayload(row));
  } catch (err) {
    return res.status(500).send("Failed to update changelog entry");
  }
});

app.delete("/api/changelog/:id", requireOwner, async (req, res) => {
  const id = Number(req.params?.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).send("Invalid entry id");

  const confirmed = req.body?.confirm === true || req.body?.confirm === "true";
  if (!confirmed) return res.status(400).send("Confirmation required");

  try {
    const result = await dbRunAsync(`DELETE FROM changelog_entries WHERE id=?`, [id]);
    if (!result?.changes) return res.status(404).send("Entry not found");
    io.emit("changelog updated");
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).send("Failed to delete changelog entry");
  }
});
// ---- Profile routes
app.get("/api/profile", requireLogin, (req, res) => res.redirect(307, "/profile"));

app.get("/profile", requireLogin, async (req, res) => {
  const userId = req.session.user.id;

  try {
    // Prefer Postgres if this user exists there (Render prod path)
    if (await pgUserExists(userId)) {
      const row = await pgGetUserRowById(userId, [
        "id",
        "username",
        "role",
        "avatar",
        "bio",
        "mood",
        "age",
        "gender",
        "created_at",
        "last_seen",
        "last_room",
        "last_status",
        "gold",
        "xp",
      ]);
      if (!row) return res.status(404).send("Not found");

      const live = onlineState.get(row.id);
      const lastStatus = normalizeStatus(live?.status || row.last_status, "");

      // Likes are stored in sqlite in this codebase; keep using it
      db.get(
        `SELECT
          (SELECT COUNT(*) FROM profile_likes WHERE target_user_id = ?) AS likes,
          EXISTS(SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?) AS liked
        `,
        [row.id, userId, row.id],
        (_likeErr, likesRow) => {
          const payload = {
            id: row.id,
            username: row.username,
            role: row.role,
            avatar: row.avatar,
            bio: row.bio,
            mood: row.mood,
            age: row.age,
            gender: row.gender,
            created_at: row.created_at,
            last_seen: row.last_seen,
            last_room: row.last_room,
            last_status: lastStatus || null,
            current_room: live?.room || null,
            likes: Number(likesRow?.likes || 0),
            likedByMe: !!Number(likesRow?.liked || 0),
            ...progressionFromRow(row, true),
          };
          return res.json(payload);
        }
      );
      return;
    }
  } catch (e) {
    console.warn("[/profile][pg] failed, falling back to sqlite:", e?.message || e);
  }

  // SQLite fallback (original behavior)
  db.get(
    `SELECT id, username, role, avatar, bio, mood, age, gender, created_at, last_seen, last_room, last_status, gold, xp
     FROM users WHERE id = ?`,
    [userId],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      const live = onlineState.get(row.id);
      const lastStatus = normalizeStatus(live?.status || row.last_status, "");
      db.get(
        `SELECT
          (SELECT COUNT(*) FROM profile_likes WHERE target_user_id = ?) AS likes,
          EXISTS(SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?) AS liked
        `,
        [row.id, userId, row.id],
        (_likeErr, likesRow) => {
          const payload = {
            id: row.id,
            username: row.username,
            role: row.role,
            avatar: row.avatar,
            bio: row.bio,
            mood: row.mood,
            age: row.age,
            gender: row.gender,
            created_at: row.created_at,
            last_seen: row.last_seen,
            last_room: row.last_room,
            last_status: lastStatus || null,
            current_room: live?.room || null,
            likes: Number(likesRow?.likes || 0),
            likedByMe: !!Number(likesRow?.liked || 0),
            ...progressionFromRow(row, true),
          };
          return res.json(payload);
        }
      );
    }
  );
});

app.get("/profile/:username", requireLogin, (req, res) => {
  const u = sanitizeUsername(req.params.username);
  if (!u) return res.status(400).send("Bad username");

  db.get(
    `SELECT id, username, role, avatar, bio, mood, age, gender, created_at, last_seen, last_room, last_status, gold, xp
     FROM users WHERE lower(username) = lower(?)`,
    [u],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      const live = onlineState.get(row.id);
      const lastStatus = normalizeStatus(live?.status || row.last_status, "");
      const includePrivate = req.session.user.id === row.id;
      db.get(
        `SELECT
          (SELECT COUNT(*) FROM profile_likes WHERE target_user_id = ?) AS likes,
          EXISTS(SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?) AS liked
        `,
        [row.id, req.session.user.id, row.id],
        (_likeErr, likesRow) => {
          const payload = {
            id: row.id,
            username: row.username,
            role: row.role,
            avatar: row.avatar,
            bio: row.bio,
            mood: row.mood,
            age: row.age,
            gender: row.gender,
            created_at: row.created_at,
            last_seen: row.last_seen,
            last_room: row.last_room,
            last_status: lastStatus || null,
            current_room: live?.room || null,
            likes: Number(likesRow?.likes || 0),
            likedByMe: !!Number(likesRow?.liked || 0),
            ...progressionFromRow(row, includePrivate),
          };
          return res.json(payload);
        }
      );
    }
  );
});

app.post("/profile/:username/like", requireLogin, (req, res) => {
  const u = sanitizeUsername(req.params.username);
  if (!u) return res.status(400).send("Bad username");

  db.get(`SELECT id FROM users WHERE lower(username) = lower(?)`, [u], (err, target) => {
    if (err || !target) return res.status(404).send("Not found");
    if (target.id === req.session.user.id) return res.status(400).json({ ok: false, message: "You cannot like yourself." });

    db.get(
      `SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?`,
      [req.session.user.id, target.id],
      (_likeErr, row) => {
        const now = Date.now();
        const toggle = row
          ? dbRunAsync(`DELETE FROM profile_likes WHERE user_id = ? AND target_user_id = ?`, [req.session.user.id, target.id])
          : dbRunAsync(`INSERT INTO profile_likes (user_id, target_user_id, created_at) VALUES (?, ?, ?)`, [
              req.session.user.id,
              target.id,
              now,
            ]);

        Promise.resolve(toggle)
          .then(() => {
            db.get(
              `SELECT
                (SELECT COUNT(*) FROM profile_likes WHERE target_user_id = ?) AS likes,
                EXISTS(SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?) AS liked
              `,
              [target.id, req.session.user.id, target.id],
              (_countErr, likesRow) => {
                return res.json({
                  ok: true,
                  likes: Number(likesRow?.likes || 0),
                  liked: !!Number(likesRow?.liked || 0),
                });
              }
            );
          })
          .catch(() => res.status(500).json({ ok: false, message: "Could not update like" }));
      }
    );
  });
});

// Avatar upload for profile edits (2MB)
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, AVATARS_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").slice(0, 10) || ".png";
      cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(png|jpeg|jpg|webp|gif)$/i.test(file.mimetype || "");
    cb(ok ? null : new Error("Invalid avatar type"), ok);
  },
});

app.post("/profile", requireLogin, avatarUpload.single("avatar"), (req, res) => {
  const mood = String(req.body?.mood || "").slice(0, 40);
  const bio = String(req.body?.bio || "").slice(0, 2000);
  const age = req.body?.age === "" || req.body?.age == null ? null : clamp(req.body.age, 18, 120);
  const gender = String(req.body?.gender || "").slice(0, 40);

  const avatar = req.file ? `/avatars/${req.file.filename}` : null;

io.on("connection", async (socket) => {
  const sessUser = socket.request.session?.user;
  if (!sessUser?.id) {
    socket.disconnect(true);
    return;
  }

  socket.user = {
    id: sessUser.id,
    username: sessUser.username,
    role: sessUser.role,
    status: "Online",
    mood: "",
    avatar: "",
  };

  socketIdByUserId.set(socket.user.id, socket.id);
  onlineXpTrack.set(socket.user.id, { lastTs: Date.now(), carryMs: 0 });
  initGoldTick(socket.user.id);

  // Load profile bits for presence (SQLite)
  db.get(
    "SELECT avatar, mood FROM users WHERE id = ?",
    [socket.user.id],
    (_e, row) => {
      if (row) {
        socket.user.avatar = row.avatar || "";
        socket.user.mood = row.mood || "";
      }
    }
  );

  socket.currentRoom = null;

  // SAFETY: auto-join main
  setTimeout(() => {
    if (!socket.currentRoom) {
      try {
        doJoin("main", socket.user.status || "Online");
      } catch (e) {
        console.warn("[auto-join main] failed:", e?.message || e);
      }
    }
  }, 500);

  socket.dmThreads = new Set();

  if (USE_PG) {
    try {
      const uid = String(socket.user.id);
      const rows = await pgPool.query(
      `SELECT thread_id FROM dm_participants WHERE user_id = $1`,
      [uid]
    );

      for (const r of rows.rows) {
        const tid = String(r.thread_id);
        socket.dmThreads.add(tid);
        socket.join(`dm:${tid}`);
      }
    } catch (e) {
      console.warn("[dm auto-join] failed:", e?.message || e);
    }
  

socket.on("dm:join", async (threadId) => {
  if (!PG_ENABLED) return;
  const tid = String(threadId);
  const uid = String(socket.user.id);
  if (!/^\d+$/.test(tid)) return;
  try {
    const ok = await pgPool.query(
      `SELECT 1 FROM dm_participants WHERE thread_id = $1 AND user_id = $2`,
      [tid, uid]
    );
    if (!ok.rows.length) return;
    socket.dmThreads.add(tid);
    socket.join(`dm:${tid}`);
  } catch (e) {
    // ignore
  }
});

}

  socket.on("join room", ({ room, status }) => {
    const desired = sanitizeRoomName(room) || "main";

    db.get(`SELECT name FROM rooms WHERE name=?`, [desired], (_err, row) => {
      const finalRoom = row ? desired : "main";
      doJoin(finalRoom, status);
    });
  });
});

// ---- Uploads (10MB max). VIP can upload mp4/mov, everyone can upload images.
const chatUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").slice(0, 12) || "";
      cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${ext}`);
    },
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
});

app.post("/upload", requireLogin, chatUpload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).send("No file");

  const mime = String(req.file.mimetype || "");
  const role = req.session.user.role;

  const isImage = /^image\//i.test(mime);
  const isVideo = /^(video\/mp4|video\/quicktime)$/i.test(mime);

  if (!isImage && !isVideo) return res.status(400).json({ message: "File type not allowed" });

  if (isVideo && !requireMinRole(role, "VIP")) {
    return res.status(403).json({ message: "VIP required for video uploads" });
  }

  const url = `/uploads/${req.file.filename}`;
  return res.json({
    url,
    mime,
    size: req.file.size,
    type: isImage ? "image" : "video",
  });
});

// ---- Mod logs API (Moderator+)
app.get("/mod/logs", requireLogin, (req, res) => {
  const role = req.session.user.role;
  if (!requireMinRole(role, "Moderator")) return res.status(403).send("Forbidden");

  const limit = clamp(req.query.limit || 50, 1, 200);
  const user = String(req.query.user || "").trim().slice(0, 40);
  const action = String(req.query.action || "").trim().slice(0, 40);

  const wh = [];
  const args = [];

  if (user) {
    wh.push("(lower(actor_username) = lower(?) OR lower(target_username) = lower(?))");
    args.push(user, user);
  }
  if (action) {
    wh.push("action = ?");
    args.push(action);
  }

  const whereSql = wh.length ? `WHERE ${wh.join(" AND ")}` : "";
  db.all(
    `SELECT ts, actor_username, actor_role, action, target_username, room, details
     FROM mod_logs ${whereSql}
     ORDER BY ts DESC LIMIT ?`,
    [...args, limit],
    (err, rows) => {
      if (err) return res.status(500).send("Failed");
      return res.json(rows || []);
    }
  );
});

// ---- Direct messages API

// -------------------- DMs (Postgres-backed) --------------------
function sqliteUsernamesForIds(ids) {
  return new Promise((resolve) => {
    const nums = (ids || [])
      .map((x) => Number(x))
      .filter((n) => Number.isFinite(n));
    if (!nums.length) return resolve(new Map());
    const placeholders = nums.map(() => "?").join(",");
    db.all(
      `SELECT id, username FROM users WHERE id IN (${placeholders})`,
      nums,
      (_e, rows) => {
        const m = new Map();
        for (const r of rows || []) m.set(String(r.id), r.username);
        resolve(m);
      }
    );
  });
}

async function pgLoadThreadForUser(threadId, userId) {
  const tid = String(threadId);
  const uid = String(userId);

  const allowed = await pgPool.query(
    `SELECT 1 FROM dm_participants WHERE thread_id = $1 AND user_id = $2`,
    [tid, uid]
  );
  if (!allowed.rows.length) throw new Error("not allowed");

  const t = await pgPool.query(
    `SELECT id, title, is_group, created_at, created_by
     FROM dm_threads
     WHERE id = $1`,
    [tid]
  );
  if (!t.rows.length) throw new Error("not found");

  const parts = await pgPool.query(
    `SELECT user_id FROM dm_participants WHERE thread_id = $1`,
    [tid]
  );

  const ids = parts.rows.map((r) => String(r.user_id));
  const nameMap = await sqliteUsernamesForIds(ids);
  const participants = ids.map((id) => nameMap.get(id) || id);

  return {
    ...t.rows[0],
    participants,
  };
}

app.get("/dm/threads", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.json([]);

  const userId = String(req.session.user.id);

  try {
    const threads = await pgPool.query(
      `
      SELECT
        t.id, t.title, t.is_group, t.created_at,
        lm.text AS last_text,
        lm.ts   AS last_ts
      FROM dm_threads t
      JOIN dm_participants p ON p.thread_id = t.id
      LEFT JOIN LATERAL (
        SELECT text, ts
        FROM dm_messages
        WHERE thread_id = t.id
        ORDER BY ts DESC
        LIMIT 1
      ) lm ON TRUE
      WHERE p.user_id = $1
        AND (t.is_group = TRUE OR lm.ts IS NOT NULL)
      ORDER BY COALESCE(lm.ts, EXTRACT(EPOCH FROM t.created_at)*1000) DESC
      `,
      [userId]
    );

    if (!threads.rows.length) return res.json([]);

    const ids = threads.rows.map((t) => String(t.id));
    const parts = await pgPool.query(
      `SELECT thread_id, user_id FROM dm_participants WHERE thread_id = ANY($1::bigint[])`,
      [ids]
    );

    const grouped = new Map();
    for (const p of parts.rows) {
      const tid = String(p.thread_id);
      if (!grouped.has(tid)) grouped.set(tid, []);
      grouped.get(tid).push(String(p.user_id));
    }

    // Map user IDs -> usernames via SQLite (fallback to ID string)
    const allUserIds = Array.from(
      new Set(parts.rows.map((p) => String(p.user_id)))
    );
    const nameMap = await sqliteUsernamesForIds(allUserIds);

    const result = threads.rows.map((t) => {
      const pids = grouped.get(String(t.id)) || [];
      return {
        ...t,
        participants: pids.map((id) => nameMap.get(id) || id),
      };
    });

    res.json(result);
  } catch (e) {
    console.error("Failed to load threads:", e);
    res.status(500).send("Failed to load threads");
  }
});

app.get("/dm/thread/:id", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.status(400).send("DMs unavailable");

  const tid = String(req.params.id);
  if (!/^\d+$/.test(tid)) return res.status(400).send("Invalid thread");

  try {
    const thread = await pgLoadThreadForUser(tid, req.session.user.id);
    return res.json(thread);
  } catch (_e) {
    return res.status(403).send("Not allowed");
  }
});

app.post("/dm/thread", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.status(400).send("DMs unavailable");

  let participants = req.body?.participants;
  if (!Array.isArray(participants)) {
    const raw = String(req.body?.participants || req.body?.participant || req.body?.user || "");
    participants = raw.split(",");
  }

  const kindRaw = String(req.body?.kind || "").trim().toLowerCase(); // "direct" | "group" | ""
  let title = String(req.body?.title || "").trim().slice(0, 80);

  const cleaned = [];
  const seen = new Set();
  for (const name of participants || []) {
    const s = sanitizeUsername(name);
    const key = normKey(s);
    if (!s || seen.has(key)) continue;
    if (key === normKey(req.session.user.username)) continue;
    seen.add(key);
    cleaned.push(s);
  }

  if (!cleaned.length) return res.status(400).send("Add at least one other user");
  if (cleaned.length > 9) return res.status(400).send("Too many participants");

  // Enforce mode rules
  if (kindRaw === "direct") {
    title = ""; // no titles for direct DMs
    if (cleaned.length !== 1) return res.status(400).send("Direct messages must have exactly 1 participant");
  }
  if (kindRaw === "group") {
    if (cleaned.length < 2 && !title) return res.status(400).send("Group chats need 2+ participants (or a title)");
  }

  fetchUsersByNames(cleaned, async (err, users) => {
    if (err) return res.status(500).send("Failed to create thread");
    if (users.length !== cleaned.length) return res.status(404).send("User not found");

    const myId = String(req.session.user.id);
    const isGroup = kindRaw === "group"
      ? true
      : (kindRaw === "direct" ? false : (users.length + 1 > 2 || !!title));

    try {
      // If it's a direct DM, reuse existing 1:1 thread (prevents duplicates)
      if (!isGroup && users.length === 1) {
        const otherId = String(users[0].id);

        const reuse = await pgPool.query(
          `
          SELECT t.id
          FROM dm_threads t
          JOIN dm_participants p1 ON p1.thread_id = t.id AND p1.user_id = $1
          JOIN dm_participants p2 ON p2.thread_id = t.id AND p2.user_id = $2
          WHERE t.is_group = FALSE
            AND (SELECT COUNT(*) FROM dm_participants dp WHERE dp.thread_id = t.id) = 2
          LIMIT 1
          `,
          [myId, otherId]
        );

        if (reuse.rows.length) {
          return res.json({ ok: true, threadId: reuse.rows[0].id, reused: true });
        }
      }

      const created = await pgPool.query(
        `INSERT INTO dm_threads (title, is_group, created_by, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id`,
        [title || null, isGroup, myId]
      );

      const threadId = String(created.rows[0].id);

      const participantIds = users.map((u) => String(u.id));
      participantIds.push(myId);

      for (const uid of participantIds) {
        await pgPool.query(
          `INSERT INTO dm_participants (thread_id, user_id, added_by, joined_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT DO NOTHING`,
          [threadId, uid, myId]
        );
      }

      const allNames = users.map((u) => u.username);
      allNames.push(req.session.user.username);

      // join sockets + notify invited users
      for (const uid of participantIds) {
        const sid = socketIdByUserId.get(uid);
        if (sid) {
          const sock = io.sockets.sockets.get(sid);
          if (sock) sock.join(`dm:${threadId}`);
          io.to(sid).emit("dm thread invited", {
            threadId,
            title,
            isGroup,
            participants: allNames,
          });
        }
      }

      return res.json({ ok: true, threadId });
    } catch (e) {
      console.error("Failed to create thread:", e);
      return res.status(500).send("Failed to create thread");
    }
  });
});

app.post("/dm/thread/:id/participants", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.status(400).send("DMs unavailable");

  const tid = String(req.params.id);
  if (!/^\d+$/.test(tid)) return res.status(400).send("Invalid thread");

  try {
    const thread = await pgLoadThreadForUser(tid, req.session.user.id);
    if (!thread.is_group) return res.status(400).send("Only group DMs can add members");

    let participants = req.body?.participants;
    if (!Array.isArray(participants)) participants = [];

    const cleaned = [];
    const seen = new Set();
    for (const name of participants || []) {
      const s = sanitizeUsername(name);
      const key = normKey(s);
      if (!s || seen.has(key)) continue;
      if (key === normKey(req.session.user.username)) continue;
      seen.add(key);
      cleaned.push(s);
    }

    if (!cleaned.length) return res.status(400).send("Pick at least one new member");

    fetchUsersByNames(cleaned, async (fetchErr, users) => {
      if (fetchErr) return res.status(500).send("Failed to add members");
      if (users.length !== cleaned.length) return res.status(404).send("User not found");

      try {
        const existing = await pgPool.query(
          `SELECT user_id FROM dm_participants WHERE thread_id = $1`,
          [tid]
        );
        const existingIds = new Set(existing.rows.map((r) => String(r.user_id)));

        const newUsers = users.filter((u) => !existingIds.has(String(u.id)));
        if (!newUsers.length) return res.status(400).send("Everyone is already in the group");

        const myId = String(req.session.user.id);

        for (const u of newUsers) {
          const uid = String(u.id);
          await pgPool.query(
            `INSERT INTO dm_participants (thread_id, user_id, added_by, joined_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT DO NOTHING`,
            [tid, uid, myId]
          );

          const sid = socketIdByUserId.get(uid);
          if (sid) {
            const sock = io.sockets.sockets.get(sid);
            if (sock) sock.join(`dm:${tid}`);
            io.to(sid).emit("dm thread invited", {
              threadId: tid,
              title: thread.title || null,
              isGroup: true,
              participants: thread.participants,
            });
          }
        }

        const fresh = await pgLoadThreadForUser(tid, req.session.user.id);
        return res.json({ ok: true, participants: fresh.participants });
      } catch (e) {
        console.error("Failed to add members:", e);
        return res.status(500).send("Failed to add members");
      }
    });
  } catch (_e) {
    return res.status(403).send("Not allowed");
  }
});

app.post("/dm/thread/:id/leave", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.status(400).send("DMs unavailable");

  const tid = String(req.params.id);
  if (!/^\d+$/.test(tid)) return res.status(400).send("Invalid thread");

  try {
    const thread = await pgLoadThreadForUser(tid, req.session.user.id);
    if (!thread.is_group) return res.status(400).send("Leaving only available in group chats");

    await pgPool.query(
      `DELETE FROM dm_participants WHERE thread_id = $1 AND user_id = $2`,
      [tid, String(req.session.user.id)]
    );

    return res.json({ ok: true });
  } catch (_e) {
    return res.status(403).send("Not allowed");
  }
});

app.delete("/dm/thread/:id/messages", requireLogin, async (req, res) => {
  if (!PG_ENABLED) return res.status(400).send("DMs unavailable");

  const tid = String(req.params.id);
  if (!/^\d+$/.test(tid)) return res.status(400).send("Invalid thread");

  try {
    await pgLoadThreadForUser(tid, req.session.user.id);

    await pgPool.query(`DELETE FROM dm_messages WHERE thread_id = $1`, [tid]);

    io.to(`dm:${tid}`).emit("dm history cleared", { threadId: tid });
    return res.json({ ok: true });
  } catch (_e) {
    return res.status(403).send("Not allowed");
  }
});
// ------------------ end DMs (Postgres-backed) ------------------

setInterval(() => {
  const now = Date.now();
  for (const [uid, track] of onlineXpTrack.entries()) {
    if (!onlineState.has(uid)) {
      onlineXpTrack.delete(uid);
      continue;
    }
    const lastTs = track.lastTs || now;
    const elapsed = Math.max(0, now - lastTs);
    const total = (track.carryMs || 0) + elapsed;
    const gains = Math.floor(total / 100_000);
    const remainder = total % 100_000;
    onlineXpTrack.set(uid, { lastTs: now, carryMs: remainder });
    if (gains > 0) applyXpGain(uid, gains);
  }

  for (const uid of onlineState.keys()) {
    awardPassiveGold(uid);
  }
}, 60_000);

// ---- Helpers for punishments
function isPunished(userId, type, cb) {
  const now = Date.now();
  db.get(
    `SELECT * FROM punishments
     WHERE user_id = ? AND type = ?
     AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY created_at DESC LIMIT 1`,
    [userId, type, now],
    (_e, row) => cb(!!row, row || null)
  );
}

// ---- Socket auth middleware (session)
io.use((socket, next) => {
  const fakeRes = socket.request.res || {
    getHeader: () => undefined,
    setHeader: () => {},
    writeHead: () => {},
  };
  sessionMiddleware(socket.request, fakeRes, () => {
    if (!socket.request.session?.user?.id) {
      return next(new Error("Not authenticated"));
    }
    next();
  });
});

function broadcastTyping(room) {
  const set = typingByRoom.get(room);
  const names = set ? Array.from(set) : [];
  io.to(room).emit("typing update", names);
}

function emitUserList(room) {
  // Build list from sockets in room
  const users = [];
  const sids = io.sockets.adapter.rooms.get(room);
  if (sids) {
    for (const sid of sids) {
      const s = io.sockets.sockets.get(sid);
      if (!s?.user) continue;
      const status = normalizeStatus(s.user.status, "Online");
      users.push({
        name: s.user.username,
        role: s.user.role,
        status,
        mood: s.user.mood || "",
        avatar: s.user.avatar || "",
      });
    }
  }

  // Sort by role then name
  const lurkWeight = (status) => normalizeStatus(status, "Online") === "Lurking" ? 1 : 0;
  users.sort((a, b) => {
    const lb = lurkWeight(a.status) - lurkWeight(b.status);
    if (lb !== 0) return lb;
    const ra = roleRank(a.role);
    const rb = roleRank(b.role);
    if (ra !== rb) return rb - ra;
    return a.name.localeCompare(b.name);
  });

  io.to(room).emit("user list", users);
}

// ---- Socket handlers
io.on("connection", async (socket) => {
  const sessUser = socket.request.session?.user;
  if (!sessUser?.id) {
    socket.disconnect(true);
    return;
  }

  socket.user = {
    id: sessUser.id,
    username: sessUser.username,
    role: sessUser.role,
    status: "Online",
    mood: "",
    avatar: "",
  };

  socketIdByUserId.set(socket.user.id, socket.id);
  onlineXpTrack.set(socket.user.id, { lastTs: Date.now(), carryMs: 0 });
  initGoldTick(socket.user.id);

  // Load profile bits for presence
  db.get(
    "SELECT avatar, mood FROM users WHERE id = ?",
    [socket.user.id],
    (_e, row) => {
      if (row) {
        socket.user.avatar = row.avatar || "";
        socket.user.mood = row.mood || "";
      }
    }
  );

  socket.currentRoom = null;
    // --- SAFETY: ensure user is always in a room so messages can appear
  // If client fails to emit "join room" (mobile / reconnect / race), auto-join main.
  setTimeout(() => {
    if (!socket.currentRoom) {
      try {
        doJoin("main", socket.user.status || "Online");
      } catch (e) {
        console.warn("[auto-join main] failed:", e?.message || e);
      }
    }
  }, 500);
  socket.dmThreads = new Set();

 if (USE_PG) {
  try {
    const uid = String(socket.user.id);

    const rows = await pgPool.query(
      `
      SELECT id
      FROM dm_threads
      WHERE user1 = $1 OR user2 = $1
      `,
      [uid]
    );

    for (const r of rows.rows) {
      const tid = String(r.id);
      socket.dmThreads.add(tid);
      socket.join(`dm:${tid}`);
    }
  } catch (e) {
    console.warn("[dm auto-join] failed:", e?.message || e);
    }
  }
});
socket.on("join room", ({ room, status }) => {
  const desired = sanitizeRoomName(room) || "main";

  db.get(`SELECT name FROM rooms WHERE name=?`, [desired], (_err, row) => {
    const finalRoom = row ? desired : "main";
    doJoin(finalRoom, status);
  });
});

  // Dice Room mini-game
  socket.on("dice:roll", () => {
    const room = socket.currentRoom;
    if (room !== "diceroom") {
      socket.emit("dice:error", "You can only roll dice in Dice Room.");
      return;
    }

    const now = Date.now();
    const uid = socket.user.id;

    (async () => {
      try {
        if (await pgUserExists(uid)) {
          const row = await pgGetUserRowById(uid, ["gold", "lastDiceRollAt"]);
          if (!row) {
            socket.emit("dice:error", "Could not roll dice right now.");
            return;
          }

          const last = Number(row.lastDiceRollAt || 0);
          if (now - last < 2000) {
            socket.emit("dice:error", `Slow down! Try again in ${Math.ceil((2000 - (now - last)) / 100) / 10}s.`);
            return;
          }

          const gold = Number(row.gold || 0);
          if (gold < 50) {
            socket.emit("dice:error", "You need at least 50 Gold to roll.");
            return;
          }

          const value = Math.floor(Math.random() * 6) + 1; // 1..6
          const won = value === 6;
          const deltaGold = won ? 500 : -50;
          const sixGain = won ? 1 : 0;

          await pgPool.query(
            `UPDATE users
               SET gold = GREATEST(0, gold + $1),
                   lastDiceRollAt = $2,
                   dice_sixes = dice_sixes + $3
             WHERE id = $4`,
            [deltaGold, now, sixGain, uid]
          );

          socket.emit("dice:result", { value, won, deltaGold });
          emitProgressionUpdate(uid);

          const faces = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
          const face = faces[value - 1] || value;
          const msg = won
            ? `${socket.user.username} rolled ${face} 🎉 (+500 Gold!)`
            : `${socket.user.username} rolled ${face} 🎲 (-50 Gold!)`;
          io.to(room).emit("system", msg);

          io.to(room).emit("dice:rolled", { userId: uid, username: socket.user.username, value, won });
          return;
        }
      } catch (e) {
        console.warn("[dice][pg] failed, falling back to sqlite:", e?.message || e);
      }

      // SQLite fallback (original behavior)
      db.get(`SELECT gold, lastDiceRollAt FROM users WHERE id=?`, [uid], (err, row) => {
        if (err || !row) {
          socket.emit("dice:error", "Could not roll dice right now.");
          return;
        }

        const last = Number(row.lastDiceRollAt || 0);
        if (now - last < 2000) {
          socket.emit("dice:error", `Slow down! Try again in ${Math.ceil((2000 - (now - last)) / 100) / 10}s.`);
          return;
        }

        const gold = Number(row.gold || 0);
        if (gold < 50) {
          socket.emit("dice:error", "You need at least 50 Gold to roll.");
          return;
        }

        const value = Math.floor(Math.random() * 6) + 1; // 1..6
        const won = value === 6;
        const deltaGold = won ? 500 : -50;
        const sixGain = won ? 1 : 0;

        db.run(
          `UPDATE users SET gold = MAX(0, gold + ?), lastDiceRollAt=?, dice_sixes = dice_sixes + ? WHERE id=?`,
          [deltaGold, now, sixGain, uid],
          (uerr) => {
            if (uerr) {
              socket.emit("dice:error", "Could not apply dice result.");
              return;
            }

            socket.emit("dice:result", { value, won, deltaGold });
            emitProgressionUpdate(uid);

            const faces = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
            const face = faces[value - 1] || value;
            const msg = won
              ? `${socket.user.username} rolled ${face} 🎉 (+500 Gold!)`
              : `${socket.user.username} rolled ${face} 🎲 (-50 Gold!)`;
            io.to(room).emit("system", msg);

            io.to(room).emit("dice:rolled", { userId: uid, username: socket.user.username, value, won });
          }
        );
      });
    })();
  });

function doJoin(room, status) {
  // leave old room
  if (socket.currentRoom) {
    socket.leave(socket.currentRoom);
    const old = socket.currentRoom;
    socket.currentRoom = null;

    const set = typingByRoom.get(old);
    if (set) {
      set.delete(socket.user.username);
      broadcastTyping(old);
    }

    emitUserList(old);
  }

  socket.currentRoom = room;
  socket.join(room);

  socket.user.status = normalizeStatus(status || socket.user.status, "Online");

  onlineState.set(socket.user.id, { room, status: socket.user.status });
  onlineXpTrack.set(socket.user.id, { lastTs: Date.now(), carryMs: 0 });
  awardPassiveGold(socket.user.id);

  db.run("UPDATE users SET last_room=?, last_status=? WHERE id=?", [
    room,
    socket.user.status,
    socket.user.id,
  ]);

  // Send history (exclude deleted messages entirely)
  // Backward-compatible room history: older builds stored rooms with a leading '#'.
  const legacyRoom = `#${room}`;
  db.all(
    `SELECT id, room, username, role, avatar, text, ts, attachment_url, attachment_type, attachment_mime, attachment_size,
            reply_to_id, reply_to_user, reply_to_text
     FROM messages
     WHERE (room=? OR room=?) AND deleted=0
     ORDER BY ts ASC LIMIT 200`,
    [room, legacyRoom],
    (_e, rows) => {
      const history = (rows || []).map((r) => ({
        messageId: r.id,
        room: r.room,
        user: r.username,
        role: r.role,
        avatar: r.avatar || "",
        text: (r.text || ""),
        ts: r.ts,
        attachmentUrl: r.attachment_url || "",
        attachmentType: r.attachment_type || "",
        attachmentMime: r.attachment_mime || "",
        attachmentSize: r.attachment_size || 0,
        replyToId: r.reply_to_id || null,
        replyToUser: r.reply_to_user || "",
        replyToText: r.reply_to_text || "",
      }));
      socket.emit("history", history);

      const ids = history.map((m) => m.messageId).slice(-80);
      if (ids.length) {
        const placeholders = ids.map(() => "?").join(",");
        db.all(
          `SELECT message_id, username, emoji FROM reactions WHERE message_id IN (${placeholders})`,
          ids,
          (_e2, reacts) => {
            const byMsg = {};
            for (const r of reacts || []) {
              byMsg[r.message_id] = byMsg[r.message_id] || {};
              byMsg[r.message_id][r.username] = r.emoji;
            }
            for (const mid of Object.keys(byMsg)) {
              socket.emit("reaction update", { messageId: mid, reactions: byMsg[mid] });
            }
          }
        );
      }
    }
  );

  socket.emit("system", `Joined ${room}`);
  emitUserList(room);
}

  socket.on("typing", () => {
    let room = socket.currentRoom;
if (!room) {
  // fallback: join main so the message shows up instead of disappearing
  try { doJoin("main", socket.user.status || "Online"); } catch {}
  room = socket.currentRoom;
  if (!room) return;
}
    let set = typingByRoom.get(room);
    if (!set) typingByRoom.set(room, (set = new Set()));
    set.add(socket.user.username);
    broadcastTyping(room);
  });

  socket.on("stop typing", () => {
    const room = socket.currentRoom;
    if (!room) return;

    const set = typingByRoom.get(room);
    if (set) {
      set.delete(socket.user.username);
      broadcastTyping(room);
    }
  });

  

socket.on("dm join", async ({ threadId }) => {
  if (!PG_ENABLED) return;
  const tid = String(threadId);
  if (!/^\d+$/.test(tid)) return;

  const uid = String(socket.user.id);

  try {
    const ok = await pgPool.query(
      `SELECT 1 FROM dm_participants WHERE thread_id = $1 AND user_id = $2`,
      [tid, uid]
    );
    if (!ok.rows.length) return;

    socket.dmThreads.add(tid);
    socket.join(`dm:${tid}`);

    const threadQ = await pgPool.query(
      `SELECT id, title, is_group, created_at, created_by FROM dm_threads WHERE id = $1`,
      [tid]
    );
    if (!threadQ.rows.length) return;

    const partsQ = await pgPool.query(
      `SELECT user_id FROM dm_participants WHERE thread_id = $1`,
      [tid]
    );
    const pids = partsQ.rows.map((r) => String(r.user_id));
    const nameMap = await sqliteUsernamesForIds(pids);
    const participants = pids.map((id) => nameMap.get(id) || id);

    const msgsQ = await pgPool.query(
      `SELECT id, thread_id, sender_id, text, ts, reply_to_id, reply_to_user, reply_to_text
       FROM dm_messages
       WHERE thread_id = $1
       ORDER BY ts DESC
       LIMIT 50`,
      [tid]
    );

    const msgs = (msgsQ.rows || []).reverse().map((r) => ({
      messageId: Number(r.id),
      id: Number(r.id),
      threadId: String(r.thread_id),
      userId: String(r.sender_id),
      user: nameMap.get(String(r.sender_id)) || String(r.sender_id),
      text: r.text,
      ts: Number(r.ts),
      replyToId: r.reply_to_id ? Number(r.reply_to_id) : null,
      replyToUser: r.reply_to_user || "",
      replyToText: r.reply_to_text || "",
    }));

    socket.emit("dm history", {
      threadId: tid,
      title: threadQ.rows[0].title || "",
      isGroup: !!threadQ.rows[0].is_group,
      participants,
      messages: msgs,
    });
  } catch (e) {
    console.warn("[dm join] failed:", e?.message || e);
  }
});


  
socket.on("dm message", async ({ threadId, text, replyToId }) => {
  if (!PG_ENABLED) return;

  const tid = String(threadId);
  const body = String(text || "").trim().slice(0, 800);
  if (!/^\d+$/.test(tid) || !body) return;

  const uid = String(socket.user.id);

  try {
    const ok = await pgPool.query(
      `SELECT 1 FROM dm_participants WHERE thread_id = $1 AND user_id = $2`,
      [tid, uid]
    );
    if (!ok.rows.length) return;

    // Reply metadata (optional)
    let replyMeta = { reply_to_id: null, reply_to_user: "", reply_to_text: "" };
    const rid = Number(replyToId);
    if (Number.isFinite(rid)) {
      const rq = await pgPool.query(
        `SELECT id, sender_id, text
         FROM dm_messages
         WHERE id = $1 AND thread_id = $2
         LIMIT 1`,
        [String(rid), tid]
      );
      if (rq.rows.length) {
        const r = rq.rows[0];
        const nameMap = await sqliteUsernamesForIds([String(r.sender_id)]);
        replyMeta = {
          reply_to_id: Number(r.id),
          reply_to_user: nameMap.get(String(r.sender_id)) || String(r.sender_id),
          reply_to_text: String(r.text || "").slice(0, 200),
        };
      }
    }

    const ts = Date.now();
    const ins = await pgPool.query(
      `INSERT INTO dm_messages (thread_id, sender_id, text, ts, reply_to_id, reply_to_user, reply_to_text, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING id, thread_id, sender_id, text, ts, reply_to_id, reply_to_user, reply_to_text`,
      [
        tid,
        uid,
        body,
        ts,
        replyMeta.reply_to_id ? String(replyMeta.reply_to_id) : null,
        replyMeta.reply_to_user || "",
        replyMeta.reply_to_text || "",
      ]
    );

    const row = ins.rows[0];
    const senderNameMap = await sqliteUsernamesForIds([uid]);

    const payload = {
      messageId: Number(row.id),
      id: Number(row.id),
      threadId: String(row.thread_id),
      userId: String(row.sender_id),
      user: senderNameMap.get(uid) || uid,
      text: row.text,
      ts: Number(row.ts),
      replyToId: row.reply_to_id ? Number(row.reply_to_id) : null,
      replyToUser: row.reply_to_user || "",
      replyToText: row.reply_to_text || "",
    };

    io.to(`dm:${tid}`).emit("dm message", payload);
  } catch (e) {
    console.warn("[dm message] failed:", e?.message || e);
  }
});
  });

  socket.on("status change", ({ status }) => {
    status = normalizeStatus(status, "Online");
    socket.user.status = status;

    const st = onlineState.get(socket.user.id);
    if (st) st.status = status;

    db.run("UPDATE users SET last_status=? WHERE id=?", [status, socket.user.id]);

    if (socket.currentRoom) emitUserList(socket.currentRoom);
  });

  socket.on("chat message", (payload) => {
    // If a client sends before it has joined a room (mobile reconnect/race),
    // auto-join main so the message doesn't silently disappear.
    let room = socket.currentRoom;
    if (!room) {
      try {
        doJoin("main", socket.user.status || "Online");
      } catch (_) {}
      room = socket.currentRoom;
      if (!room) return;
    }

    // basic spam rate limiting
    const now = Date.now();
    const r = msgRate.get(socket.id) || { lastTs: now, count: 0 };
    if (now - r.lastTs > 4000) {
      r.lastTs = now;
      r.count = 0;
    }
    r.count++;
    msgRate.set(socket.id, r);
    if (r.count > 10) return;

    isPunished(socket.user.id, "ban", (banned) => {
      if (banned) return;
      isPunished(socket.user.id, "mute", (muted) => {
        if (muted) return;

        const text = String(payload?.text || "").slice(0, 800);
        if (text.trim().startsWith("/")) {
          executeCommand(socket, text, room);
          return;
        }
        const attachmentUrl = String(payload?.attachmentUrl || "").slice(0, 400);
        const attachmentType = String(payload?.attachmentType || "").slice(0, 20);
        const attachmentMime = String(payload?.attachmentMime || "").slice(0, 60);
        const attachmentSize = Number(payload?.attachmentSize || 0) || 0;

        awardPassiveGold(socket.user.id);

        // maintenance / lock / slowmode enforcement
        if (maintenanceState.enabled && !requireMinRole(socket.user.role, "Moderator")) {
          socket.emit("command response", { ok: false, message: "Site is in maintenance mode" });
          return;
        }

        db.get(
          `SELECT slowmode_seconds, is_locked FROM rooms WHERE name=?`,
          [room],
          (_err, settings) => {
            const slowSeconds = Number(settings?.slowmode_seconds || 0);
            const locked = Number(settings?.is_locked || 0) === 1;
            if (locked && !requireMinRole(socket.user.role, "Moderator")) {
              socket.emit("command response", { ok: false, message: "Room is locked" });
              return;
            }
            if (slowSeconds > 0 && !requireMinRole(socket.user.role, "Moderator")) {
              const key = `${room}:${socket.user.id}`;
              const last = slowmodeTracker.get(key) || 0;
              if (Date.now() - last < slowSeconds * 1000) {
                socket.emit("command response", { ok: false, message: `Slowmode: wait ${Math.ceil((slowSeconds * 1000 - (Date.now() - last)) / 1000)}s` });
                return;
              }
              slowmodeTracker.set(key, Date.now());
            }

            const replyId = Number(payload?.replyToId);
            const insertWithReply = (replyMeta = {}) => {
              const replyPk = Number.isInteger(replyMeta.id) ? replyMeta.id : null;
              const replyUser = replyMeta.username || replyMeta.user || null;
              const replyText = replyMeta.text || null;
              const tsNow = Date.now();

              db.run(
                `INSERT INTO messages (room, user_id, username, role, avatar, text, ts, attachment_url, attachment_type, attachment_mime, attachment_size, reply_to_id, reply_to_user, reply_to_text)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  room,
                  socket.user.id,
                  socket.user.username,
                  socket.user.role,
                  socket.user.avatar || "",
                  text,
                  tsNow,
                  attachmentUrl || null,
                  attachmentType || null,
                  attachmentMime || null,
                  attachmentSize || null,
                  replyPk,
                  replyUser,
                  replyText,
                ],
                function () {
                  awardMessageXp(socket.user.id);
                  awardMessageGold(socket.user.id);
                  const msg = {
                    messageId: this.lastID,
                    room,
                    user: socket.user.username,
                    role: socket.user.role,
                    avatar: socket.user.avatar || "",
                    text,
                    ts: tsNow,
                    attachmentUrl: attachmentUrl || "",
                    attachmentType: attachmentType || "",
                    attachmentMime: attachmentMime || "",
                    attachmentSize: attachmentSize || 0,
                    replyToId: replyPk,
                    replyToUser: replyUser || "",
                    replyToText: replyText || "",
                  };
                  io.to(room).emit("chat message", msg);
                }
              );
            };

            if (Number.isInteger(replyId)) {
              db.get(
                `SELECT id, username, text FROM messages WHERE id=? AND room=? AND deleted=0`,
                [replyId, room],
                (_rErr, row) => insertWithReply(row || {})
              );
            } else {
              insertWithReply();
            }
          }
        );
      });
    });
  });

  // Reactions: 1 reaction per user per message (enforced by PRIMARY KEY)
  socket.on("reaction", ({ messageId, emoji }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const mid = String(messageId || "").trim();
    const em = String(emoji || "").slice(0, 8);
    if (!mid || !em) return;

    db.run(
      `INSERT INTO reactions (message_id, username, emoji)
       VALUES (?, ?, ?)
       ON CONFLICT(message_id, username) DO UPDATE SET emoji=excluded.emoji`,
      [mid, socket.user.username, em],
      () => {
        db.all("SELECT username, emoji FROM reactions WHERE message_id=?", [mid], (_e, rows) => {
          const reactions = {};
          for (const r of rows || []) reactions[r.username] = r.emoji;
          io.to(room).emit("reaction update", { messageId: mid, reactions });
        });
      }
    );
  });

  // ---- Moderation: delete message
  socket.on("mod delete message", ({ messageId }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    const mid = String(messageId || "").trim();
    if (!mid) return;

    db.get(
      "SELECT * FROM messages WHERE id=? AND room=?",
      [mid, room],
      (_e, msg) => {
        if (!msg) return;
        // cannot delete higher/equal role messages unless it's your own
        if (!canModerate(actorRole, msg.role) && msg.user_id !== socket.user.id) return;

        db.run("UPDATE messages SET deleted=1 WHERE id=?", [mid], () => {
          io.to(room).emit("message deleted", { messageId: mid });
          logModAction({
            actor: socket.user,
            action: "DELETE_MESSAGE",
            targetUserId: msg.user_id,
            targetUsername: msg.username,
            room,
            details: `messageId=${mid}`,
          });
        });
      }
    );
  });

  // ---- Kick / Mute / Ban + Unmute/Unban/Warn + Set role
  socket.on("mod kick", ({ username }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);
    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

      io.to(room).emit("system", `${username} was kicked.`);
      logModAction({ actor: socket.user, action: "KICK", targetUserId: target.id, targetUsername: username, room });
    });
  });

  socket.on("mod mute", ({ username, minutes = 10, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);
    const mins = clamp(minutes, 1, 1440);
    const expiresAt = Date.now() + mins * 60 * 1000;

    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at)
         VALUES (?, 'mute', ?, ?, ?, ?)`,
        [target.id, expiresAt, String(reason || "").slice(0, 180), socket.user.id, Date.now()],
        () => {
          io.to(room).emit("system", `${username} was muted for ${mins} minutes.`);
          logModAction({
            actor: socket.user,
            action: "MUTE",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: `minutes=${mins} reason=${String(reason || "").slice(0, 180)}`,
          });
        }
      );
    });
  });

  socket.on("mod ban", ({ username, minutes = 0, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return;

    username = sanitizeUsername(username);
    const mins = Number(minutes);
    const expiresAt = Number.isFinite(mins) && mins > 0 ? Date.now() + mins * 60 * 1000 : null;

    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at)
         VALUES (?, 'ban', ?, ?, ?, ?)`,
        [target.id, expiresAt, String(reason || "").slice(0, 180), socket.user.id, Date.now()],
        () => {
          io.to(room).emit(
            "system",
            `${username} was banned${expiresAt ? ` for ${mins} minutes` : " permanently"}.`
          );
          const sid = socketIdByUserId.get(target.id);
          if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

          logModAction({
            actor: socket.user,
            action: "BAN",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: expiresAt ? `minutes=${mins}` : `permanent reason=${String(reason || "").slice(0, 180)}`,
          });
        }
      );
    });
  });

  socket.on("mod unmute", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);
    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run("DELETE FROM punishments WHERE user_id=? AND type='mute'", [target.id], () => {
        io.to(room).emit("system", `${username} was unmuted.`);
        logModAction({
          actor: socket.user,
          action: "UNMUTE",
          targetUserId: target.id,
          targetUsername: username,
          room,
          details: String(reason || "").slice(0, 180),
        });
      });
    });
  });

  socket.on("mod unban", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return;

    username = sanitizeUsername(username);
    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run("DELETE FROM punishments WHERE user_id=? AND type='ban'", [target.id], () => {
        io.to(room).emit("system", `${username} was unbanned.`);
        logModAction({
          actor: socket.user,
          action: "UNBAN",
          targetUserId: target.id,
          targetUsername: username,
          room,
          details: String(reason || "").slice(0, 180),
        });
      });
    });
  });

  socket.on("mod warn", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);
    db.get("SELECT id, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      io.to(room).emit("system", `${username} was warned: ${String(reason || "").slice(0, 120)}`);
      logModAction({
        actor: socket.user,
        action: "WARN",
        targetUserId: target.id,
        targetUsername: username,
        room,
        details: String(reason || "").slice(0, 180),
      });
    });
  });

  socket.on("mod set role", ({ username, role, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (actorRole !== "Owner") return;

    username = sanitizeUsername(username);
    role = String(role || "").trim();
    if (!ROLES.includes(role)) return;

    db.get("SELECT id, role as oldRole FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;

      // don't allow lowering Owner unless it's yourself (simple safety)
      if (target.oldRole === "Owner" && target.id !== socket.user.id) return;

      db.run("UPDATE users SET role=? WHERE id=?", [role, target.id], () => {
        logModAction({
          actor: socket.user,
          action: "SET_ROLE",
          targetUserId: target.id,
          targetUsername: username,
          room,
          details: `role=${role} reason=${String(reason || "").slice(0, 180)}`,
        });

        // if user is online, update session-ish info
        const sid = socketIdByUserId.get(target.id);
        if (sid) {
          const s = io.sockets.sockets.get(sid);
          if (s?.request?.session?.user) {
            s.request.session.user.role = role;
            s.user.role = role;
          }
        }

        io.to(room).emit("system", `${username} role set to ${role}.`);
        emitUserList(room);
      });
    });
  });

  socket.on("disconnect", () => {
    const room = socket.currentRoom;

    socketIdByUserId.delete(socket.user.id);
    onlineState.delete(socket.user.id);
    msgRate.delete(socket.id);
    onlineXpTrack.delete(socket.user.id);
    initGoldTick(socket.user.id);

    db.run("UPDATE users SET last_seen=? WHERE id=?", [Date.now(), socket.user.id]);

    if (room) {
      const set = typingByRoom.get(room);
      if (set) {
        set.delete(socket.user.username);
        broadcastTyping(room);
      }
      emitUserList(room);
    }
  });

// ---- Start
pgInitPromise.finally(() => {
  server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});
