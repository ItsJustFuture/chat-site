//

// Update a user's role in SQLite (legacy) and Postgres (Render/prod) when available.
async function setRoleEverywhere(targetId, username, role) {
  // SQLite
  try {
    if (targetId != null) {
      await dbRunAsync("UPDATE users SET role=? WHERE id=?", [role, targetId]);
    } else if (username) {
      await dbRunAsync("UPDATE users SET role=? WHERE lower(username)=lower(?)", [role, username]);
    }
  } catch {}

  // Postgres
  try {
    if (targetId != null) {
      await pgPool.query("UPDATE users SET role=$1 WHERE id=$2", [role, targetId]);
    } else if (username) {
      await pgPool.query("UPDATE users SET role=$1 WHERE lower(username)=lower($2)", [role, username]);
    }
  } catch {}
}
"use strict";

// === Iris & Lola private theme config ===
const PRIVATE_THEME_ALLOWLIST = {
  "Iris & Lola Neon": {
    users: ["Iri", "Lola Henderson"],
    requireBothOnline: false
  }
};

const ONLINE_USERS = new Set();



const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const multer = require("multer");
const { Pool } = require("pg");
const http = require("http");

// ---- Safety nets (prevents silent crashes in prod) ----
process.on("unhandledRejection", (err) => {
  console.error("[unhandledRejection]", err);
});
process.on("uncaughtException", (err) => {
  console.error("[uncaughtException]", err);
});
const { Server } = require("socket.io");
const { db, migrationsReady } = require("./database");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(__dirname, "uploads");

// ---- Startup sanity checks (fail fast in production)
const IS_PROD = process.env.NODE_ENV === "production";
if (IS_PROD) {
  if (!process.env.SESSION_SECRET || String(process.env.SESSION_SECRET).trim().length < 16) {
    console.error("FATAL: SESSION_SECRET is missing/too short. Set a strong secret in your environment.");
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error("FATAL: DATABASE_URL is missing. Set your Postgres connection string in your environment.");
    process.exit(1);
  }
}

const AVATARS_DIR = path.join(__dirname, "avatars");

// ---- Ensure folders exist
for (const dir of [UPLOADS_DIR, AVATARS_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---- App + Server
  const app = express();
  const httpServer = http.createServer(app);
  const io = new Server(httpServer, {
    // Render uses HTTPS -> allow websocket upgrade
    cors: { origin: true, credentials: true },

    // More tolerant of mobile/background + Render sleep
    pingInterval: 30_000,  // send pings every 30s
    pingTimeout: 120_000,  // wait 120s for pong before disconnect
    upgradeTimeout: 30_000,
  });
  const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});// ---- Postgres: helpers to keep legacy schemas compatible
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
async function pgEnsureCamelColumn(tableName, camelName, typeSql = "BIGINT") {
  // If exact camelCase column already exists, we're good
  const exact = await pgGetColumnType(tableName, camelName);
  if (exact) return;

  // If a lowercased version exists (created without quotes), rename it to the camelCase quoted form
  const lower = camelName.toLowerCase();
  const lowerInfo = await pgGetColumnType(tableName, lower);
  if (lowerInfo) {
    // Postgres lowercases unquoted identifiers; rename the legacy column to a quoted camelCase name.
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
let PG_READY = false;
let PG_INIT_ERROR = null;
// ---- Postgres table setup
// Run once on boot, and start the server only after this finishes (so schema/type fixes apply before /register).
const pgInitPromise = (async () => {
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
        prefs_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        gold INTEGER NOT NULL DEFAULT 0,
        xp INTEGER NOT NULL DEFAULT 0,
        lastXpMessageAt BIGINT,
        lastDailyLoginAt BIGINT,
        lastGoldTickAt BIGINT,
        lastMessageGoldAt BIGINT,
        lastDailyLoginGoldAt BIGINT,
        lastDiceRollAt BIGINT,
        dice_sixes INTEGER NOT NULL DEFAULT 0,
        vibe_tags JSONB NOT NULL DEFAULT '[]'::jsonb
      );

      CREATE TABLE IF NOT EXISTS session (
        sid TEXT PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP NOT NULL
      );
    `);

    // Changelog tables (Postgres) — ensures changelog persists across restarts
    await pgPool.query(`
      CREATE SEQUENCE IF NOT EXISTS changelog_seq;
      CREATE TABLE IF NOT EXISTS changelog_entries (
        id SERIAL PRIMARY KEY,
        seq BIGINT UNIQUE NOT NULL DEFAULT nextval('changelog_seq'),
        title TEXT NOT NULL,
        body TEXT,
        created_at BIGINT,
        updated_at BIGINT,
        author_id INTEGER REFERENCES users(id) ON DELETE SET NULL
      );
    `);
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
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS prefs_json JSONB NOT NULL DEFAULT '{}'::jsonb`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS gold INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastXpMessageAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastGoldTickAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastMessageGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDiceRollAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS dice_sixes INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vibe_tags JSONB NOT NULL DEFAULT '[]'::jsonb`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS header_grad_a TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS header_grad_b TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_bytes BYTEA`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_mime TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_updated BIGINT`,
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
      "avatar_updated",
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

    PG_READY = true;
    PG_INIT_ERROR = null;
    console.log("Postgres tables ready");
  } catch (err) {
    PG_READY = false;
    PG_INIT_ERROR = err;
    console.error("Postgres init error:", err);
    throw err;
  }
})();
// IMPORTANT for Render/any reverse proxy so secure cookies work
app.set("trust proxy", 1);
// ---- DB
async function pgUserExists(userId) {
  const { rows } = await pgPool.query("SELECT 1 FROM users WHERE id=$1 LIMIT 1", [userId]);
  return !!rows[0];
}

// ---- Security + parsing
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

// IMPORTANT: CSP that blocks inline JS (good), but allows our external /public/app.js & /public/styles.css
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://www.youtube.com https://www.youtube-nocookie.com https://s.ytimg.com",
      "script-src-elem 'self' 'unsafe-eval' 'unsafe-inline' https://www.youtube.com https://www.youtube-nocookie.com https://s.ytimg.com",
      // Inline style attributes are set by the client JS (e.g. show/hide panels),
      // so allow them alongside our external stylesheet.
      "style-src 'self' 'unsafe-inline'",
      // allow avatars/uploads + blob previews on client
      "img-src 'self' data: blob: https://i.ytimg.com",
      "media-src 'self' blob:",
      // socket.io
      "connect-src 'self' ws: wss: https://noembed.com",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  next();
});

// ---- Sessions (Postgres-backed; survives redeploys)
const sessionMiddleware = session({
  store: new PgSession({
    pool: pgPool,
    tableName: "session",
    // Prevent cold-start / deploy races where the session table isn't ready yet.
    // connect-pg-simple will create it on demand if missing.
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
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

// ---- Static
app.use("/uploads", express.static(UPLOADS_DIR));
app.use("/avatars", express.static(AVATARS_DIR));
app.use(express.static(PUBLIC_DIR));

// Serve avatars stored in Postgres
app.get("/avatar/:id", async (req, res) => {
  const id = Number(req.params?.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).send("Invalid id");

  try {
    const { rows } = await pgPool.query(
      `SELECT avatar_bytes, avatar_mime, avatar_updated FROM users WHERE id = $1 LIMIT 1`,
      [id]
    );
    const row = rows?.[0];
    if (!row?.avatar_bytes) return res.status(404).send("Not found");

    const etag = `"av-${id}-${Number(row.avatar_updated || 0)}"`;
    const weakEtag = `W/${etag}`;
    const inm = String(req.headers["if-none-match"] || "");
    if (inm === etag || inm === weakEtag) return res.status(304).end();

    res.setHeader("Content-Type", row.avatar_mime || "image/png");
    res.setHeader("Cache-Control", "public, max-age=86400");
    res.setHeader("ETag", etag);
    return res.send(row.avatar_bytes);
  } catch (e) {
    console.error("[/avatar] failed:", e?.message || e);
    return res.status(500).send("Failed to load avatar");
  }
});

// ---- Helpers
function normalizeUsername(u) {
  return String(u || "").trim();
}
function cleanUsernameForLookup(u) {
  // Lookup-friendly normalization that won't break emoji/symbol usernames.
  u = normalizeUsername(u);
  // Remove ASCII control chars only (keeps emojis / unicode).
  u = u.replace(/[\u0000-\u001F\u007F]/g, "");
  // Collapse whitespace
  u = u.replace(/\s+/g, " ").trim();
  return u.slice(0, 64);
}
function normKey(u) {
  return normalizeUsername(u).toLowerCase();
}
function sanitizeUsername(u) {
  // Registration-safe: normalize without unicode property escapes (older Node safe).
  u = normalizeUsername(u);
  u = u.replace(/[\u0000-\u001F\u007F]/g, "");
  u = u.replace(/\s+/g, " ").trim();
  // Keep it short for UI/DB consistency
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

const VIBE_TAG_OPTIONS = [
  "Chill", "Chaotic", "Night Owl", "Cozy", "Loud", "Quiet", "Curious", "Unhinged", "Friendly", "Competitive"
];

const HEX_COLOR_RE = /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

function sanitizeVibeTags(raw) {
  const arr = Array.isArray(raw)
    ? raw
    : (typeof raw === "string"
      ? (() => { try { return JSON.parse(raw); } catch { return []; } })()
      : []);

  const out = [];
  for (const v of arr) {
    if (out.length >= 3) break;
    const val = String(v || "").trim();
    if (!val) continue;
    const hit = VIBE_TAG_OPTIONS.find((opt) => opt.toLowerCase() === val.toLowerCase());
    if (hit && !out.includes(hit)) out.push(hit);
  }
  return out;
}
function sanitizeHexColor(raw){
  const c = String(raw || "").trim();
  if(!c) return null;
  return HEX_COLOR_RE.test(c) ? c : null;
}
function avatarUrlFromRow(row) {
  if (!row) return null;
  const id = row.id ?? row.user_id ?? row.userId;
  const avatarUpdated = Number(row.avatar_updated ?? row.avatarUpdated ?? 0);
  const hasBytes = (row.avatar_bytes && row.avatar_bytes.length) || avatarUpdated > 0;

  if (Number.isInteger(Number(id)) && hasBytes) {
    return `/avatar/${Number(id)}?v=${avatarUpdated || 1}`;
  }

  const legacy = row.avatar || row.avatar_url || row.avatarUrl || null;
  return legacy || null;
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
    avatar: avatarUrlFromRow(row),
    avatar_updated: row.avatar_updated ?? row.avatarUpdated ?? null,
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
    vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
    header_grad_a: sanitizeHexColor(row.header_grad_a),
    header_grad_b: sanitizeHexColor(row.header_grad_b),
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
    `SELECT id, username, password_hash, role, created_at, avatar, avatar_updated, bio, mood, age, gender, last_seen, last_room, last_status,
            theme, gold, xp, "lastXpMessageAt", "lastDailyLoginAt", "lastGoldTickAt", "lastMessageGoldAt", "lastDailyLoginGoldAt",
            "lastDiceRollAt", dice_sixes, vibe_tags, header_grad_a, header_grad_b
       FROM users WHERE lower(username) = lower($1) LIMIT 1`,
    [username]
  );
  return pgRowToUser(rows[0]);
}

async function pgGetUserById(id) {
  const { rows } = await pgPool.query(
    `SELECT id, username, password_hash, role, created_at, avatar, avatar_updated, bio, mood, age, gender, last_seen, last_room, last_status,
            theme, gold, xp, "lastXpMessageAt", "lastDailyLoginAt", "lastGoldTickAt", "lastMessageGoldAt", "lastDailyLoginGoldAt",
            "lastDiceRollAt", dice_sixes, vibe_tags, header_grad_a, header_grad_b
       FROM users WHERE id = $1 LIMIT 1`,
    [id]
  );
  return pgRowToUser(rows[0]);
}



// Fetch a raw Postgres user row by id, selecting only requested columns.
// NOTE: This returns the raw row object (snake_case keys), not the mapped pgRowToUser().
async function pgGetUserRowById(id, columns) {
  const allow = new Set([
    "id","username","password_hash","role","created_at","avatar","avatar_bytes","avatar_mime","avatar_updated","bio","mood","age","gender",
    "last_seen","last_room","last_status","theme","gold","xp",
    "lastXpMessageAt","lastDailyLoginAt","lastGoldTickAt","lastMessageGoldAt","lastDailyLoginGoldAt",
    "lastDiceRollAt","dice_sixes","vibe_tags","header_grad_a","header_grad_b"
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
  const rawName = String(raw || "").replace(/^@+/, "").trim().slice(0, 64);
  const cleaned = cleanUsernameForLookup(rawName);
  const legacy = sanitizeUsername(rawName);

  const tryOne = (name, next) => {
    if (!name) return next();
    db.get(
      `SELECT id, username, role FROM users
       WHERE username = ?
          OR lower(username) = lower(?)
       ORDER BY CASE WHEN username = ? THEN 0 ELSE 1 END
       LIMIT 1`,
      [name, name, name],
      (err, row) => {
        if (!err && row) return cb(null, row);
        next();
      }
    );
  };

  // Try the most faithful version first, then the cleaned lookup, then legacy sanitized.
  tryOne(rawName, () => tryOne(cleaned, () => tryOne(legacy, () => cb(new Error("User not found")))));
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

// ---- DM read receipts (in-memory; resets on restart)
const dmReadState = new Map(); // threadId -> Map(userId -> { messageId, ts })

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
  setrole: {
    minRole: "Admin",
    description: "Set a user's role (Admin+). Owners can set any role; Admins can only set roles below Admin.",
    usage: "/setrole @user RoleName",
    example: "/setrole @Sam Moderator",
    handler: async ({ socket, args, actorRole }) => {
      if (!args[0] || !args[1]) return { ok: false, message: "Usage: /setrole @user Role" };

      const target = await new Promise((resolve, reject) =>
        findUserByMention(args[0], (e, u) => (e ? reject(e) : resolve(u)))
      );

      const newRoleRaw = args.slice(1).join(" ").trim();
      const newRole = ROLES.find((r) => r.toLowerCase() === newRoleRaw.toLowerCase());
      if (!newRole) return { ok: false, message: `Invalid role. Options: ${ROLES.join(", ")}` };

      // Must be allowed to act on the target
      if (!canModerate(actorRole, target.role) && actorRole !== "Owner") {
        return { ok: false, message: "Permission denied" };
      }

      // Admins can only set roles strictly below Admin.
      if (actorRole !== "Owner") {
        if (roleRank(newRole) >= roleRank(actorRole)) {
          return { ok: false, message: "You can't assign a role at or above your own." };
        }
        if (roleRank(newRole) >= roleRank("Admin")) {
          return { ok: false, message: "Admins can only assign roles below Admin." };
        }
      }

      await setRoleEverywhere(target.id, target.username, newRole);

      // Live-update any connected sockets for that user
      for (const s of io.sockets.sockets.values()) {
        if (s.user?.id === target.id) {
          s.user.role = newRole;
          try {
            if (s.request?.session?.user) s.request.session.user.role = newRole;
          } catch {}
        }
      }

      emitUserList(socket.currentRoom);
      return { ok: true, message: `${target.username} is now ${newRole}`, targets: target.id };
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
      await setRoleEverywhere(target.id, target.username, role);
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
  // On reconnects / session-store hiccups, socket.request.session.user can be
  // temporarily missing. Commands should still work based on the live socket user.
  const actorRole = godmodeUsers.has(actor.id)
    ? "Owner"
    : (socket.user?.role || socket.request?.session?.user?.role || "User");
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

function resolveLastSeen(row, live, lastStatus) {
  const raw = row?.last_seen;
  const hasRaw = raw !== undefined && raw !== null && String(raw).trim() !== "";
  const num = Number(raw);
  if (hasRaw && Number.isFinite(num)) return num;

  const statusLabel = normalizeStatus(lastStatus || row?.last_status, "");
  const isOnline = !!live || statusLabel === "Online";
  return isOnline ? Date.now() : null;
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


async function pgUsersEnabled() {
  if (!process.env.DATABASE_URL) return false;
  try {
    await pgInitPromise;
    return PG_READY;
  } catch (e) {
    return false;
  }
}

function sqliteFetchUsersByNames(exacts, lowers) {
  return new Promise((resolve, reject) => {
    const exPh = exacts.map(() => "?").join(",");
    const loPh = lowers.map(() => "?").join(",");

    const where = [];
    const args = [];
    if (exacts.length) { where.push(`username IN (${exPh})`); args.push(...exacts); }
    if (lowers.length) { where.push(`lower(username) IN (${loPh})`); args.push(...lowers); }

    db.all(
      `SELECT id, username FROM users WHERE ${where.join(" OR ")}`,
      args,
      (err, rows) => (err ? reject(err) : resolve(rows || []))
    );
  });
}

async function fetchUsersByNames(usernames) {
  // Keep BOTH exact strings and lowercased keys.
  // This avoids breaking lookups for usernames containing emoji/symbols where LOWER() behavior can be inconsistent.
  const exacts = [];
  const lowers = [];
  const seenExact = new Set();
  const seenLower = new Set();

  for (const u of (usernames || [])) {
    const s = cleanUsernameForLookup(u);
    if (!s) continue;
    if (!seenExact.has(s)) { seenExact.add(s); exacts.push(s); }
    const k = normKey(s);
    if (!seenLower.has(k)) { seenLower.add(k); lowers.push(k); }
  }

  if (!exacts.length && !lowers.length) return [];

  const expectedKeys = new Set(lowers);
  const merged = new Map();

  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT id, username FROM users
         WHERE username = ANY($1::text[])
            OR lower(username) = ANY($2::text[])`,
        [exacts, lowers]
      );
      for (const row of rows || []) {
        if (!row?.id || !row?.username) continue;
        const id = Number(row.id);
        if (!Number.isInteger(id)) continue;
        merged.set(id, { id, username: row.username });
      }

      const foundKeys = new Set(Array.from(merged.values()).map((u) => normKey(u.username)));
      const missing = Array.from(expectedKeys).filter((k) => !foundKeys.has(k));
      if (!missing.length) return Array.from(merged.values());

      // Fall through to SQLite to cover any users that only exist there.
      const missingNames = exacts.filter((name) => missing.includes(normKey(name)));
      const fallbackRows = await sqliteFetchUsersByNames(missingNames, missing);
      for (const row of fallbackRows || []) {
        const id = Number(row?.id);
        if (!Number.isInteger(id) || merged.has(id)) continue;
        merged.set(id, { id, username: row.username });
      }
      return Array.from(merged.values());
    } catch (e) {
      console.warn("[fetchUsersByNames][pg] failed, falling back to sqlite:", e?.message || e);
      try {
        const rows = await sqliteFetchUsersByNames(exacts, lowers);
        return rows;
      } catch (fallbackErr) {
        throw fallbackErr;
      }
    }
  }

  const rows = await sqliteFetchUsersByNames(exacts, lowers);
  return rows;
}

function sqliteFetchUsersByIds(cleaned) {
  return new Promise((resolve, reject) => {
    const placeholders = cleaned.map(() => "?").join(",");
    db.all(
      `SELECT id, username FROM users WHERE id IN (${placeholders})`,
      cleaned,
      (err, rows) => (err ? reject(err) : resolve(rows || []))
    );
  });
}

async function fetchUsersByIds(ids) {
  const cleaned = Array.from(
    new Set((ids || [])
      .map((v) => Number(v))
      .filter((n) => Number.isInteger(n) && n > 0))
  );
  if (!cleaned.length) return [];

  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT id, username FROM users WHERE id = ANY($1::int[])`,
        [cleaned]
      );
      const merged = new Map();
      for (const row of rows || []) {
        const id = Number(row?.id);
        if (!Number.isInteger(id)) continue;
        merged.set(id, { id, username: row.username });
      }

      const missing = cleaned.filter((id) => !merged.has(id));
      if (!missing.length) return Array.from(merged.values());

      const sqliteRows = await sqliteFetchUsersByIds(missing);
      for (const row of sqliteRows || []) {
        const id = Number(row?.id);
        if (!Number.isInteger(id) || merged.has(id)) continue;
        merged.set(id, { id, username: row.username });
      }
      return Array.from(merged.values());
    } catch (e) {
      console.warn("[fetchUsersByIds][pg] failed, falling back to sqlite:", e?.message || e);
      try {
        const rows = await sqliteFetchUsersByIds(cleaned);
        return rows;
      } catch (fallbackErr) {
        throw fallbackErr;
      }
    }
  }

  const rows = await sqliteFetchUsersByIds(cleaned);
  return rows;
}

function sanitizeRoomName(r) {
  r = String(r || "").trim();
  r = r.replace(/^#+/, "");      // drop leading '#'
  r = r.toLowerCase();
  r = r.replace(/[^a-z0-9_-]/g, "");
  return r.slice(0, 24);
}
function normalizeDmPair(a, b) {
  const aId = Number(a);
  const bId = Number(b);
  if (!Number.isInteger(aId) || !Number.isInteger(bId) || aId <= 0 || bId <= 0 || aId === bId) {
    return null;
  }
  return { low: Math.min(aId, bId), high: Math.max(aId, bId) };
}

function ensureDmParticipants(threadId, userIds, addedBy, joinedAt, cb) {
  let pending = userIds.length;
  if (!pending) return cb && cb();
  for (const uid of userIds) {
    db.run(
      `INSERT OR IGNORE INTO dm_participants (thread_id, user_id, added_by, joined_at) VALUES (?, ?, ?, ?)`,
      [threadId, uid, addedBy, joinedAt],
      () => {
        pending -= 1;
        if (pending === 0 && cb) cb();
      }
    );
  }
}

function getOrCreateDirectThread({ userA, userB, createdBy }, cb) {
  const pair = normalizeDmPair(userA, userB);
  if (!pair) return cb(new Error("invalid participants"));
  const now = Date.now();

  const finish = (row, created) => {
    ensureDmParticipants(row.id, [pair.low, pair.high], createdBy, now, () => {
      cb(null, { id: row.id, created: !!created, user_low: pair.low, user_high: pair.high });
    });
  };

  const lookup = () => {
    db.get(
      `SELECT id, user_low, user_high FROM dm_threads WHERE is_group=0 AND user_low=? AND user_high=?`,
      [pair.low, pair.high],
      (err, row) => {
        if (row && row.id) {
          if (!row.user_low || !row.user_high) {
            db.run(`UPDATE dm_threads SET user_low=?, user_high=? WHERE id=?`, [pair.low, pair.high, row.id]);
          }
          return finish(row, false);
        }

        if (err) return cb(err);

        // Fallback: legacy rows without user_low/user_high but with both participants.
        db.get(
          `SELECT t.id FROM dm_threads t
             JOIN dm_participants p1 ON p1.thread_id=t.id AND p1.user_id=?
             JOIN dm_participants p2 ON p2.thread_id=t.id AND p2.user_id=?
           WHERE t.is_group=0
           ORDER BY t.id DESC LIMIT 1`,
          [pair.low, pair.high],
          (legacyErr, legacyRow) => {
            if (legacyRow && legacyRow.id) {
              db.run(`UPDATE dm_threads SET user_low=?, user_high=? WHERE id=?`, [pair.low, pair.high, legacyRow.id]);
              return finish({ ...legacyRow, user_low: pair.low, user_high: pair.high }, false);
            }
            if (legacyErr) return cb(legacyErr);
            return insert();
          }
        );
      }
    );
  };

  const insert = () => {
    db.run(
      `INSERT INTO dm_threads (title, is_group, created_by, created_at, user_low, user_high) VALUES (?, 0, ?, ?, ?, ?)`,
      [null, createdBy, now, pair.low, pair.high],
      function (insertErr) {
        if (insertErr) {
          // Unique constraint race: try lookup again.
          if (String(insertErr.message || "").toLowerCase().includes("unique")) return lookup();
          return cb(insertErr);
        }
        console.log(`[dm:create] thread ${this.lastID} created for users ${pair.low}/${pair.high}`);
        finish({ id: this.lastID, user_low: pair.low, user_high: pair.high }, true);
      }
    );
  };

  lookup();
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
            `SELECT u.id, u.username, u.avatar FROM dm_participants dp JOIN users u ON u.id = dp.user_id WHERE dp.thread_id = ?`,
            [threadId],
            (err3, parts) => {
              if (err3) return cb(err3);
              cb(null, {
                ...thread,
                participants: (parts || []).map((p) => p.username),
                participantIds: (parts || []).map((p) => p.id),
                participantsDetail: (parts || []).map((p) => ({ id: p.id, username: p.username, avatar: avatarUrlFromRow(p) })),
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
  const normalizeEpoch = (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  return {
    id: row.id,
    seq: row.seq,
    title: row.title,
    body: row.body || "",
    // Always send numeric epoch millis (client formats to viewer's locale/timezone).
    createdAt: normalizeEpoch(row.created_at),
    updatedAt: normalizeEpoch(row.updated_at),
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


async function pgChangelogEnabled(){
  // If DATABASE_URL is missing or Postgres init/connect failed, fall back to sqlite.
  if (!process.env.DATABASE_URL) return false;
  try {
    await pgInitPromise;
    if (!PG_READY) return false;
    // simple connectivity check
    await pgPool.query('SELECT 1');
    return true;
  } catch (e) {
    return false;
  }
}

async function pgAllChangelog(limit = 0){
  await pgInitPromise;
  if(limit){
    const { rows } = await pgPool.query(
      "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries ORDER BY seq DESC LIMIT $1",
      [limit]
    );
    return rows;
  }
  const { rows } = await pgPool.query(
    "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries ORDER BY seq DESC"
  );
  return rows;
}

async function pgCreateChangelogEntry({ title, body, authorId }){
  await pgInitPromise;
  const now = Date.now();
  const { rows } = await pgPool.query(
    "INSERT INTO changelog_entries (title, body, created_at, updated_at, author_id) VALUES ($1,$2,$3,$4,$5) RETURNING id, seq, title, body, created_at, updated_at, author_id",
    [title, body, now, now, authorId]
  );
  return rows[0];
}

async function pgUpdateChangelogEntry({ id, title, body }){
  await pgInitPromise;
  const now = Date.now();
  const { rowCount } = await pgPool.query(
    "UPDATE changelog_entries SET title=$1, body=$2, updated_at=$3 WHERE id=$4",
    [title, body, now, id]
  );
  if(!rowCount) return null;
  const { rows } = await pgPool.query(
    "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries WHERE id=$1",
    [id]
  );
  return rows[0] || null;
}

async function pgDeleteChangelogEntry(id){
  await pgInitPromise;
  const { rowCount } = await pgPool.query("DELETE FROM changelog_entries WHERE id=$1", [id]);
  return rowCount > 0;
}

function createChangelogEntrySqlite({ title, body, authorId }) {
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
      avatar: user.avatar || "",
      avatar_updated: user.avatar_updated ?? null,
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
    const raw = String(req.body?.username || "").trim().slice(0, 64);
    const cleaned = cleanUsernameForLookup(raw);
    const legacy = sanitizeUsername(raw);
    const candidates = Array.from(new Set([raw, cleaned, legacy].filter(Boolean)));

    const password = String(req.body?.password || "");
    if (!candidates.length || !password) return res.status(400).send("Missing credentials");

    // 1) Prefer Postgres users (new registrations land here)
    let pgUser = null;
    for (const cand of candidates) {
      pgUser = await pgGetUserByUsername(cand);
      if (pgUser) break;
    }
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

      // IMPORTANT: In Postgres we primarily store avatars in avatar_bytes/avatar_updated.
      // If we only read the legacy "avatar" column here, the session will have an empty avatar
      // and the UI will look like the profile "didn't save" after refresh.
      req.session.user = {
        id: pgUser.id,
        username: pgUser.username,
        role: pgUser.role,
        theme,
        avatar: avatarUrlFromRow(pgUser) || "",
        avatar_updated: pgUser.avatar_updated ?? pgUser.avatarUpdated ?? null,
      };
      await dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", pgUser.id]).catch(() => {});

      initGoldTick(pgUser.id);

      return req.session.save((saveErr) => {
        if (saveErr) return res.status(500).send("Session save failed");
        return res.json({ ok: true });
      });
    }

    // 2) Fallback to SQLite (legacy accounts)
    let row = null;
    for (const cand of candidates) {
      row = await dbGetAsync(
        "SELECT * FROM users WHERE username = ? OR lower(username) = lower(?)",
        [cand, cand]
      ).catch(() => null);
      if (row) break;
    }
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

    req.session.user = { id: row.id, username: row.username, role: row.role, theme, avatar: avatarUrlFromRow(row) || "", avatar_updated: row.avatar_updated ?? row.avatarUpdated ?? null };

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

    // If we already have an avatar in-session, keep it as a fallback.
    const prevAvatar = req.session?.user?.avatar || "";
    const prevAvatarUpdated = req.session?.user?.avatar_updated ?? null;

    // Prefer Postgres
    const { rows } = await pgPool.query(
      "SELECT id, username, role, theme, avatar, avatar_bytes, avatar_mime, avatar_updated FROM users WHERE id = $1 LIMIT 1",
      [req.session.user.id]
    );

    let row = rows[0];

    // If not in Postgres yet, fallback to SQLite and (optionally) sync
    if (!row) {
      const srow = await dbGet(
        "SELECT id, username, role, theme, avatar, vibe_tags, bio, mood, age, gender FROM users WHERE id = ?",
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

      const computedAvatar = avatarUrlFromRow(srow) || "";
      req.session.user = {
        id: srow.id,
        username: srow.username,
        role: srow.role,
        theme,
        avatar: computedAvatar || prevAvatar,
        avatar_updated: srow.avatar_updated ?? srow.avatarUpdated ?? prevAvatarUpdated,
      };
      return res.json(req.session.user);
    }

    const theme = sanitizeThemeNameServer(row.theme);
    if (!row.theme) await pgPool.query("UPDATE users SET theme = $1 WHERE id = $2", [theme, row.id]);

    const computedAvatar = avatarUrlFromRow(row) || "";
    req.session.user = {
      id: row.id,
      username: row.username,
      role: row.role,
      theme,
      avatar: computedAvatar || prevAvatar,
      avatar_updated: row.avatar_updated ?? row.avatarUpdated ?? prevAvatarUpdated,
    };
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
        // Enforce private-theme rules server-side
    const effective = canUseTheme(req.session.user, theme) ? theme : DEFAULT_THEME;
    req.session.user.theme = effective;
    return res.json({ theme: effective });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Failed");
  }
});


app.post("/api/me/theme", requireLogin, async (req, res) => {
  try {
    const theme = sanitizeThemeNameServer(req.body?.theme);

    // Enforce private-theme rules server-side
    if (!canUseTheme(req.session.user, theme)) {
      return res.status(403).json({ error: "Theme not allowed" });
    }


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

// ---- User prefs (badge colors, DM theme, etc)
function safeJsonParse(raw, fallback) {
  try {
    if (raw == null || raw === "") return fallback;
    if (typeof raw === "object") return raw; // pg may already return json
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
function sanitizePrefsInput(p) {
  const out = {};
  if (p && typeof p === "object") {
    if (p.dmBadgePrefs && typeof p.dmBadgePrefs === "object") out.dmBadgePrefs = p.dmBadgePrefs;
    if (p.dmThemePrefs && typeof p.dmThemePrefs === "object") out.dmThemePrefs = p.dmThemePrefs;
    if (p.sound && typeof p.sound === "object") {
      const sound = {};
      for (const key of ["enabled", "room", "dm", "mention", "sent", "receive", "reaction"]) {
        if (typeof p.sound[key] === "boolean") sound[key] = p.sound[key];
      }
      out.sound = sound;
    }
  }
  return out;
}

app.get("/api/me/prefs", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  try {
    // Prefer Postgres if the user exists there
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query("SELECT prefs_json FROM users WHERE id = $1 LIMIT 1", [userId]);
      const prefs = safeJsonParse(rows?.[0]?.prefs_json, {});
      return res.json({ prefs });
    }
  } catch (e) {
    console.warn("[prefs][pg] read failed, falling back to sqlite:", e?.message || e);
  }

  db.get("SELECT prefs_json FROM users WHERE id = ?", [userId], (err, row) => {
    if (err) return res.status(500).send("Failed");
    const prefs = safeJsonParse(row?.prefs_json, {});
    return res.json({ prefs });
  });
});

app.post("/api/me/prefs", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const incoming = sanitizePrefsInput(req.body?.prefs ?? req.body);

  try {
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query("SELECT prefs_json FROM users WHERE id = $1 LIMIT 1", [userId]);
      const current = safeJsonParse(rows?.[0]?.prefs_json, {});
      const merged = { ...(current || {}), ...(incoming || {}) };
      await pgPool.query("UPDATE users SET prefs_json = $1 WHERE id = $2", [merged, userId]);

      // Keep SQLite in sync
      db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId]);
      return res.json({ ok: true, prefs: merged });
    }
  } catch (e) {
    console.warn("[prefs][pg] update failed, falling back to sqlite:", e?.message || e);
  }

  // SQLite fallback
  db.get("SELECT prefs_json FROM users WHERE id = ?", [userId], (_e, row) => {
    const current = safeJsonParse(row?.prefs_json, {});
    const merged = { ...(current || {}), ...(incoming || {}) };
    db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId], (err2) => {
      if (err2) return res.status(500).send("Failed");
      return res.json({ ok: true, prefs: merged });
    });
  });
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
  const limit = clamp(req.query?.limit || 0, 0, 200);

  // Prefer Postgres for persistence on Render; fall back to sqlite on any PG error.
  if (await pgChangelogEnabled()) {
    try {
      const rows = await pgAllChangelog(limit);
      return res.json((rows || []).map((r) => toChangelogPayload(r)));
    } catch (e) {
      console.warn("[changelog] PG GET failed, falling back to sqlite:", e?.message || e);
    }
  }

  try {
    const sql =
      "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries ORDER BY seq DESC" +
      (limit ? " LIMIT ?" : "");
    const rows = await dbAllAsync(sql, limit ? [limit] : []);
    return res.json((rows || []).map((r) => toChangelogPayload(r)));
  } catch (e) {
    console.error("[changelog] sqlite GET failed:", e?.message || e);
    return res.status(500).send("Failed to load changelog");
  }
});

app.post("/api/changelog", requireOwner, async (req, res) => {
  const cleaned = cleanChangelogInput(req.body?.title, req.body?.body);
  if (cleaned.error) return res.status(400).send(cleaned.error);

  try {
    let entry = null;

    if (await pgChangelogEnabled()) {
      try {
        entry = await pgCreateChangelogEntry({
          title: cleaned.title,
          body: cleaned.body,
          authorId: req.session.user.id,
        });
      } catch (e) {
        console.warn("[changelog] PG POST failed, falling back to sqlite:", e?.message || e);
      }
    }

    if (!entry) {
      entry = await createChangelogEntrySqlite({
        title: cleaned.title,
        body: cleaned.body,
        authorId: req.session.user.id,
      });
    }

    const payload = toChangelogPayload(entry);
    io.emit("changelog updated");
    return res.json(payload);
  } catch (err) {
    console.error("[changelog] create failed:", err?.message || err);
    return res.status(500).send("Failed to create changelog entry");
  }
});

app.put("/api/changelog/:id", requireOwner, async (req, res) => {
  const id = Number(req.params?.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).send("Invalid entry id");

  const cleaned = cleanChangelogInput(req.body?.title, req.body?.body);
  if (cleaned.error) return res.status(400).send(cleaned.error);

  try {
    if (await pgChangelogEnabled()) {
      try {
        const row = await pgUpdateChangelogEntry({ id, title: cleaned.title, body: cleaned.body });
        if (row) {
          io.emit("changelog updated");
          return res.json(toChangelogPayload(row));
        }
      } catch (e) {
        console.warn("[changelog] PG PUT failed, falling back to sqlite:", e?.message || e);
      }
    }

    // sqlite fallback
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
    console.error("[changelog] update failed:", err?.message || err);
    return res.status(500).send("Failed to update changelog entry");
  }
});

app.delete("/api/changelog/:id", requireOwner, async (req, res) => {
  const id = Number(req.params?.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).send("Invalid entry id");

  const confirmed = req.body?.confirm === true || req.body?.confirm === "true";
  if (!confirmed) return res.status(400).send("Confirmation required");

  try {
    if (await pgChangelogEnabled()) {
      try {
        const ok = await pgDeleteChangelogEntry(id);
        if (ok) {
          io.emit("changelog updated");
          return res.json({ ok: true });
        }
      } catch (e) {
        console.warn("[changelog] PG DELETE failed, falling back to sqlite:", e?.message || e);
      }
    }

    // sqlite fallback
    const result = await dbRunAsync(`DELETE FROM changelog_entries WHERE id=?`, [id]);
    if (!result?.changes) return res.status(404).send("Entry not found");
    io.emit("changelog updated");
    return res.json({ ok: true });
  } catch (err) {
    console.error("[changelog] delete failed:", err?.message || err);
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
        "avatar_updated",
        "bio",
        "mood",
        "age",
        "gender",
        "header_grad_a",
        "header_grad_b",
        "created_at",
        "last_seen",
        "last_room",
        "last_status",
        "gold",
        "xp",
        "vibe_tags",
      ]);
      if (!row) return res.status(404).send("Not found");

      const live = onlineState.get(row.id);
      const lastStatus = normalizeStatus(live?.status || row.last_status, "");
      const lastSeen = resolveLastSeen(row, live, lastStatus);

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
            avatar: avatarUrlFromRow(row),
            bio: row.bio,
            mood: row.mood,
            age: row.age,
            gender: row.gender,
          created_at: row.created_at,
          last_seen: lastSeen,
          last_room: row.last_room,
          last_status: lastStatus || null,
          current_room: live?.room || null,
          header_grad_a: sanitizeHexColor(row.header_grad_a),
          header_grad_b: sanitizeHexColor(row.header_grad_b),
          likes: Number(likesRow?.likes || 0),
          likedByMe: !!Number(likesRow?.liked || 0),
          vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
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
    `SELECT id, username, role, avatar, bio, mood, age, gender, created_at, last_seen, last_room, last_status, gold, xp, vibe_tags, header_grad_a, header_grad_b
     FROM users WHERE id = ?`,
    [userId],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      const live = onlineState.get(row.id);
      const lastStatus = normalizeStatus(live?.status || row.last_status, "");
      const lastSeen = resolveLastSeen(row, live, lastStatus);
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
            avatar: avatarUrlFromRow(row),
            bio: row.bio,
            mood: row.mood,
            age: row.age,
            gender: row.gender,
            created_at: row.created_at,
            last_seen: lastSeen,
            last_room: row.last_room,
            last_status: lastStatus || null,
            current_room: live?.room || null,
            header_grad_a: sanitizeHexColor(row.header_grad_a),
            header_grad_b: sanitizeHexColor(row.header_grad_b),
            likes: Number(likesRow?.likes || 0),
            likedByMe: !!Number(likesRow?.liked || 0),
            vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
            ...progressionFromRow(row, true),
          };
          return res.json(payload);
        }
      );
    }
  );
});

app.get("/profile/:username", requireLogin, async (req, res) => {
  const rawParam = String(req.params.username || "");
  let decoded = rawParam;
  try { decoded = decodeURIComponent(rawParam); } catch {}
  const rawName = String(decoded || "").trim().slice(0, 64);
  const cleaned = cleanUsernameForLookup(rawName);
  const legacy = sanitizeUsername(rawName);

  const candidates = Array.from(new Set([rawName, cleaned, legacy].filter(Boolean)));
  if (!candidates.length) return res.status(400).send("Bad username");

  try {
    // Prefer Postgres first (Render/prod path). Some users may not exist in SQLite yet.
    let row = null;
    try {
      for (const cand of candidates) {
        try {
          const r = await pgPool.query(
            `SELECT id, username, role, avatar, avatar_updated, bio, mood, age, gender, created_at, last_seen, last_room, last_status, gold, xp, vibe_tags, header_grad_a, header_grad_b
             FROM users
             WHERE username = $1 OR lower(username) = lower($1)
             LIMIT 1`,
            [cand]
          );
          row = r.rows?.[0] || null;
          if (row) break;
        } catch {}
      }
    } catch {}

    // Fallback to SQLite
    if (!row) {
      for (const cand of candidates) {
        row = await dbGet(
          `SELECT id, username, role, avatar, avatar_updated, bio, mood, age, gender, created_at, last_seen, last_room, last_status, gold, xp, vibe_tags, header_grad_a, header_grad_b
           FROM users
           WHERE username = ? OR lower(username) = lower(?)`,
          [cand, cand]
        );
        if (row) break;
      }
    }

    if (!row) return res.status(404).send("Not found");

    const live = onlineState.get(row.id);
    const lastStatus = normalizeStatus(live?.status || row.last_status, "");
    const lastSeen = resolveLastSeen(row, live, lastStatus);
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
          avatar: avatarUrlFromRow(row),
          bio: row.bio,
          mood: live?.mood ?? row.mood,
          age: row.age,
          gender: row.gender,
          created_at: row.created_at,
          last_seen: lastSeen,
          last_room: row.last_room,
          last_status: lastStatus || null,
          current_room: live?.room || null,
          header_grad_a: sanitizeHexColor(row.header_grad_a),
          header_grad_b: sanitizeHexColor(row.header_grad_b),
          likes: Number(likesRow?.likes || 0),
          likedByMe: !!Number(likesRow?.liked || 0),
          vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
          ...progressionFromRow(row, includePrivate),
        };
        return res.json(payload);
      }
    );
  } catch (e) {
    return res.status(500).send("Server error");
  }
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

// Avatar upload for profile edits (2MB max, in-memory only)
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(png|jpeg|jpg|webp|gif)$/i.test(file.mimetype || "");
    cb(ok ? null : new Error("Invalid avatar type"), ok);
  },
});

// IMPORTANT: Most of your app now reads profiles from Postgres (when the user exists there).
// The old version of this route only updated SQLite, so uploads "worked" but never showed up.
app.post("/profile", requireLogin, (req, res) => {
  avatarUpload.single("avatar")(req, res, async (err) => {
    if (err) {
      const msg =
        err.code === "LIMIT_FILE_SIZE"
          ? "Avatar too large (max 2MB)."
          : (err.message || "Avatar upload failed.");
      return res.status(400).json({ ok: false, message: msg });
    }

    const userId = req.session.user.id;
    const mood = String(req.body?.mood || "").slice(0, 40);
    const bio = String(req.body?.bio || "").slice(0, 2000);
    const age = req.body?.age === "" || req.body?.age == null ? null : clamp(req.body.age, 18, 120);
    const gender = String(req.body?.gender || "").slice(0, 40);
    const vibeTags = sanitizeVibeTags(req.body?.vibeTags);
    const headerGradA = sanitizeHexColor(req.body?.headerColorA);
    const headerGradB = sanitizeHexColor(req.body?.headerColorB);
    // Postgres stores vibe_tags as JSONB. node-postgres will otherwise serialize arrays
    // as Postgres array literals, which causes the UPDATE to fail and makes changes
    // appear to "revert" on refresh (because /profile reads from Postgres first).
    const vibeTagsJson = JSON.stringify(vibeTags);
    const file = req.file || null;
    const avatarUpdated = file ? Date.now() : null;
    const avatarUrl = file ? `/avatar/${userId}?v=${avatarUpdated}` : null;

    // Best-effort: push updated profile bits into the currently-connected socket (so members list/chat updates immediately)
    const refreshLivePresence = () => {
      const sid = socketIdByUserId.get(userId);
      const s = sid ? io.sockets.sockets.get(sid) : null;
      if (!s?.user) return;
      if (avatarUrl) s.user.avatar = avatarUrl;
      s.user.mood = mood;
      s.user.vibe_tags = vibeTags;
      if (s.currentRoom) emitUserList(s.currentRoom);
    };

    try {
      // Prefer Postgres if this user exists there (Render prod path)
      if (await pgUserExists(userId)) {
        if (file) {
          await pgPool.query(
            `UPDATE users
               SET mood = $1,
                   bio = $2,
                   age = $3,
                   gender = $4,
                   avatar_bytes = $5,
                   avatar_mime = $6,
                   avatar_updated = $7,
                   avatar = NULL,
                   vibe_tags = $8::jsonb,
                   header_grad_a = COALESCE($9, header_grad_a),
                   header_grad_b = COALESCE($10, header_grad_b)
             WHERE id = $11`,
            [mood, bio, age, gender, file.buffer, file.mimetype, avatarUpdated, vibeTagsJson, headerGradA, headerGradB, userId]
          );
        } else {
          await pgPool.query(
            `UPDATE users
               SET mood = $1,
                   bio = $2,
                   age = $3,
                   gender = $4,
                   vibe_tags = $5::jsonb,
                   header_grad_a = COALESCE($6, header_grad_a),
                   header_grad_b = COALESCE($7, header_grad_b)
             WHERE id = $8`,
            [mood, bio, age, gender, vibeTagsJson, headerGradA, headerGradB, userId]
          );
        }
        if (avatarUrl) req.session.user.avatar = avatarUrl;
        // Reinforcement: persist the updated session before responding so refresh
        // cannot revert to a stale/empty avatar due to an unsaved session write.
        return req.session.save((saveErr) => {
          if (saveErr) return res.status(500).json({ ok: false, message: "Session save failed" });
          refreshLivePresence();
          return res.json({ ok: true, avatar: avatarUrl });
        });
      }
    } catch (e) {
      console.warn("[/profile][pg] update failed, falling back to sqlite:", e?.message || e);
    }

    if (file) {
      return res.status(500).json({ ok: false, message: "Avatar storage unavailable right now." });
    }

    // SQLite fallback (original behavior)
    db.get("SELECT avatar, vibe_tags, header_grad_a, header_grad_b FROM users WHERE id = ?", [userId], (_e, old) => {
      const newAvatar = old?.avatar || null;
      const oldVibes = sanitizeVibeTags(old?.vibe_tags || []);
      const vibeJson = JSON.stringify(vibeTags.length ? vibeTags : oldVibes);
      const newHeaderGradA = headerGradA ?? sanitizeHexColor(old?.header_grad_a);
      const newHeaderGradB = headerGradB ?? sanitizeHexColor(old?.header_grad_b);

      db.run(
        `UPDATE users SET mood=?, bio=?, age=?, gender=?, avatar=?, vibe_tags=?, header_grad_a=?, header_grad_b=? WHERE id=?`,
        [mood, bio, age, gender, newAvatar, vibeJson, newHeaderGradA, newHeaderGradB, userId],
        (err2) => {
          if (err2) return res.status(500).send("Save failed");
          if (avatarUrl) req.session.user.avatar = avatarUrl;
          refreshLivePresence();
          return res.json({ ok: true, avatar: avatarUrl });
        }
      );
    });
  });
});



// Remove avatar (clears avatar field; best-effort deletes local file if present)
app.delete("/profile/avatar", requireLogin, async (req, res) => {
  const userId = req.session.user.id;

  const clearAvatarInLivePresence = () => {
    const sid = socketIdByUserId.get(userId);
    const s = sid ? io.sockets.sockets.get(sid) : null;
    if (!s?.user) return;
    s.user.avatar = null;
    if (s.currentRoom) emitUserList(s.currentRoom);
  };

  const tryDeleteLocalAvatarFile = (avatarUrl) => {
    try {
      const rel = String(avatarUrl || "");
      if (!rel.startsWith("/avatars/")) return;
      const fp = path.join(AVATARS_DIR, path.basename(rel));
      fs.unlink(fp, () => {});
    } catch {}
  };

  try {
    // Prefer Postgres if present
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query(`SELECT avatar FROM users WHERE id = $1`, [userId]);
      const oldAvatar = rows?.[0]?.avatar || null;

      await pgPool.query(
        `UPDATE users
            SET avatar = NULL,
                avatar_bytes = NULL,
                avatar_mime = NULL,
                avatar_updated = NULL
          WHERE id = $1`,
        [userId]
      );
      req.session.user.avatar = null;
      clearAvatarInLivePresence();
      tryDeleteLocalAvatarFile(oldAvatar);
      return res.json({ ok: true });
    }
  } catch (e) {
    console.warn("[/profile/avatar][pg] delete failed, falling back to sqlite:", e?.message || e);
  }

  // SQLite fallback
  db.get("SELECT avatar FROM users WHERE id = ?", [userId], (_e, row) => {
    const oldAvatar = row?.avatar || null;
    db.run(`UPDATE users SET avatar = NULL WHERE id = ?`, [userId], (err2) => {
      if (err2) return res.status(500).send("Could not remove avatar");
      req.session.user.avatar = null;
      clearAvatarInLivePresence();
      tryDeleteLocalAvatarFile(oldAvatar);
      return res.json({ ok: true });
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
// NOTE: This handler is used for BOTH /dm/threads and /api/dm/threads.
// Older builds mounted everything under /api; newer builds use /dm.
// Keeping both paths avoids breaking clients and prevents 404s.
function handleListDmThreads(req, res) {
  const userId = req.session.user.id;

  db.all(
    `SELECT t.id, t.title, t.is_group, t.created_at,
            COALESCE(t.last_message_id, (SELECT id FROM dm_messages WHERE thread_id=t.id ORDER BY ts DESC LIMIT 1)) AS last_message_id,
            (SELECT text FROM dm_messages WHERE thread_id=t.id ORDER BY ts DESC LIMIT 1) AS last_text,
            COALESCE(t.last_message_at, (SELECT ts FROM dm_messages WHERE thread_id=t.id ORDER BY ts DESC LIMIT 1)) AS last_ts,
            (SELECT COUNT(*) FROM dm_messages m
              WHERE m.thread_id = t.id
                AND m.user_id != ?
                AND m.ts > COALESCE(pself.last_read_at, 0)
            ) AS unreadCount
     FROM dm_threads t
     INNER JOIN dm_participants pself ON pself.thread_id = t.id AND pself.user_id = ?
     ORDER BY COALESCE(t.last_message_at, last_ts, t.created_at) DESC`,
    [userId, userId],
    (err, threads) => {
      if (err) {
        console.error("[dm/threads]", err);
        return res.status(500).send("Failed to load threads");
      }
      if (!threads?.length) return res.json([]);

      const ids = threads.map((t) => t.id);
      const placeholders = ids.map(() => "?").join(",");

      db.all(
        `SELECT dp.thread_id, u.id as user_id, u.username, u.avatar
         FROM dm_participants dp
         JOIN users u ON u.id = dp.user_id
         WHERE dp.thread_id IN (${placeholders})`,
        ids,
        (_e, parts) => {
          const grouped = new Map();
          for (const p of parts || []) {
            if (!grouped.has(p.thread_id)) grouped.set(p.thread_id, []);
            grouped.get(p.thread_id).push(p);
          }

          const result = threads.map((t) => {
            const members = grouped.get(t.id) || [];
            const other = members.find((m) => Number(m.user_id) !== Number(userId)) || members[0] || null;
            return {
              ...t,
              participants: members.map((p) => p.username),
              participantIds: members.map((p) => p.user_id),
              participantsDetail: members.map((p) => ({ id: p.user_id, username: p.username, avatar: avatarUrlFromRow(p) })),
              otherUser: other
                ? { id: other.user_id, username: other.username, avatar: avatarUrlFromRow(other) }
                : null,
              unreadCount: Number(t.unreadCount || 0),
            };
          });
          res.json(result);
        }
      );
    }
  );
}

app.get("/dm/threads", requireLogin, handleListDmThreads);
app.get("/api/dm/threads", requireLogin, handleListDmThreads);

app.get("/dm/thread/:id", requireLogin, (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isInteger(tid)) return res.status(400).send("Invalid thread");
  loadThreadForUser(tid, req.session.user.id, (err, thread) => {
    if (err) return res.status(403).send("Not allowed");
    return res.json(thread);
  });
});

app.get("/api/dm/thread/:id", requireLogin, (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isInteger(tid)) return res.status(400).send("Invalid thread");
  loadThreadForUser(tid, req.session.user.id, (err, thread) => {
    if (err) return res.status(403).send("Not allowed");
    return res.json(thread);
  });
});

  // --- DM thread creation (shared by /dm and /api prefixes)
  async function handleCreateDmThread(req, res) {
    // Accept multiple payload shapes for compatibility:
    // { participants:["a"], kind:"direct" }
    // { participant:"a" } / { user:"a" } / { to:"a" } / { username:"a" }
    let participantNames = req.body?.participants;
    let participantIds = req.body?.participantIds || req.body?.participantsIds;
    if (!Array.isArray(participantIds)) {
      const singleId =
        req.body?.participantId ??
        req.body?.toId ??
        req.body?.userId ??
        req.body?.targetId ??
        null;
      participantIds = singleId != null ? [singleId] : [];
    }

    // Normalize participants list (strings) and allow mixed arrays (ids or usernames)
    if (Array.isArray(participantNames)) {
      const nextNames = [];
      for (const v of participantNames) {
        const n = Number(v);
        if (Number.isInteger(n) && n > 0) participantIds.push(n);
        else nextNames.push(v);
      }
      participantNames = nextNames;
    } else {
      const raw = String(
        participantNames ||
        req.body?.participant ||
        req.body?.user ||
        req.body?.to ||
        req.body?.username ||
        ""
      );
      participantNames = raw.split(",");
    }

    // De-dupe ids
    participantIds = Array.from(
      new Set(
        participantIds
          .map((v) => Number(v))
          .filter((n) => Number.isInteger(n) && n > 0)
      )
    );

    const kindRaw = String(req.body?.kind || "").trim().toLowerCase();
    let title = String(req.body?.title || "").trim().slice(0, 80);
    const cleanedNames = [];
    const seen = new Set();
    for (const name of participantNames || []) {
      const s = cleanUsernameForLookup(name);
      const key = normKey(s);
      if (!s || seen.has(key)) continue;
      if (key === normKey(req.session.user.username)) continue;
      seen.add(key);
      cleanedNames.push(s);
    }

    // If client passed ids, allow creating threads without relying on username matching.
    if (!cleanedNames.length && !participantIds.length) {
      return res.status(400).send("Pick someone to message");
    }

    // Determine kind: group if explicitly requested OR more than one recipient (by name or id) OR a title is provided.
    const requestedCount = cleanedNames.length + participantIds.length;
    const isGroup = kindRaw === "group" || requestedCount > 1 || !!title;

    if (isGroup && requestedCount < 2) {
      return res.status(400).send("Group chats need 2+ participants (or a title)");
    }

    try {
      const usersByName = await fetchUsersByNames(cleanedNames);
      if (usersByName.length !== cleanedNames.length) {
        const found = new Set((usersByName || []).map((u) => normKey(u.username)));
        const missing = cleanedNames.filter((n) => !found.has(normKey(n))).slice(0, 3);
        return res.status(404).send(missing.length ? `User not found: ${missing.join(", ")}` : "User not found");
      }

      const myId = req.session.user.id;
      const myName = req.session.user.username;
      const now = Date.now();

      const usersById = await fetchUsersByIds(participantIds);
      if (usersById.length !== participantIds.length) {
        const foundIds = new Set((usersById || []).map((u) => Number(u.id)));
        const missingIds = participantIds.filter((id) => !foundIds.has(Number(id))).slice(0, 3);
        return res.status(404).send(missingIds.length ? `User not found (id): ${missingIds.join(", ")}` : "User not found");
      }

      const merged = new Map();
      for (const u of usersByName || []) merged.set(Number(u.id), u);
      for (const u of usersById || []) merged.set(Number(u.id), u);
      merged.delete(Number(myId));

      const recipients = Array.from(merged.values());
      if (!isGroup && recipients.length !== 1) {
        return res.status(400).send("Pick exactly one person for a direct DM");
      }

      const recipientIds = recipients.map((u) => Number(u.id));
      const recipientNames = recipients.map((u) => u.username);
      const allParticipantIds = Array.from(new Set([...recipientIds, myId]));
      const allParticipantNames = Array.from(new Set([...recipientNames, myName]));

      const notifyParticipants = (threadId, reused, isGroupThread, threadTitle = title || null) => {
        for (const uid of allParticipantIds) {
          const sid = socketIdByUserId.get(uid);
          if (sid) {
            const sock = io.sockets.sockets.get(sid);
            if (sock) sock.join(`dm:${threadId}`);
            io.to(sid).emit("dm thread invited", {
              threadId,
              title: threadTitle,
              isGroup: isGroupThread,
              participants: allParticipantNames,
            });
          }
        }

        return res.json({ ok: true, threadId, reused, isGroup: isGroupThread, participants: allParticipantNames });
      };

      if (!isGroup) {
        const otherId = recipientIds[0];
        return getOrCreateDirectThread({ userA: myId, userB: otherId, createdBy: myId }, (err3, info) => {
          if (err3) {
            console.error("[dm:create] direct helper failed", err3);
            return res.status(500).send("Failed to create thread");
          }
          notifyParticipants(info.id, !info.created, false, null);
        });
      }

      db.run(
        `INSERT INTO dm_threads (title, is_group, created_by, created_at) VALUES (?, ?, ?, ?)`,
        [title || null, 1, myId, now],
        function (insertErr) {
          if (insertErr) {
            console.error("[dm:create] failed to insert group", insertErr);
            return res.status(500).send("Failed to create thread");
          }
          const threadId = this.lastID;
          ensureDmParticipants(threadId, allParticipantIds, myId, now, () =>
            notifyParticipants(threadId, false, true, title || null)
          );
        }
      );
    } catch (err) {
      console.error("[dm:create] failed", err);
      return res.status(500).send("Failed to create thread");
    }
  }

app.post("/dm/thread", requireLogin, handleCreateDmThread);
app.post("/api/dm/thread", requireLogin, handleCreateDmThread);

app.post("/dm/thread/:id/participants", requireLogin, (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isInteger(tid)) return res.status(400).send("Invalid thread");

  loadThreadForUser(tid, req.session.user.id, (err, thread) => {
    if (err) return res.status(403).send("Not allowed");
    if (!thread.is_group) return res.status(400).send("Only group DMs can add members");

    let participants = req.body?.participants;
    if (!Array.isArray(participants)) participants = [];

    const cleaned = [];
    const seen = new Set();
    for (const name of participants || []) {
      const s = cleanUsernameForLookup(name);
      const key = normKey(s);
      if (!s || seen.has(key)) continue;
      if (key === normKey(req.session.user.username)) continue;
      seen.add(key);
      cleaned.push(s);
    }

    if (!cleaned.length) return res.status(400).send("Pick at least one new member");

    (async () => {
      try {
        const users = await fetchUsersByNames(cleaned);
        if (users.length !== cleaned.length) {
          const found = new Set((users || []).map((u) => normKey(u.username)));
          const missing = cleaned.filter((n) => !found.has(normKey(n))).slice(0, 3);
          return res.status(404).send(missing.length ? `User not found: ${missing.join(", ")}` : "User not found");
        }

        db.all(
          `SELECT user_id FROM dm_participants WHERE thread_id = ?`,
          [tid],
          (listErr, rows) => {
            if (listErr) return res.status(500).send("Failed to add members");
            const existingIds = new Set((rows || []).map((r) => r.user_id));
            const newUsers = users.filter((u) => !existingIds.has(u.id));
            if (!newUsers.length) return res.status(400).send("Everyone is already in the group");

            const now = Date.now();
            for (const u of newUsers) {
              db.run(
                `INSERT OR IGNORE INTO dm_participants (thread_id, user_id, added_by, joined_at) VALUES (?, ?, ?, ?)`,
                [tid, u.id, req.session.user.id, now]
              );
              const sid = socketIdByUserId.get(u.id);
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

            loadThreadForUser(tid, req.session.user.id, (infoErr, fresh) => {
              if (infoErr) return res.status(500).send("Added but could not refresh");
              return res.json({ ok: true, participants: fresh.participants });
            });
          }
        );
      } catch (fetchErr) {
        console.error("[dm:add] failed", fetchErr);
        return res.status(500).send("Failed to add members");
      }
    })();
  });
});

app.post("/dm/thread/:id/leave", requireLogin, (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isInteger(tid)) return res.status(400).send("Invalid thread");
  loadThreadForUser(tid, req.session.user.id, (err, thread) => {
    if (err) return res.status(403).send("Not allowed");
    if (!thread.is_group) return res.status(400).send("Leaving only available in group chats");

    db.run(
      `DELETE FROM dm_participants WHERE thread_id = ? AND user_id = ?`,
      [tid, req.session.user.id],
      (delErr) => {
        if (delErr) return res.status(500).send("Could not leave group");
        return res.json({ ok: true });
      }
    );
  });
});

app.delete("/dm/thread/:id/messages", requireLogin, (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isInteger(tid)) return res.status(400).send("Invalid thread");

  loadThreadForUser(tid, req.session.user.id, (err) => {
    if (err) return res.status(403).send("Not allowed");

    db.run("DELETE FROM dm_messages WHERE thread_id = ?", [tid], (delErr) => {
      if (delErr) return res.status(500).send("Failed to delete history");

      io.to(`dm:${tid}`).emit("dm history cleared", { threadId: tid });
      res.json({ ok: true });
    });
  });
});

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

function emitOnlineUsers() {
  try {
    io.emit("onlineUsers", Array.from(ONLINE_USERS));
  } catch {}
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
        username: s.user.username,
        id: s.user.id,
        role: s.user.role,
        status,
        mood: s.user.mood || "",
        avatar: s.user.avatar || "",
        vibe_tags: sanitizeVibeTags(s.user.vibe_tags || []),
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
io.on("connection", (socket) => {
  const sessUser = socket.request.session?.user;
  if (!sessUser?.id) {
    socket.disconnect(true);
    return;
  }

  socket.user = {
    id: sessUser.id,
    username: sessUser.username,
    role: sessUser.role,
    theme: sessUser.theme || null,
    status: sessUser.status || "Online",
    mood: sessUser.mood || "",
    avatar: sessUser.avatar || "",
    vibe_tags: Array.isArray(sessUser.vibe_tags) ? sessUser.vibe_tags : [],
  };

  // Track global online usernames (for private theme "together online" effects)
  if (socket.user?.username) ONLINE_USERS.add(socket.user.username);
  emitOnlineUsers();
// Enforce single active connection per user (prevents duplicate presence)
const existingSid = socketIdByUserId.get(socket.user.id);
if (existingSid && existingSid !== socket.id) {
  const oldSocket = io.sockets.sockets.get(existingSid);
  if (oldSocket) {
    oldSocket.disconnect(true);
  }
}
  socketIdByUserId.set(socket.user.id, socket.id);
  onlineXpTrack.set(socket.user.id, { lastTs: Date.now(), carryMs: 0 });
  initGoldTick(socket.user.id);

// Load profile bits for presence (PG-first, SQLite fallback) + refresh member list when ready
(async () => {
  try {
    if (await pgUserExists(socket.user.id)) {
      const { rows } = await pgPool.query(
        "SELECT avatar, avatar_updated, mood, vibe_tags FROM users WHERE id=$1 LIMIT 1",
        [socket.user.id]
      );
      const r = rows?.[0];
      if (r) {
        // IMPORTANT: don't overwrite a session-provided avatar with an empty value
        // from a fallback/partial row. This was causing avatars to "reset" on refresh.
        const computedAvatar = avatarUrlFromRow(r);
        if (computedAvatar) socket.user.avatar = computedAvatar;
        if (typeof r.mood === "string") socket.user.mood = r.mood;
        socket.user.vibe_tags = sanitizeVibeTags(r.vibe_tags || []);
        if (socket.currentRoom) emitUserList(socket.currentRoom);
      }
      return;
    }
  } catch (e) {
    console.warn("[presence][pg] failed:", e?.message || e);
  }

  db.get(
    "SELECT avatar, mood, vibe_tags FROM users WHERE id = ?",
    [socket.user.id],
    (_e, row) => {
      if (row) {
        const computedAvatar = avatarUrlFromRow(row);
        if (computedAvatar) socket.user.avatar = computedAvatar;
        if (typeof row.mood === "string") socket.user.mood = row.mood;
        socket.user.vibe_tags = sanitizeVibeTags(row.vibe_tags || []);
        if (socket.currentRoom) emitUserList(socket.currentRoom);
      }
    }
  );
})();

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

  db.all(
    `SELECT thread_id FROM dm_participants WHERE user_id = ?`,
    [socket.user.id],
    (_e, rows) => {
      for (const r of rows || []) {
        const tid = Number(r.thread_id);
        if (!Number.isFinite(tid)) continue;
        socket.dmThreads.add(tid);
        socket.join(`dm:${tid}`);
      }
    }
  );

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
          if (now - last < 3000) {
            socket.emit("dice:error", `Roll available in ${Math.ceil((3000 - (now - last)) / 1000)}s.`);
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
        if (now - last < 3000) {
          socket.emit("dice:error", `Roll available in ${Math.ceil((3000 - (now - last)) / 1000)}s.`);
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
            attachmentUrl: r.attachment_url || null,
            attachmentMime: r.attachment_mime || null,
            attachmentType: r.attachment_type || null,
            attachmentSize: r.attachment_size || null,
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

  socket.on("dm join", ({ threadId }) => {
    const tid = Number(threadId);
    if (!Number.isInteger(tid)) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err) return;
      socket.dmThreads.add(tid);
      socket.join(`dm:${tid}`);

      db.all(
        `SELECT id, thread_id, user_id, username, text, ts, edited_at, reply_to_id, reply_to_user, reply_to_text, attachment_url, attachment_mime, attachment_type, attachment_size FROM dm_messages WHERE thread_id=? ORDER BY ts DESC LIMIT 50`,
        [tid],
        (_e, rows) => {
          const msgs = (rows || []).reverse().map((r) => ({
            messageId: r.id,
            id: r.id,
            threadId: r.thread_id,
            userId: r.user_id,
            user: r.username,
            text: r.text,
            ts: r.ts,
            editedAt: r.edited_at || 0,
            replyToId: r.reply_to_id || null,
            replyToUser: r.reply_to_user || "",
            replyToText: r.reply_to_text || "",
            attachmentUrl: r.attachment_url || null,
            attachmentMime: r.attachment_mime || null,
            attachmentType: r.attachment_type || null,
            attachmentSize: r.attachment_size || null,
          }));
          socket.emit("dm history", {
            threadId: tid,
            title: thread.title || "",
            isGroup: !!thread.is_group,
            participants: thread.participants || [],
            messages: msgs,
          });

          // Send initial DM reactions for these messages (so the client can render immediately)
          try {
            const mids = (msgs || []).map(m => Number(m.messageId || m.id)).filter(n => Number.isInteger(n));
            if (mids.length) {
              const placeholders = mids.map(() => "?").join(",");
              db.all(
                `SELECT message_id, username, emoji
                   FROM dm_reactions
                  WHERE thread_id = ?
                    AND message_id IN (${placeholders})`,
                [tid, ...mids],
                (_re, rrows) => {
                  const byMid = new Map();
                  for (const rr of (rrows || [])) {
                    const k = String(rr.message_id);
                    if (!byMid.has(k)) byMid.set(k, {});
                    byMid.get(k)[rr.username] = rr.emoji;
                  }
                  for (const mid of mids) {
                    const reactions = byMid.get(String(mid)) || {};
                    socket.emit("dm reaction update", { threadId: tid, messageId: mid, reactions });
                  }
                }
              );
            }
          } catch {}

        }
      );
    });
  });

  
  socket.on("dm mark read", ({ threadId, messageId, ts }) => {
    const tid = Number(threadId);
    const mid = Number(messageId);
    const tms = Number(ts) || Date.now();
    if (!socket.user) return;
    if (!Number.isInteger(tid) || !Number.isInteger(mid)) return;

    // ensure user is allowed in this thread
    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err || !thread) return;

      let perThread = dmReadState.get(tid);
      if (!perThread) dmReadState.set(tid, (perThread = new Map()));
      perThread.set(socket.user.id, { messageId: mid, ts: tms });

      // Persist last-read so unread counts/badges survive reloads/devices
      db.run(
        `UPDATE dm_participants
           SET last_read_at = CASE WHEN COALESCE(last_read_at,0) < ? THEN ? ELSE COALESCE(last_read_at,0) END
         WHERE thread_id = ? AND user_id = ?`,
        [tms, tms, tid, socket.user.id],
        () => {}
      );

      // Broadcast to everyone in the dm room (clients can ignore self)
      io.to(`dm:${tid}`).emit("dm read", {
        threadId: tid,
        userId: socket.user.id,
        messageId: mid,
        ts: tms
      });
    });
  });


  socket.on("dm leave", ({ threadId }) => {
    const tid = Number(threadId);
    if (!Number.isInteger(tid)) return;
    try { socket.leave(`dm:${tid}`); } catch {}
    try { socket.dmThreads?.delete(tid); } catch {}
  });

socket.on("dm message", ({ threadId, text, replyToId, attachment }) => {
    const tid = Number(threadId);
    const body = String(text || "").trim().slice(0, 800);
    const att = attachment && typeof attachment === "object" ? attachment : null;

    // Allow messages with either text or an image attachment
    if (!Number.isInteger(tid) || (!body && !att)) return;

    // Basic attachment validation (DMs: images only)
    let attUrl = null, attMime = null, attType = null, attSize = null;
    if (att) {
      attUrl = String(att.url || "").trim();
      attMime = String(att.mime || "").trim();
      attType = String(att.type || "").trim();
      attSize = Number(att.size || 0) || 0;

      const okUrl = attUrl.startsWith("/uploads/");
      const okImg = attType === "image" && /^image\//i.test(attMime);
      if (!okUrl || !okImg) return;
      if (attSize > (10 * 1024 * 1024)) return; // 10MB
    }

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err) return;
      const ts = Date.now();

      const replyId = Number(replyToId);
      const doInsert = (replyMeta = {}) => {
        const replyUser = replyMeta.user || null;
        const replyText = replyMeta.text || null;
        const replyPk = Number.isInteger(replyMeta.id) ? replyMeta.id : null;

        db.run(
          `INSERT INTO dm_messages (thread_id, user_id, username, text, ts, reply_to_id, reply_to_user, reply_to_text, attachment_url, attachment_mime, attachment_type, attachment_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [tid, socket.user.id, socket.user.username, body, ts, replyPk, replyUser, replyText],
          function (insertErr) {
            if (insertErr) return;
            const payload = {
              threadId: tid,
              messageId: this.lastID,
              userId: socket.user.id,
              user: socket.user.username,
              text: body,
              ts,
                          attachmentUrl: attUrl,
            attachmentMime: attMime,
            attachmentType: attType,
            attachmentSize: attSize,
replyToId: replyPk,
              replyToUser: replyUser || "",
              replyToText: replyText || "",
            };
              db.run(
                `UPDATE dm_threads SET last_message_id=?, last_message_at=? WHERE id=?`,
                [this.lastID, ts, tid]
              );
              console.log(`[dm:send] thread ${tid} msg ${this.lastID} by user ${socket.user.id}`);
              io.to(`dm:${tid}`).emit("dm message", payload);
            }
          );
        };

      if (Number.isInteger(replyId)) {
        db.get(
          `SELECT id, username, text FROM dm_messages WHERE id = ? AND thread_id = ?`,
          [replyId, tid],
          (_e, row) => {
            doInsert(row || {});
          }
        );
      } else {
        doInsert();
      }
    });
  });

    // ---- DM edit message (self-only, short window)
  socket.on("dm edit message", ({ threadId, messageId, text }) => {
    const tid = Number(threadId);
    const mid = Number(messageId);
    const body = String(text || "").trim().slice(0, 2000);
    if (!socket.user) return;
    if (!Number.isInteger(tid) || !Number.isInteger(mid) || !body) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err || !thread) return;

      db.get(
        `SELECT id, thread_id, user_id, ts FROM dm_messages WHERE id = ? AND thread_id = ?`,
        [mid, tid],
        (e2, row) => {
          if (e2 || !row) return;

          const isOwner = Number(row.user_id) === Number(socket.user.id);
          if (!isOwner) return;

          const now = Date.now();
          const ts = Number(row.ts) || 0;
          if (now - ts > 5 * 60 * 1000) return;

          db.run(
            `UPDATE dm_messages SET text = ?, edited_at = ? WHERE id = ?`,
            [body, now, mid],
            () => {
              io.to(`dm:${tid}`).emit("dm message edited", {
                threadId: tid,
                messageId: mid,
                text: body,
                editedAt: now
              });
            }
          );
        }
      );
    });
  });

  // ---- DM reactions (1 reaction per user per DM message)
  socket.on("dm reaction", ({ threadId, messageId, emoji }) => {
    const tid = Number(threadId);
    const mid = Number(messageId);
    const em = String(emoji || "").slice(0, 8);
    if (!socket.user) return;
    if (!Number.isInteger(tid) || !Number.isInteger(mid) || !em) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err || !thread) return;

      db.run(
        `INSERT INTO dm_reactions (thread_id, message_id, username, emoji)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(thread_id, message_id, username) DO UPDATE SET emoji=excluded.emoji`,
        [tid, mid, socket.user.username, em],
        () => {
          db.all(
            `SELECT username, emoji FROM dm_reactions WHERE thread_id=? AND message_id=?`,
            [tid, mid],
            (_e, rows) => {
              const reactions = {};
              for (const r of rows || []) reactions[r.username] = r.emoji;
              io.to(`dm:${tid}`).emit("dm reaction update", { threadId: tid, messageId: mid, reactions });
            }
          );
        }
      );
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

  // ---- Edit message (self-only, short window)
  socket.on("edit message", ({ messageId, text }) => {
    const mid = Number(messageId);
    const body = String(text || "").trim().slice(0, 2000);
    if (!socket.user) return;
    if (!Number.isInteger(mid) || !body) return;

    db.get(
      `SELECT id, room, user_id, ts, deleted FROM messages WHERE id = ?`,
      [mid],
      (err, row) => {
        if (err || !row || Number(row.deleted || 0) === 1) return;

        const isOwner = Number(row.user_id) === Number(socket.user.id);
        if (!isOwner) return;

        const now = Date.now();
        const ts = Number(row.ts) || 0;
        if (now - ts > 5 * 60 * 1000) return;

        db.run(
          `UPDATE messages SET text = ?, edited_at = ? WHERE id = ?`,
          [body, now, mid],
          () => {
            io.to(String(row.room)).emit("message edited", {
              messageId: mid,
              text: body,
              editedAt: now
            });
          }
        );
      }
    );
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
    db.get("SELECT id, username, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

      io.to(room).emit("system", `${username} was kicked.`);
      logModAction({ actor: socket.user, action: "KICK", targetUserId: target.id, targetUsername: target.username, room });
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

    db.get("SELECT id, username, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
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
            targetUsername: target.username,
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
            targetUsername: target.username,
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
          targetUsername: target.username,
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
          targetUsername: target.username,
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
	    db.get("SELECT id, username, role FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      io.to(room).emit("system", `${username} was warned: ${String(reason || "").slice(0, 120)}`);
      logModAction({
        actor: socket.user,
        action: "WARN",
        targetUserId: target.id,
        targetUsername: target.username,
        room,
        details: String(reason || "").slice(0, 180),
      });
    });
  });

  socket.on("mod set role", ({ username, role, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actor = socket.user;
    const actorRole = godmodeUsers.has(actor.id)
      ? "Owner"
      : (socket.user?.role || socket.request?.session?.user?.role || "User");

    // Admin+ can update roles via the moderation panel.
    if (!requireMinRole(actorRole, "Admin")) return;

    const rawName = String(username || "").trim().slice(0, 64);
    const sanitized = sanitizeUsername(rawName);
    role = String(role || "").trim();

    const normalizedRole = ROLES.find((r) => r.toLowerCase() === role.toLowerCase());
    if (!normalizedRole) return;
    role = normalizedRole;

    const lookupName = rawName || sanitized;
    if (!lookupName) return;

    db.get(
      "SELECT id, username, role as oldRole FROM users WHERE lower(username)=lower(?) LIMIT 1",
      [lookupName], (_e, target) => {
      if (!target) return;

      // Permission checks: you can only modify users below you.
      if (actorRole !== "Owner" && !canModerate(actorRole, target.oldRole)) return;

      // Prevent non-owners from assigning roles at/above themselves (or Admin+).
      if (actorRole !== "Owner") {
        if (roleRank(role) >= roleRank(actorRole)) return;
        if (roleRank(role) >= roleRank("Admin")) return;
      }

      setRoleEverywhere(target.id, target.username, role).then(() => {
        logModAction({
          actor: socket.user,
          action: "SET_ROLE",
          targetUserId: target.id,
          targetUsername: target.username,
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

        io.to(room).emit("system", `${target.username} role set to ${role}.`);
        emitUserList(room);
      }).catch((e) => {
        console.error("[mod set role]", e);
      });
    });
  });

  socket.on("disconnect", () => {
    // socket.user is attached after successful auth; guard for anonymous / early disconnects
    if (socket.user?.username) ONLINE_USERS.delete(socket.user.username);
    emitOnlineUsers();

    const room = socket.currentRoom;

    // Always clear per-socket rate tracking
    msgRate.delete(socket.id);

    // Only clear per-user mappings if THIS socket is still the active one
    if (socket.user?.id && socketIdByUserId.get(socket.user.id) === socket.id) {
      socketIdByUserId.delete(socket.user.id);
      onlineState.delete(socket.user.id);
      onlineXpTrack.delete(socket.user.id);
    }

    // last_seen + typing indicators only apply to authenticated users
    if (socket.user?.id) {
      db.run("UPDATE users SET last_seen=? WHERE id=?", [Date.now(), socket.user.id]);
    }

    if (room) {
      const set = typingByRoom.get(room);
      if (set) {
        if (socket.user?.username) set.delete(socket.user.username);
        broadcastTyping(room);
      }
      emitUserList(room);
    }
  });
  });

  // ---- Start
  Promise.allSettled([migrationsReady, pgInitPromise]).then((results) => {
    const [sqliteResult, pgResult] = results;
    if (sqliteResult.status === "rejected") {
      console.error("[startup] SQLite migration failed", sqliteResult.reason);
      process.exit(1);
    }
    if (pgResult.status === "rejected") {
      console.error("[startup] Postgres init failed", pgResult.reason);
    }

    httpServer.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  });


function areIrisAndLolaOnline() {
  return ONLINE_USERS.has("Iri") && ONLINE_USERS.has("Lola Henderson");
}

function canUseTheme(user, themeName) {
  const rule = PRIVATE_THEME_ALLOWLIST[themeName];
  if (rule) {
    if (!rule.users.includes(user.username)) return false;
    if (rule.requireBothOnline && !areIrisAndLolaOnline()) return false;
    return true;
  }
  return true;
}