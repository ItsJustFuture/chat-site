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
    userIds: [],
    requireBothOnline: false
  }
};

const ONLINE_USERS = new Set();


// --- Owner session map (in-memory)
const sessionMetaBySocketId = new Map(); // socket.id -> meta
const sessionByUserId = new Map(); // userId -> Set(socket.id)
const DICE_ROLL_MIN_INTERVAL_MS = 1000;
const diceRollRateByUserId = new Map();
const SURVIVAL_ROOM_ID = "survivalsimulator";
const SURVIVAL_ROOM_DB_ID = 1;
const CORE_ROOMS = [
  { name: "main", sortOrder: 0 },
  { name: "music", sortOrder: 1 },
  { name: "nsfw", sortOrder: 2 },
  { name: "diceroom", sortOrder: 3 },
  { name: "survivalsimulator", sortOrder: 4 },
];
const CORE_ROOM_NAMES = new Set(CORE_ROOMS.map((room) => room.name));
const SURVIVAL_SEASON_COOLDOWN_MS = 2 * 60 * 1000;
const SURVIVAL_ADVANCE_COOLDOWN_MS = 2000;
const CHESS_DEFAULT_ELO = 1200;
const CHESS_MIN_PLIES_RATED = 6;
const CHESS_SEAT_CLAIM_TIMEOUT_MS = 10 * 60 * 1000;

// Auto-fill NPC pool: 25 male + 25 female (big recognizable names; used only for NPC slots).
// NOTE: Keep this list PG and non-offensive.
const SURVIVAL_AUTOFILL_POOL = {
  female: [
    "Taylor Swift","Beyonce","Rihanna","Ariana Grande","Lady Gaga",
    "Selena Gomez","Billie Eilish","Dua Lipa","Katy Perry","Adele",
    "Miley Cyrus","Jennifer Lawrence","Emma Stone","Scarlett Johansson","Zendaya",
    "Margot Robbie","Emma Watson","Natalie Portman","Gal Gadot","Angelina Jolie",
    "Shakira","Cardi B","Nicki Minaj","Serena Williams","Oprah Winfrey",
  ],
  male: [
    "Dwayne Johnson","Chris Hemsworth","Leonardo DiCaprio","Tom Holland","Ryan Reynolds",
    "Keanu Reeves","Robert Downey Jr.","Brad Pitt","Will Smith","Johnny Depp",
    "Tom Cruise","Jason Momoa","Chris Evans","Michael B. Jordan","Drake",
    "Ed Sheeran","Justin Bieber","Harry Styles","The Weeknd","Bruno Mars",
    "Lionel Messi","Cristiano Ronaldo","LeBron James","Stephen Curry","Elon Musk",
  ],
};
const survivalSeasonCooldownByRoom = new Map();
const survivalAdvanceCooldownBySeason = new Map();

// Survival lobby (opt-in list) — in-memory, per room. Used to quickly add participants.
const survivalLobbyByRoom = new Map(); // roomDbId -> Set<userId>
function getSurvivalLobbySet(roomDbId){
  if(!survivalLobbyByRoom.has(roomDbId)) survivalLobbyByRoom.set(roomDbId, new Set());
  return survivalLobbyByRoom.get(roomDbId);
}
const qualifyingMsgWindowByUserId = new Map();
const rollCadenceWindowByUserId = new Map();

// --- Behaviour heat score (in-memory; admin/owner only)
const heatByUserId = new Map(); // userId -> number
const lastRoomHopByUserId = new Map(); // userId -> {room, ts}
const lastMentionByUserId = new Map(); // userId -> ts
const lastReactionByUserId = new Map(); // userId -> ts

// --- Room events (in-memory, roomName -> {type,title,endsAt,startedBy})
const ACTIVE_ROOM_EVENTS = new Map();
let ROOM_EVENT_SEQ = 1;
const ROOM_PROMPT_TEMPLATES = [
  "What’s a small win you had this week?",
  "Share a comfort movie or show you love.",
  "What song do you have on repeat right now?",
  "What’s a simple joy you want more of lately?",
  "Drop a cozy weekend plan in one sentence.",
  "What’s something new you want to try this month?",
  "Describe today in three words.",
];

function pruneWindowTimestamps(list, now, windowMs) {
  const cutoff = now - windowMs;
  while (list.length && list[0] < cutoff) list.shift();
  return list;
}

function getQualifyingMessageCount(uid, now) {
  const list = qualifyingMsgWindowByUserId.get(uid) || [];
  pruneWindowTimestamps(list, now, LUCK_MESSAGE_WINDOW_MS);
  qualifyingMsgWindowByUserId.set(uid, list);
  return list.length;
}

function recordQualifyingMessage(uid, now) {
  const list = qualifyingMsgWindowByUserId.get(uid) || [];
  pruneWindowTimestamps(list, now, LUCK_MESSAGE_WINDOW_MS);
  list.push(now);
  qualifyingMsgWindowByUserId.set(uid, list);
  return list.length;
}

function updateRollCadenceWindow(uid, now) {
  const list = rollCadenceWindowByUserId.get(uid) || [];
  list.push(now);
  while (list.length > LUCK_CADENCE_WINDOW) list.shift();
  rollCadenceWindowByUserId.set(uid, list);
  return list;
}

function isCadenceFlagged(uid, now, rollStreak, lastQualMsgAt) {
  const list = updateRollCadenceWindow(uid, now);
  if (rollStreak < 6 || list.length < 5) return false;
  if (lastQualMsgAt && now - Number(lastQualMsgAt || 0) < LUCK_RECENT_BREAK_WINDOW_MS) return false;
  const intervals = [];
  for (let i = 1; i < list.length; i += 1) {
    intervals.push(list[i] - list[i - 1]);
  }
  if (!intervals.length) return false;
  const mean = intervals.reduce((sum, n) => sum + n, 0) / intervals.length;
  if (mean > LUCK_CADENCE_MEAN_MAX_MS) return false;
  const variance =
    intervals.reduce((sum, n) => sum + Math.pow(n - mean, 2), 0) / intervals.length;
  const stddev = Math.sqrt(variance);
  return stddev <= LUCK_CADENCE_STDDEV_THRESHOLD_MS;
}

function emitLuckUpdate(uid, luck, rollStreak) {
  emitToUserIds(uid, "luck:update", { luck, rollStreak, ts: Date.now() });
}

function emitToUserIds(userIds, event, payload) {
  const ids = Array.isArray(userIds) ? userIds : [userIds];
  for (const uidRaw of ids) {
    const uid = Number(uidRaw) || 0;
    if (!uid) continue;
    const sockets = sessionByUserId.get(uid);
    if (sockets && sockets.size) {
      for (const sid of sockets) {
        io.to(sid).emit(event, payload);
      }
    } else {
      const sid = socketIdByUserId.get(uid);
      if (sid) io.to(sid).emit(event, payload);
    }
  }
}



function bumpHeat(userId, delta = 1) {
  const d = Math.max(0, Number(delta) || 0);
  if (!userId || !d) return;
  const prev = heatByUserId.get(userId) || 0;
  const next = Math.min(100, prev + d);
  heatByUserId.set(userId, next);
}

function decayHeat() {
  for (const [uid, val] of heatByUserId.entries()) {
    const next = Math.max(0, Math.floor(val * 0.92)); // gentle decay
    if (next <= 0) heatByUserId.delete(uid);
    else heatByUserId.set(uid, next);
  }
}
setInterval(decayHeat, 60_000).unref?.();




const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { Chess } = require("chess.js");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { Pool } = require("pg");
const http = require("http");
const {
  DICE_VARIANTS,
  DICE_VARIANT_LABELS,
  normalizeDiceVariant,
  rollDiceVariantWithLuck,
  isLuckWin,
  computeDiceReward,
} = require("./dice-utils");
const {
  LUCK_MESSAGE_MIN_LEN,
  LUCK_MESSAGE_WINDOW_MS,
  LUCK_REPEAT_WINDOW_MS,
  LUCK_CADENCE_WINDOW,
  LUCK_CADENCE_STDDEV_THRESHOLD_MS,
  LUCK_CADENCE_MEAN_MAX_MS,
  LUCK_CADENCE_PENALTY,
  LUCK_RECENT_BREAK_WINDOW_MS,
  clampLuck,
  hashLuckMessage,
  computeQualifyingLuckGain,
  computeRollStreakPenalty,
  applyWinCut,
  normalizeLuckMessage,
} = require("./luck-utils");
const { SURVIVAL_EVENT_TEMPLATES, SURVIVAL_ITEM_POOL } = require("./survival-events");

// ---- Safety nets (prevents silent crashes in prod) ----
process.on("unhandledRejection", (err) => {
  console.error("[unhandledRejection]", err);
});
process.on("uncaughtException", (err) => {
  console.error("[uncaughtException]", err);
});
const { Server } = require("socket.io");
const { db, migrationsReady, seedDevUser, DB_FILE } = require("./database");
const { VIBE_TAGS, VIBE_TAG_LIMIT } = require("./vibe-tags");

const MEMORY_SYSTEM_ENABLED = process.env.MEMORY_SYSTEM_ENABLED === "1";
const MEMORY_SYSTEM_ALLOWLIST = new Set(
  String(process.env.MEMORY_SYSTEM_ALLOWLIST || "")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean)
);

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const CAPTCHA_PROVIDER = String(process.env.CAPTCHA_PROVIDER || "none").trim().toLowerCase();
const CAPTCHA_SITE_KEY = String(process.env.CAPTCHA_SITE_KEY || "").trim();
const CAPTCHA_SECRET_KEY = String(process.env.CAPTCHA_SECRET_KEY || "").trim();
const ALLOWED_ORIGINS = new Set(
  String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

const LOCAL_DEV = process.env.LOCAL_DEV === "1";
const NODE_ENV = process.env.NODE_ENV || "development";
// ---- Startup sanity checks (fail fast in production)
const IS_PROD = NODE_ENV === "production" && !LOCAL_DEV;
const IS_DEV_MODE = LOCAL_DEV || NODE_ENV === "development" || NODE_ENV === "test";
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

    // Origin allowlist for Socket.IO handshake
    allowRequest: (req, cb) => {
      try {
        const origin = req.headers.origin;
        const host = req.headers.host;
        if (!origin) {
          return cb(null, !IS_PROD);
        }
        return cb(null, isAllowedOrigin(origin, host));
      } catch {
        return cb(null, false);
      }
    },

    // More tolerant of mobile/background + Render sleep
    pingInterval: 25_000,  // send pings every 25s
    pingTimeout: 300_000,  // wait 5 minutes for pong before disconnect (mobile suspend)
    upgradeTimeout: 45_000,
  });

  const DEBUG_ROOMS = String(process.env.DEBUG_ROOMS || "").toLowerCase() === "true";

  // ---- System messages (room-scoped)
  // Historically the server emitted plain strings on the "system" event.
  // Some client UIs keep a single visible log and can accidentally render
  // a system message that was meant for another room.
  //
  // For room-scoped system messages, we now emit an explicit payload
  // { room, text, meta? } so the client can route it correctly.
  function buildSystemPayload(room, text, meta, scope) {
    const ts = Date.now();
    const payload = {
      id: `sys-${ts}-${Math.random().toString(36).slice(2, 8)}`,
      ts,
      room: String(room || ""),
      type: "system",
      text: String(text ?? ""),
    };
    const resolvedScope = String(scope || (payload.room === "__global__" ? "global" : (payload.room ? "room" : "")));
    if (resolvedScope) payload.scope = resolvedScope;
    if (meta && typeof meta === "object") payload.meta = meta;
    return payload;
  }

  function emitRoomSystem(room, text, meta) {
    const r = typeof room === "string" ? room : "";
    if (!r) return;
    const payload = buildSystemPayload(r, text, meta, "room");
    // IMPORTANT: Some historical code paths can leave a socket joined to a room
    // even after its "currentRoom" changes (e.g., legacy "#room" mismatches or
    // reconnect races). If we emit to the Socket.IO room directly, those stale
    // memberships can cause system messages to "bleed" into other rooms.
    //
    // To hard-stop bleeding, emit only to sockets that explicitly report being
    // in that room.
    try {
      for (const s of io.sockets.sockets.values()) {
        if (s?.currentRoom === r || s?.data?.currentRoom === r) {
          s.emit("system", payload);
        }
      }
    } catch {
      // Fallback to room emit if iteration fails for any reason.
      io.to(r).emit("system", payload);
    }
    if (DEBUG_ROOMS) {
      console.log("[rooms] system emit", { room: r, text: payload.text, meta: payload.meta || null });
    }
  }

  function emitGlobalSystem(text, meta) {
    // Global system messages must be explicitly marked as such so clients can
    // safely ignore accidental global emissions (prevents room bleed).
    const m = (meta && typeof meta === "object") ? { ...meta } : {};
    if (!m.kind) m.kind = "global";
    const payload = buildSystemPayload("__global__", text, m, "global");
    io.emit("system", payload);
    if (DEBUG_ROOMS) {
      console.log("[rooms] system emit", { room: "__global__", text: payload.text, meta: payload.meta || null });
    }
  }
const PG_ENABLED = Boolean(process.env.DATABASE_URL);
const pgPool = PG_ENABLED
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false,
    })
  : null;
if (!PG_ENABLED && IS_DEV_MODE) {
  console.warn("[db] PG unavailable, using SQLite dev fallback:", DB_FILE);
}
let DB_BACKEND = "sqlite";
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

  // If the column has a default that can't be cast to BIGINT (common on legacy timestamp defaults),
  // the ALTER TYPE will fail. Drop the default first (best-effort).
  try {
    await pgPool.query(`ALTER TABLE ${tableName} ALTER COLUMN ${columnName} DROP DEFAULT`);
  } catch (_) {}

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
let COUPLES_READY = false;
let FRIENDS_READY = false;
let PG_INIT_ERROR = null;
// ---- Postgres table setup
// Run once on boot, and start the server only after this finishes (so schema/type fixes apply before /register).
const pgInitPromise = PG_ENABLED ? (async () => {
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
        room_master_collapsed TEXT NOT NULL DEFAULT '{}',
        room_category_collapsed TEXT NOT NULL DEFAULT '{}',
        gold INTEGER NOT NULL DEFAULT 0,
        xp INTEGER NOT NULL DEFAULT 0,
        lastMessageXpAt BIGINT,
        lastLoginXpAt BIGINT,
        lastOnlineXpAt BIGINT,
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

      CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS room_master_categories (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS room_categories (
        id SERIAL PRIMARY KEY,
        master_id INTEGER NOT NULL REFERENCES room_master_categories(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        UNIQUE(master_id, name)
      );
      CREATE TABLE IF NOT EXISTS rooms (
        name TEXT PRIMARY KEY,
        created_by INTEGER,
        created_at BIGINT NOT NULL,
        slowmode_seconds INTEGER NOT NULL DEFAULT 0,
        is_locked INTEGER NOT NULL DEFAULT 0,
        pinned_message_ids TEXT,
        maintenance_mode INTEGER NOT NULL DEFAULT 0,
        vip_only INTEGER NOT NULL DEFAULT 0,
        staff_only INTEGER NOT NULL DEFAULT 0,
        min_level INTEGER NOT NULL DEFAULT 0,
        events_enabled INTEGER NOT NULL DEFAULT 1,
        archived INTEGER NOT NULL DEFAULT 0,
        category_id INTEGER REFERENCES room_categories(id) ON DELETE SET NULL,
        room_sort_order INTEGER NOT NULL DEFAULT 0,
        created_by_user_id INTEGER,
        is_user_room INTEGER NOT NULL DEFAULT 0,
        is_system INTEGER NOT NULL DEFAULT 0
      );
    `);

    const roomCols = [
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS slowmode_seconds INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS is_locked INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS pinned_message_ids TEXT`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS maintenance_mode INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS category_id INTEGER`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS room_sort_order INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS created_by_user_id INTEGER`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS is_user_room INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS vip_only INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS staff_only INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS min_level INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS events_enabled INTEGER NOT NULL DEFAULT 1`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS archived INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE rooms ADD COLUMN IF NOT EXISTS is_system INTEGER NOT NULL DEFAULT 0`,
    ];
    for (const q of roomCols) {
      try { await pgPool.query(q); } catch (_) {}
    }

    try {
      const now = Date.now();
      await pgPool.query(
        `INSERT INTO room_master_categories (name, sort_order, created_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (name) DO NOTHING`,
        ["Site Rooms", 0, now]
      );
      await pgPool.query(
        `INSERT INTO room_master_categories (name, sort_order, created_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (name) DO NOTHING`,
        ["User Rooms", 1, now]
      );
      const { rows: masterRows } = await pgPool.query(
        `SELECT id, name FROM room_master_categories WHERE name IN ('Site Rooms', 'User Rooms')`
      );
      for (const master of masterRows || []) {
        await pgPool.query(
          `INSERT INTO room_categories (master_id, name, sort_order, created_at)
           VALUES ($1, 'Uncategorized', 0, $2)
           ON CONFLICT (master_id, name) DO NOTHING`,
          [master.id, now]
        );
      }
    } catch (e) {
      console.warn("[pg-init] room hierarchy seed failed:", e?.message || e);
    }

    try {
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_room_categories_master_sort ON room_categories(master_id, sort_order)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_rooms_category_sort ON rooms(category_id, room_sort_order)`);
    } catch (e) {
      console.warn("[pg-init] room hierarchy indexes failed:", e?.message || e);
    }

    try {
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS mod_cases (
          id SERIAL PRIMARY KEY,
          type TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          priority TEXT NOT NULL DEFAULT 'normal',
          subject_user_id INTEGER,
          created_by_user_id INTEGER,
          assigned_to_user_id INTEGER,
          room_id TEXT,
          title TEXT,
          summary TEXT,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL,
          closed_at BIGINT,
          closed_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS mod_case_events (
          id SERIAL PRIMARY KEY,
          case_id INTEGER NOT NULL REFERENCES mod_cases(id) ON DELETE CASCADE,
          actor_user_id INTEGER,
          event_type TEXT NOT NULL,
          event_payload JSONB,
          created_at BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mod_case_notes (
          id SERIAL PRIMARY KEY,
          case_id INTEGER NOT NULL REFERENCES mod_cases(id) ON DELETE CASCADE,
          author_user_id INTEGER,
          body TEXT NOT NULL,
          created_at BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mod_case_evidence (
          id SERIAL PRIMARY KEY,
          case_id INTEGER NOT NULL REFERENCES mod_cases(id) ON DELETE CASCADE,
          evidence_type TEXT NOT NULL,
          room_id TEXT,
          message_id INTEGER,
          message_excerpt TEXT,
          url TEXT,
          text TEXT,
          created_by_user_id INTEGER,
          created_at BIGINT NOT NULL
        );
      `);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_mod_cases_status ON mod_cases(status)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_mod_cases_type ON mod_cases(type)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_mod_case_events_case ON mod_case_events(case_id)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_mod_case_notes_case ON mod_case_notes(case_id)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_mod_case_evidence_case ON mod_case_evidence(case_id)`);
    } catch (e) {
      console.warn("[pg-init] mod cases tables failed:", e?.message || e);
    }

    try {
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS room_structure_audit (
          id SERIAL PRIMARY KEY,
          action TEXT NOT NULL,
          actor_user_id INTEGER,
          payload JSONB,
          created_at BIGINT NOT NULL
        );
      `);
    } catch (e) {
      console.warn("[pg-init] room audit table failed:", e?.message || e);
    }

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
      CREATE TABLE IF NOT EXISTS changelog_reactions (
        entry_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reaction TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        CONSTRAINT changelog_reactions_unique UNIQUE(entry_id, user_id, reaction)
      );
      CREATE INDEX IF NOT EXISTS idx_changelog_react_entry ON changelog_reactions(entry_id);
      CREATE INDEX IF NOT EXISTS idx_changelog_react_user ON changelog_reactions(user_id);
    `);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS faq_questions (
        id SERIAL PRIMARY KEY,
        created_at BIGINT,
        question_title TEXT NOT NULL,
        question_details TEXT,
        answer_body TEXT,
        answered_at BIGINT,
        answered_by INTEGER,
        is_deleted INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS faq_reactions (
        question_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        reaction_key TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        CONSTRAINT faq_reactions_unique UNIQUE(question_id, username, reaction_key)
      );
      CREATE INDEX IF NOT EXISTS idx_faq_react_question ON faq_reactions(question_id);
    `);

    // Track profile likes in Postgres so we can keep counts consistent across PG-first reads.
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS profile_likes (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        target_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at BIGINT NOT NULL,
        CONSTRAINT profile_likes_unique UNIQUE(user_id, target_user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_profile_likes_target ON profile_likes(target_user_id);
      CREATE INDEX IF NOT EXISTS idx_profile_likes_user ON profile_likes(user_id);
    `);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS chess_user_stats (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        chess_elo INTEGER NOT NULL DEFAULT 1200,
        chess_games_played INTEGER NOT NULL DEFAULT 0,
        chess_wins INTEGER NOT NULL DEFAULT 0,
        chess_losses INTEGER NOT NULL DEFAULT 0,
        chess_draws INTEGER NOT NULL DEFAULT 0,
        chess_peak_elo INTEGER NOT NULL DEFAULT 1200,
        chess_last_game_at BIGINT,
        updated_at BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS chess_games (
        game_id TEXT PRIMARY KEY,
        context_type TEXT NOT NULL,
        context_id TEXT NOT NULL,
        white_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        black_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        fen TEXT NOT NULL,
        pgn TEXT NOT NULL,
        status TEXT NOT NULL,
        turn TEXT NOT NULL,
        result TEXT,
        rated BOOLEAN,
        rated_reason TEXT,
        plies_count INTEGER NOT NULL DEFAULT 0,
        draw_offer_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        draw_offer_at BIGINT,
        white_elo_change INTEGER,
        black_elo_change INTEGER,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        last_move_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS chess_challenges (
        challenge_id TEXT PRIMARY KEY,
        dm_thread_id INTEGER NOT NULL,
        challenger_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        challenged_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_chess_games_context ON chess_games(context_type, context_id);
      CREATE INDEX IF NOT EXISTS idx_chess_games_status ON chess_games(status);
      CREATE INDEX IF NOT EXISTS idx_chess_challenges_thread ON chess_challenges(dm_thread_id);
      CREATE INDEX IF NOT EXISTS idx_chess_challenges_status ON chess_challenges(status);
    `);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS memories (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        room_id TEXT,
        type TEXT NOT NULL,
        key TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        icon TEXT,
        created_at BIGINT NOT NULL,
        metadata JSONB,
        visibility TEXT NOT NULL DEFAULT 'private',
        pinned BOOLEAN NOT NULL DEFAULT false,
        seen BOOLEAN NOT NULL DEFAULT false
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_user_key ON memories(user_id, key);
      CREATE INDEX IF NOT EXISTS idx_memories_user_created ON memories(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_memories_user_pinned ON memories(user_id, pinned);

      CREATE TABLE IF NOT EXISTS memory_settings (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        enabled BOOLEAN NOT NULL DEFAULT false,
        last_seen_at BIGINT
      );
    `);

    // Centralized gold spending ledger so spend reasons can be audited later.
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS gold_transactions (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at BIGINT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_gold_transactions_user ON gold_transactions(user_id);
      CREATE INDEX IF NOT EXISTS idx_gold_transactions_created ON gold_transactions(created_at DESC);
    `);

    // Daily micro-challenges progress (per-user, per-day)
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS daily_challenge_progress (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        day_key TEXT NOT NULL,
        progress_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        claimed_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, day_key)
      );
      CREATE INDEX IF NOT EXISTS idx_daily_challenge_progress_user ON daily_challenge_progress(user_id);
      CREATE INDEX IF NOT EXISTS idx_daily_challenge_progress_day ON daily_challenge_progress(day_key);
    `);



    // Best-effort backfill of legacy SQLite likes into Postgres so leaderboards/profile counts stay consistent.
    try {
      const sqliteLikes = await dbAllAsync("SELECT user_id, target_user_id, created_at FROM profile_likes");
      for (const row of sqliteLikes || []) {
        await pgPool.query(
          `INSERT INTO profile_likes (user_id, target_user_id, created_at)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id, target_user_id) DO NOTHING`,
          [row.user_id, row.target_user_id, row.created_at]
        );
      }
    } catch (e) {
      console.warn("[pg backfill] profile_likes:", e?.message || e);
    }
// Fix camelCase columns that Postgres lowercased previously
// ---- Fix camelCase timestamp columns Postgres lowercased
try {
  await pgEnsureCamelColumn("users", "lastGoldTickAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastMessageGoldAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastDailyLoginGoldAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastXpMessageAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastMessageXpAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastLoginXpAt", "BIGINT");
  await pgEnsureCamelColumn("users", "lastOnlineXpAt", "BIGINT");
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
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS room_master_collapsed TEXT NOT NULL DEFAULT '{}'`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS room_category_collapsed TEXT NOT NULL DEFAULT '{}'`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS gold INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastMessageXpAt" BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastLoginXpAt" BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastOnlineXpAt" BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastXpMessageAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastGoldTickAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastMessageGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDailyLoginGoldAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS lastDiceRollAt BIGINT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS dice_sixes INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS luck DOUBLE PRECISION NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS roll_streak INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_qual_msg_hash TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_qual_msg_at BIGINT`,
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



// --- Kick/Ban restrictions + appeals (persistent)
try {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS user_restrictions (
      username TEXT PRIMARY KEY,
      restriction_type TEXT NOT NULL DEFAULT 'none', -- 'none'|'kick'|'ban'
      reason TEXT,
      set_by TEXT,
      set_at BIGINT NOT NULL,
      expires_at BIGINT,
      updated_at BIGINT NOT NULL
    )
  `);

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS moderation_actions (
      id SERIAL PRIMARY KEY,
      target_username TEXT NOT NULL,
      actor_username TEXT,
      action_type TEXT NOT NULL,
      reason TEXT,
      duration_seconds INTEGER,
      expires_at BIGINT,
      created_at BIGINT NOT NULL
    )
  `);

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS appeals (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      restriction_type TEXT NOT NULL, -- 'kick'|'ban'
      reason_at_time TEXT,
      status TEXT NOT NULL DEFAULT 'open', -- 'open'|'resolved'|'closed'
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL,
      last_admin_reply_at BIGINT,
      last_user_reply_at BIGINT
    )
  `);
  await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_appeals_status ON appeals(status)`);
  await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_appeals_username ON appeals(username)`);

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS appeal_messages (
      id SERIAL PRIMARY KEY,
      appeal_id INTEGER NOT NULL REFERENCES appeals(id) ON DELETE CASCADE,
      author_role TEXT NOT NULL, -- 'user'|'admin'
      author_name TEXT,
      message TEXT NOT NULL,
      created_at BIGINT NOT NULL
    )
  `);
  await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_appeal_messages_appeal ON appeal_messages(appeal_id)`);

  // Single OPEN appeal per user (best-effort; if already exists, ignore)
  try {
    await pgPool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_open_appeal_per_user ON appeals(username) WHERE status='open'`);
  } catch {}
} catch (e) {
  console.warn("[pg-init] restrictions/appeals tables failed:", e?.message || e);
}
  // --- Couples (opt-in linked profiles)
  try {
    // Adapt to existing DBs where users.id may be INTEGER or BIGINT
    const { rows: idInfo } = await pgPool.query(
      `SELECT udt_name FROM information_schema.columns WHERE table_name='users' AND column_name='id' LIMIT 1`
    );
    const udt = (idInfo?.[0]?.udt_name || '').toLowerCase();
    const ID_TYPE = (udt == 'int8' || udt == 'bigint') ? 'BIGINT' : 'INTEGER';

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS couple_links (
        id SERIAL PRIMARY KEY,
        user1_id ${ID_TYPE} NOT NULL,
        user2_id ${ID_TYPE} NOT NULL,
        requested_by_id ${ID_TYPE},
        status TEXT NOT NULL DEFAULT 'pending', -- pending | active
        status_emoji TEXT NOT NULL DEFAULT '💜',
        status_label TEXT NOT NULL DEFAULT 'Linked',
        privacy TEXT NOT NULL DEFAULT 'private',
        couple_name TEXT,
        couple_bio TEXT,
        settings_json TEXT,
        show_badge BOOLEAN NOT NULL DEFAULT true,
        bonuses_enabled BOOLEAN NOT NULL DEFAULT false,
        created_at BIGINT NOT NULL,
        activated_at BIGINT,
        updated_at BIGINT NOT NULL
      )
    `);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS privacy TEXT NOT NULL DEFAULT 'private'`);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS couple_name TEXT`);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS couple_bio TEXT`);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS settings_json TEXT`);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS show_badge BOOLEAN NOT NULL DEFAULT true`);
    await pgPool.query(`ALTER TABLE couple_links ADD COLUMN IF NOT EXISTS bonuses_enabled BOOLEAN NOT NULL DEFAULT false`);

    // Best-effort FK constraints (may fail if legacy schemas differ); couples will still work without them.
    try {
      await pgPool.query(`ALTER TABLE couple_links ADD CONSTRAINT couple_links_user1_fk FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE`);
    } catch {}
    try {
      await pgPool.query(`ALTER TABLE couple_links ADD CONSTRAINT couple_links_user2_fk FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE`);
    } catch {}
    try {
      await pgPool.query(`ALTER TABLE couple_links ADD CONSTRAINT couple_links_requested_by_fk FOREIGN KEY (requested_by_id) REFERENCES users(id) ON DELETE SET NULL`);
    } catch {}

    await pgPool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_couple_pair ON couple_links(user1_id, user2_id)`);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS couple_prefs (
        link_id INTEGER NOT NULL REFERENCES couple_links(id) ON DELETE CASCADE,
        user_id ${ID_TYPE} NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT true,
        show_profile BOOLEAN NOT NULL DEFAULT true,
        show_members BOOLEAN NOT NULL DEFAULT true,
        group_members BOOLEAN NOT NULL DEFAULT false,
        aura BOOLEAN NOT NULL DEFAULT true,
        badge BOOLEAN NOT NULL DEFAULT true,
        allow_ping BOOLEAN NOT NULL DEFAULT true,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (link_id, user_id)
      )
    `);
    await pgPool.query(`ALTER TABLE couple_prefs ADD COLUMN IF NOT EXISTS allow_ping BOOLEAN NOT NULL DEFAULT true`);
    try {
      await pgPool.query(`ALTER TABLE couple_prefs ADD CONSTRAINT couple_prefs_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`);
    } catch {}

    COUPLES_READY = true;
  } catch (e) {
    COUPLES_READY = false;
    console.warn('[pg-init] couples tables failed:', e?.message || e);
  }


  // --- Friends (requests + favorites)
  try {
    const { rows: idInfoF } = await pgPool.query(
      `SELECT udt_name FROM information_schema.columns WHERE table_name='users' AND column_name='id' LIMIT 1`
    );
    const udtF = (idInfoF?.[0]?.udt_name || '').toLowerCase();
    const ID_TYPE_F = (udtF == 'int8' || udtF == 'bigint') ? 'BIGINT' : 'INTEGER';

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS friend_requests (
        id SERIAL PRIMARY KEY,
        from_user_id ${ID_TYPE_F} NOT NULL,
        to_user_id ${ID_TYPE_F} NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', -- pending|accepted|declined|cancelled
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      )
    `);

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS friends (
        user_id ${ID_TYPE_F} NOT NULL,
        friend_user_id ${ID_TYPE_F} NOT NULL,
        is_favorite BOOLEAN NOT NULL DEFAULT false,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, friend_user_id)
      )
    `);

    // Best-effort FK constraints
    try { await pgPool.query(`ALTER TABLE friend_requests ADD CONSTRAINT friend_requests_from_fk FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE`); } catch {}
    try { await pgPool.query(`ALTER TABLE friend_requests ADD CONSTRAINT friend_requests_to_fk FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE`); } catch {}
    try { await pgPool.query(`ALTER TABLE friends ADD CONSTRAINT friends_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`); } catch {}
    try { await pgPool.query(`ALTER TABLE friends ADD CONSTRAINT friends_friend_fk FOREIGN KEY (friend_user_id) REFERENCES users(id) ON DELETE CASCADE`); } catch {}

    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_friend_requests_to_status ON friend_requests(to_user_id, status)`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_friend_requests_from_status ON friend_requests(from_user_id, status)`);
    // One pending request per direction
    try { await pgPool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_friend_request_pending ON friend_requests(from_user_id, to_user_id) WHERE status='pending'`); } catch {}

    FRIENDS_READY = true;
  } catch (e) {
    FRIENDS_READY = false;
    console.warn('[pg-init] friends tables failed:', e?.message || e);
  }

  try {
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS survival_seasons (
        id SERIAL PRIMARY KEY,
        room_id INTEGER NOT NULL,
        created_by_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        day_index INTEGER NOT NULL DEFAULT 1,
        phase TEXT NOT NULL DEFAULT 'day',
        rng_seed TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS survival_participants (
        id SERIAL PRIMARY KEY,
        season_id INTEGER NOT NULL REFERENCES survival_seasons(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        display_name TEXT NOT NULL,
        avatar_url TEXT,
        alive INTEGER NOT NULL DEFAULT 1,
        hp INTEGER NOT NULL DEFAULT 100,
        kills INTEGER NOT NULL DEFAULT 0,
        alliance_id INTEGER,
        inventory_json TEXT DEFAULT '[]',
        traits_json TEXT DEFAULT '{}',
        last_event_at BIGINT,
        created_at BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS survival_alliances (
        id SERIAL PRIMARY KEY,
        season_id INTEGER NOT NULL REFERENCES survival_seasons(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS survival_events (
        id SERIAL PRIMARY KEY,
        season_id INTEGER NOT NULL REFERENCES survival_seasons(id) ON DELETE CASCADE,
        day_index INTEGER NOT NULL,
        phase TEXT NOT NULL,
        order_index INTEGER NOT NULL,
        text TEXT NOT NULL,
        involved_user_ids_json TEXT DEFAULT '[]',
        outcome_json TEXT DEFAULT '{}',
        created_at BIGINT NOT NULL
      );
    `);

    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_survival_seasons_room ON survival_seasons(room_id)`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_survival_participants_season ON survival_participants(season_id)`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_survival_alliances_season ON survival_alliances(season_id)`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_survival_events_season ON survival_events(season_id)`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_survival_events_day_phase ON survival_events(season_id, day_index, phase)`);

    // Migrations / compatibility:
    // - Allow NPC participants by letting user_id be nullable (FK still applies for real users; NULL is allowed).
    // - Ensure location column exists for arena map.
    try { await pgPool.query(`ALTER TABLE survival_participants ALTER COLUMN user_id DROP NOT NULL`); } catch(e) {}
    try { await pgPool.query(`ALTER TABLE survival_participants ADD COLUMN IF NOT EXISTS location TEXT`); } catch(e) {}
  } catch (e) {
    console.warn('[pg-init] survival tables failed:', e?.message || e);
  }

    PG_READY = true;
    PG_INIT_ERROR = null;
    DB_BACKEND = "postgres";
    console.log("Postgres tables ready");
  } catch (err) {
    PG_READY = false;
    PG_INIT_ERROR = err;
    if (IS_DEV_MODE) {
      console.warn("[db] PG unavailable, using SQLite dev fallback:", err?.message || err);
      return false;
    }
    console.error("Postgres init error:", err);
    throw err;
  }
})() : Promise.resolve(null);
// IMPORTANT for Render/any reverse proxy so secure cookies work
app.set("trust proxy", 1);
// ---- DB
async function pgUserExists(userId) {
  if (!pgPool || !PG_READY) return false;
  const { rows } = await pgPool.query("SELECT 1 FROM users WHERE id=$1 LIMIT 1", [userId]);
  return !!rows[0];
}

// ---- Couples helpers (Postgres only)
function orderPair(a, b) {
  const x = Number(a) || 0;
  const y = Number(b) || 0;
  return x < y ? [x, y] : [y, x];
}

function normalizeCoupleMembers(couple) {
  if (!couple) return { user_a_id: 0, user_b_id: 0 };
  const userA = Number(
    couple.user_a_id ?? couple.userAId ?? couple.user1_id ?? couple.user1Id ?? couple.user_a ?? 0
  ) || 0;
  const userB = Number(
    couple.user_b_id ?? couple.userBId ?? couple.user2_id ?? couple.user2Id ?? couple.user_b ?? 0
  ) || 0;
  return { user_a_id: userA, user_b_id: userB };
}

function isCoupleMember(userId, couple) {
  const uid = Number(userId) || 0;
  if (!uid || !couple) return false;
  const { user_a_id, user_b_id } = normalizeCoupleMembers(couple);
  return uid === user_a_id || uid === user_b_id;
}

function getCouplePartnerId(userId, couple) {
  const uid = Number(userId) || 0;
  if (!uid || !couple) return 0;
  const { user_a_id, user_b_id } = normalizeCoupleMembers(couple);
  if (uid === user_a_id) return user_b_id;
  if (uid === user_b_id) return user_a_id;
  return 0;
}

async function pgGetCoupleLinkForUser(userId) {
  const uid = Number(userId) || 0;
  if (!uid) return null;
  const { rows } = await pgPool.query(
    `
    SELECT cl.*,
           u1.username AS user1_name,
           u2.username AS user2_name
      FROM couple_links cl
      JOIN users u1 ON u1.id = cl.user1_id
      JOIN users u2 ON u2.id = cl.user2_id
     WHERE (cl.user1_id=$1 OR cl.user2_id=$1)
     ORDER BY cl.updated_at DESC
     LIMIT 1
    `,
    [uid]
  );
  return rows[0] || null;
}

async function pgGetActiveCoupleLinkForUser(userId) {
  const uid = Number(userId) || 0;
  if (!uid) return null;
  const { rows } = await pgPool.query(
    `
    SELECT cl.*,
           u1.username AS user1_name,
           u2.username AS user2_name,
           u1.avatar AS user1_avatar,
           u2.avatar AS user2_avatar,
           u1.role AS user1_role,
           u2.role AS user2_role
      FROM couple_links cl
      JOIN users u1 ON u1.id = cl.user1_id
      JOIN users u2 ON u2.id = cl.user2_id
     WHERE cl.status='active'
       AND (cl.user1_id=$1 OR cl.user2_id=$1)
     ORDER BY cl.updated_at DESC
     LIMIT 1
    `,
    [uid]
  );
  return rows[0] || null;
}

async function pgGetCouplePrefs(linkId, userId) {
  const { rows } = await pgPool.query(
    `SELECT * FROM couple_prefs WHERE link_id=$1 AND user_id=$2 LIMIT 1`,
    [Number(linkId) || 0, Number(userId) || 0]
  );
  return rows[0] || null;
}

async function pgGetCoupleSummaryFor(user) {
  const userId = Number(user?.id ?? user?.user_id ?? user?.userId) || 0;
  const link = await pgGetActiveCoupleLinkForUser(userId);

  // Pending links involving this user (incoming/outgoing)
  const { rows: pending } = await pgPool.query(
    `
    SELECT cl.*,
           u1.username AS user1_name,
           u2.username AS user2_name,
           ur.username AS requested_by_name
      FROM couple_links cl
      JOIN users u1 ON u1.id = cl.user1_id
      JOIN users u2 ON u2.id = cl.user2_id
      LEFT JOIN users ur ON ur.id = cl.requested_by_id
     WHERE (cl.user1_id=$1 OR cl.user2_id=$1)
       AND cl.status='pending'
     ORDER BY cl.updated_at DESC
    `,
    [Number(userId) || 0]
  );

  const incoming = [];
  const outgoing = [];
  for (const r of pending) {
    const requestedBy = Number(r.requested_by_id) || 0;
    const otherName = (Number(r.user1_id) === Number(userId)) ? r.user2_name : r.user1_name;
    const item = {
      linkId: r.id,
      other: otherName,
      requestedBy: r.requested_by_name || null,
      createdAt: Number(r.created_at) || null
    };
    if (requestedBy && requestedBy !== Number(userId)) incoming.push(item);
    else outgoing.push(item);
  }

  let active = null;
  let couple = null;
  let partner = null;
  if (link && link.status === "active" && isCoupleMember(userId, link)) {
    const prefsMe = await pgGetCouplePrefs(link.id, userId);
    const partnerId = getCouplePartnerId(userId, link);
    const prefsPartner = await pgGetCouplePrefs(link.id, partnerId);
    const isU1 = Number(link.user1_id) === Number(userId);
    const partnerName = isU1 ? link.user2_name : link.user1_name;
    const partnerAvatar = isU1 ? link.user2_avatar : link.user1_avatar;
    const partnerRole = isU1 ? link.user2_role : link.user1_role;

    couple = {
      id: link.id,
      user_a_id: Number(link.user1_id) || 0,
      user_b_id: Number(link.user2_id) || 0,
      partner_id: partnerId,
      status: link.status,
      created_at: Number(link.created_at) || null,
      activated_at: Number(link.activated_at || link.created_at) || null,
      privacy: link.privacy || "private",
      couple_name: link.couple_name || "",
      couple_bio: link.couple_bio || "",
      show_badge: link.show_badge !== false,
      bonuses_enabled: !!link.bonuses_enabled,
      status_emoji: link.status_emoji || "💜",
      status_label: link.status_label || "Linked"
    };

    partner = {
      id: partnerId,
      username: partnerName,
      avatar: partnerAvatar || "",
      role: partnerRole || "User"
    };

    active = {
      linkId: link.id,
      partnerId,
      partner: partnerName,
      since: Number(link.activated_at || link.created_at) || null,
      statusEmoji: link.status_emoji || "💜",
      statusLabel: link.status_label || "Linked",
      settingsAvailable: true,
      prefs: prefsMe ? {
        enabled: !!prefsMe.enabled,
        showProfile: !!prefsMe.show_profile,
        showMembers: !!prefsMe.show_members,
        groupMembers: !!prefsMe.group_members,
        aura: !!prefsMe.aura,
        badge: !!prefsMe.badge,
        allowPing: prefsMe.allow_ping !== false
      } : null,
      partnerPrefs: prefsPartner ? {
        enabled: !!prefsPartner.enabled,
        showProfile: !!prefsPartner.show_profile,
        showMembers: !!prefsPartner.show_members,
        groupMembers: !!prefsPartner.group_members,
        aura: !!prefsPartner.aura,
        badge: !!prefsPartner.badge,
        allowPing: prefsPartner.allow_ping !== false
      } : null,
      couple
    };
  }

  return {
    active,
    incoming,
    outgoing,
    couple,
    partner,
    isCoupleMember: !!(active && active.settingsAvailable),
    v2Enabled: isCouplesV2EnabledFor(user)
  };
}

function canShowCoupleFeature(mePrefs, partnerPrefs, key) {
  if (!mePrefs || !partnerPrefs) return false;
  if (!mePrefs.enabled || !partnerPrefs.enabled) return false;
  if (key === "profile") return !!mePrefs.showProfile && !!partnerPrefs.showProfile;
  if (key === "members") return !!mePrefs.showMembers && !!partnerPrefs.showMembers;
  if (key === "aura") return !!mePrefs.aura && !!partnerPrefs.aura;
  if (key === "badge") return !!mePrefs.badge && !!partnerPrefs.badge;
  if (key === "group") return !!mePrefs.groupMembers && !!partnerPrefs.groupMembers;
  return false;
}

function canShowCoupleBadge(mePrefs, partnerPrefs, link) {
  if (!canShowCoupleFeature(mePrefs, partnerPrefs, "badge")) return false;
  if (link && link.show_badge === false) return false;
  return true;
}

async function ensureCoupleLinkedMemories(link) {
  if (!FEATURE_FLAGS_CACHE?.COUPLES_V2_ENABLED) return;
  if (!link) return;
  const userIds = [Number(link.user1_id) || 0, Number(link.user2_id) || 0].filter(Boolean);
  if (userIds.length !== 2) return;
  const { rows: users } = await pgPool.query(
    `SELECT id, username, role FROM users WHERE id = ANY($1::int[])`,
    [userIds]
  );
  const map = new Map(users.map((u) => [Number(u.id), u]));
  const u1 = map.get(userIds[0]);
  const u2 = map.get(userIds[1]);
  if (!u1 || !u2) return;
  const payloadFor = (self, partner) => ({
    type: "social",
    title: "Couple linked",
    description: `Linked with ${partner.username}.`,
    icon: "💜",
    metadata: { partnerId: partner.id, partnerName: partner.username, coupleId: link.id },
  });
  if (isCouplesV2EnabledFor(u1)) {
    void ensureMemory(u1.id, `couple_linked_${link.id}`, payloadFor(u1, u2), u1);
  }
  if (isCouplesV2EnabledFor(u2)) {
    void ensureMemory(u2.id, `couple_linked_${link.id}`, payloadFor(u2, u1), u2);
  }
}

async function ensureCoupleMilestoneMemories(link) {
  if (!FEATURE_FLAGS_CACHE?.COUPLES_V2_ENABLED) return;
  if (!link) return;
  const since = Number(link.activated_at || link.activatedAt || link.created_at || link.createdAt) || 0;
  if (!since) return;
  const days = Math.floor((Date.now() - since) / 86400000);
  if (days < 7) return;
  const userIds = [Number(link.user1_id ?? link.user_a_id) || 0, Number(link.user2_id ?? link.user_b_id) || 0].filter(Boolean);
  if (userIds.length !== 2) return;
  const { rows: users } = await pgPool.query(
    `SELECT id, username, role FROM users WHERE id = ANY($1::int[])`,
    [userIds]
  );
  const map = new Map(users.map((u) => [Number(u.id), u]));
  const u1 = map.get(userIds[0]);
  const u2 = map.get(userIds[1]);
  if (!u1 || !u2) return;
  const milestones = [
    { days: 7, key: `couple_days_7_${link.id}`, title: "7 days together", icon: "🫶" },
    { days: 30, key: `couple_days_30_${link.id}`, title: "30 days together", icon: "💞" }
  ];
  for (const milestone of milestones) {
    if (days < milestone.days) continue;
    const payloadFor = (self, partner) => ({
      type: "social",
      title: milestone.title,
      description: `${milestone.days} days together with ${partner.username}.`,
      icon: milestone.icon,
      metadata: { partnerId: partner.id, partnerName: partner.username, coupleId: link.id, days: milestone.days },
    });
    if (isCouplesV2EnabledFor(u1)) {
      void ensureMemory(u1.id, milestone.key, payloadFor(u1, u2), u1);
    }
    if (isCouplesV2EnabledFor(u2)) {
      void ensureMemory(u2.id, milestone.key, payloadFor(u2, u1), u2);
    }
  }
}

async function pgUpsertCouplePrefs(linkId, userId, patch) {
  const now = Date.now();
  const p = patch || {};
  const fields = {
    enabled: typeof p.enabled === "boolean" ? p.enabled : undefined,
    show_profile: typeof p.showProfile === "boolean" ? p.showProfile : undefined,
    show_members: typeof p.showMembers === "boolean" ? p.showMembers : undefined,
    group_members: typeof p.groupMembers === "boolean" ? p.groupMembers : undefined,
    aura: typeof p.aura === "boolean" ? p.aura : undefined,
    badge: typeof p.badge === "boolean" ? p.badge : undefined,
    allow_ping: typeof p.allowPing === "boolean" ? p.allowPing : undefined
  };

  // If row doesn't exist, insert defaults first
  const existing = await pgGetCouplePrefs(linkId, userId);
  if (!existing) {
    await pgPool.query(
      `
      INSERT INTO couple_prefs(link_id, user_id, enabled, show_profile, show_members, group_members, aura, badge, allow_ping, updated_at)
      VALUES($1,$2,true,true,true,false,true,true,true,$3)
      ON CONFLICT (link_id, user_id) DO NOTHING
      `,
      [Number(linkId) || 0, Number(userId) || 0, now]
    );
  }

  const sets = [];
  const vals = [];
  let i = 1;
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v === "undefined") continue;
    sets.push(`${k}=$${i++}`);
    vals.push(v);
  }
  if (!sets.length) return;
  vals.push(now);
  vals.push(Number(linkId) || 0);
  vals.push(Number(userId) || 0);
  await pgPool.query(
    `UPDATE couple_prefs SET ${sets.join(", ")}, updated_at=$${i++} WHERE link_id=$${i++} AND user_id=$${i++}`,
    vals
  );
}


// ---- Friends helpers (Postgres-first, SQLite fallback)
async function pgAreFriends(userId, otherId){
  const uid=Number(userId)||0; const oid=Number(otherId)||0;
  if(!uid||!oid) return false;
  const { rows } = await pgPool.query(
    `SELECT 1 FROM friends WHERE user_id=$1 AND friend_user_id=$2 LIMIT 1`,
    [uid, oid]
  );
  return !!rows[0];
}

async function pgGetPendingFriendRequest(fromId, toId){
  const a=Number(fromId)||0; const b=Number(toId)||0;
  if(!a||!b) return null;
  const { rows } = await pgPool.query(
    `SELECT * FROM friend_requests WHERE from_user_id=$1 AND to_user_id=$2 AND status='pending' ORDER BY id DESC LIMIT 1`,
    [a, b]
  );
  return rows[0] || null;
}

async function pgListIncomingFriendRequests(userId){
  const uid=Number(userId)||0;
  if(!uid) return [];
  const { rows } = await pgPool.query(
    `SELECT fr.id, fr.created_at, u.id AS from_id, u.username AS from_username, u.avatar, u.avatar_bytes, u.avatar_mime, u.avatar_updated
       FROM friend_requests fr
       JOIN users u ON u.id = fr.from_user_id
      WHERE fr.to_user_id=$1 AND fr.status='pending'
      ORDER BY fr.created_at DESC`,
    [uid]
  );
  return rows || [];
}

async function pgCreateFriendsPair(a, b){
  const uid=Number(a)||0; const oid=Number(b)||0;
  const now=Date.now();
  if(!uid||!oid||uid===oid) return;
  await pgPool.query(
    `INSERT INTO friends(user_id, friend_user_id, is_favorite, created_at)
     VALUES ($1,$2,false,$3)
     ON CONFLICT (user_id, friend_user_id) DO NOTHING`,
    [uid, oid, now]
  );
  await pgPool.query(
    `INSERT INTO friends(user_id, friend_user_id, is_favorite, created_at)
     VALUES ($1,$2,false,$3)
     ON CONFLICT (user_id, friend_user_id) DO NOTHING`,
    [oid, uid, now]
  );
}

async function pgListFriendsForUser(userId){
  const uid=Number(userId)||0;
  if(!uid) return [];
  const { rows } = await pgPool.query(
    `SELECT f.friend_user_id AS id,
            f.is_favorite,
            u.username,
            u.role,
            u.last_seen,
            u.last_room,
            u.last_status,
            u.avatar, u.avatar_bytes, u.avatar_mime, u.avatar_updated
       FROM friends f
       JOIN users u ON u.id = f.friend_user_id
      WHERE f.user_id=$1
      ORDER BY f.is_favorite DESC, lower(u.username) ASC`,
    [uid]
  );
  return rows || [];
}

async function dbAreFriends(userId, otherId){
  const row = await dbGetAsync(`SELECT 1 FROM friends WHERE user_id=? AND friend_user_id=? LIMIT 1`, [userId, otherId]).catch(()=>null);
  return !!row;
}

async function dbGetPendingFriendRequest(fromId, toId){
  return await dbGetAsync(`SELECT * FROM friend_requests WHERE from_user_id=? AND to_user_id=? AND status='pending' ORDER BY id DESC LIMIT 1`, [fromId, toId]).catch(()=>null);
}

async function dbListIncomingFriendRequests(userId){
  return await dbAllAsync(
    `SELECT fr.id, fr.created_at, u.id AS from_id, u.username AS from_username, u.avatar
       FROM friend_requests fr
       JOIN users u ON u.id = fr.from_user_id
      WHERE fr.to_user_id=? AND fr.status='pending'
      ORDER BY fr.created_at DESC`,
    [userId]
  ).catch(()=>[]);
}

async function dbCreateFriendsPair(a,b){
  const now=Date.now();
  if(!a||!b||a===b) return;
  await dbRunAsync(`INSERT OR IGNORE INTO friends(user_id, friend_user_id, is_favorite, created_at) VALUES (?,?,0,?)`, [a,b,now]).catch(()=>{});
  await dbRunAsync(`INSERT OR IGNORE INTO friends(user_id, friend_user_id, is_favorite, created_at) VALUES (?,?,0,?)`, [b,a,now]).catch(()=>{});
}

async function dbListFriendsForUser(userId){
  return await dbAllAsync(
    `SELECT f.friend_user_id AS id, f.is_favorite, u.username, u.role, u.last_seen, u.last_room, u.last_status, u.avatar
       FROM friends f
       JOIN users u ON u.id = f.friend_user_id
      WHERE f.user_id=?
      ORDER BY f.is_favorite DESC, lower(u.username) ASC`,
    [userId]
  ).catch(()=>[]);
}

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function safeParseUrl(input) {
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function isLocalhostOrigin(origin) {
  const url = safeParseUrl(origin);
  if (!url) return false;
  return LOCALHOST_HOSTS.has(url.hostname);
}

function isAllowedOrigin(origin, hostHeader) {
  if (!origin) return false;
  const url = safeParseUrl(origin);
  if (!url) return false;

  // Always allow same-host origins (covers cases where ALLOWED_ORIGINS is set
  // but the site is accessed via a different deployed host, e.g. Render URL).
  if (hostHeader && url.host === hostHeader) return true;

  // If an explicit allowlist is provided, prefer it.
  if (ALLOWED_ORIGINS.size) {
    if (ALLOWED_ORIGINS.has(url.origin)) return true;
  }

  // Local dev convenience.
  if (!IS_PROD && isLocalhostOrigin(url.origin)) return true;
  return false;
}


function getClientIp(req) {
  const xfwd = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xfwd || req.ip || req.connection?.remoteAddress || "";
}

// ---- Security + parsing
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// IMPORTANT: CSP that blocks inline JS (good), but allows our external /public/app.js & /public/styles.css
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' https://www.youtube.com https://www.youtube-nocookie.com https://s.ytimg.com https://unpkg.com https://challenges.cloudflare.com https://hcaptcha.com https://js.hcaptcha.com 'sha256-ieoeWczDHkReVBsRBqaal5AFMlBtNjMzgwKvLqi/tSU=' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM='",      "script-src-elem 'self' https://www.youtube.com https://www.youtube-nocookie.com https://s.ytimg.com https://unpkg.com https://challenges.cloudflare.com https://hcaptcha.com https://js.hcaptcha.com 'sha256-ieoeWczDHkReVBsRBqaal5AFMlBtNjMzgwKvLqi/tSU=' 'sha256-ZswfTY7H35rbv8WC7NXBoiC7WNu86vSzCDChNWwZZDM='",      // Inline style attributes are set by the client JS (e.g. show/hide panels),
      // so allow them alongside our external stylesheet.
      // Also allow Google Fonts stylesheets for optional custom fonts.
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      // Allow Google Fonts font files.
      "font-src 'self' data: https://fonts.gstatic.com",
      // allow avatars/uploads + blob previews on client
      "img-src 'self' data: blob: https://i.ytimg.com",
      "media-src 'self' blob:",
      // socket.io
      "connect-src 'self' ws: wss: https://noembed.com https://challenges.cloudflare.com https://hcaptcha.com https://js.hcaptcha.com",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com https://challenges.cloudflare.com https://hcaptcha.com",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  next();
});

// ---- Sessions (Postgres-backed; survives redeploys)
const sessionStore = pgPool
  ? new PgSession({
      pool: pgPool,
      tableName: "session",
      // Prevent cold-start / deploy races where the session table isn't ready yet.
      // connect-pg-simple will create it on demand if missing.
      createTableIfMissing: true,
    })
  : new session.MemoryStore();
const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
});

app.use(sessionMiddleware);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", db: DB_BACKEND });
});

const genericRateLimitHandler = (_req, res) => {
  res.status(429).json({ message: "Too many requests, please try again later." });
};

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_GLOBAL || 900),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => getClientIp(req),
});

app.use(globalLimiter);

const strictLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_STRICT || 30),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => getClientIp(req),
});

const loginIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_LOGIN_IP || 20),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => getClientIp(req),
});

const passwordUpgradeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_PASSWORD_UPGRADE || 12),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => String(req.session?.passwordUpgrade?.userId || getClientIp(req)),
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_REGISTER_IP || 8),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => getClientIp(req),
});

const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_UPLOAD_IP || 40),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => getClientIp(req),
});

const uploadUserLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_UPLOAD_USER || 30),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => String(req.session?.user?.id || getClientIp(req)),
});

const dmLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_DM_HTTP || 60),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => String(req.session?.user?.id || getClientIp(req)),
});

const survivalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_SURVIVAL_HTTP || 40),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => String(req.session?.user?.id || getClientIp(req)),
});

const moderationHttpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_MOD_HTTP || 40),
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: genericRateLimitHandler,
  keyGenerator: (req) => String(req.session?.user?.id || getClientIp(req)),
});

const postOriginGuard = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (req.path && req.path.startsWith("/socket.io/")) return next();
  const hostHeader = String(req.headers.host || "");
  const origin = String(req.headers.origin || "");
  const referer = String(req.headers.referer || "");
  const secFetchSite = String(req.headers["sec-fetch-site"] || "").toLowerCase();

  if (origin) {
    if (isAllowedOrigin(origin, hostHeader)) return next();
    return res.status(403).json({ message: "Origin not allowed." });
  }

  if (referer) {
    const refOrigin = safeParseUrl(referer)?.origin || "";
    if (refOrigin && isAllowedOrigin(refOrigin, hostHeader)) return next();
  }

  if (secFetchSite === "same-origin" || secFetchSite === "same-site") return next();
  return res.status(403).json({ message: "Origin required." });
};

app.use(postOriginGuard);

// ---- Static
app.use("/uploads", express.static(UPLOADS_DIR, {
  setHeaders: (res, filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".mp3") res.setHeader("Content-Type", "audio/mpeg");
    if (ext === ".m4a") res.setHeader("Content-Type", "audio/mp4");
    if (ext === ".mp4") res.setHeader("Content-Type", "video/mp4");
    if (ext === ".webm") res.setHeader("Content-Type", "video/webm");
    res.setHeader("X-Content-Type-Options", "nosniff");
  },
}));
app.use("/avatars", express.static(AVATARS_DIR, {
  setHeaders: (res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
  },
}));
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
    res.setHeader("X-Content-Type-Options", "nosniff");
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

const VIBE_TAG_LABELS = new Map(
  VIBE_TAGS.map((tag) => [String(tag.label).toLowerCase(), tag.label])
);

const HEX_COLOR_RE = /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

function sanitizeVibeTags(raw) {
  const arr = Array.isArray(raw)
    ? raw
    : (typeof raw === "string"
      ? (() => { try { return JSON.parse(raw); } catch { return []; } })()
      : []);

  const out = [];
  for (const v of arr) {
    if (out.length >= VIBE_TAG_LIMIT) break;
    const val = String(v || "").trim();
    if (!val) continue;
    const hit = VIBE_TAG_LABELS.get(val.toLowerCase());
    if (hit && !out.includes(hit)) out.push(hit);
  }
  return out;
}
function sanitizeHexColor(raw){
  const c = String(raw || "").trim();
  if(!c) return null;
  return HEX_COLOR_RE.test(c) ? c : null;
}

const CHAT_FX_DEFAULTS = Object.freeze({
  font: "system",
  nameFont: "system",
  accent: null,
  textColor: null,
  nameColor: null,
  autoContrast: false,
  textBold: false,
  textItalic: false,
  textGlow: "off",
  textGradientEnabled: false,
  textGradientA: null,
  textGradientB: null,
  textGradientAngle: 135,
  polishPack: true,
  polishAuras: true,
  polishAnimations: true
});
const TEXT_STYLE_DEFAULTS = Object.freeze({
  mode: "color",
  color: null,
  neon: {
    presetId: null,
    color: null,
    intensity: "med"
  },
  gradient: {
    presetId: null,
    css: null,
    intensity: "normal"
  },
  fontFamily: "system",
  fontStyle: "normal"
});
const TEXT_STYLE_MODES = new Set(["color", "neon", "gradient"]);
const TEXT_STYLE_INTENSITIES = new Set(["low", "med", "high", "ultra"]);
const TEXT_STYLE_GRADIENT_INTENSITIES = new Set(["soft", "normal", "bold"]);
const TEXT_STYLE_HEX = /^#[0-9a-f]{6}$/i;
const CHAT_FX_TEXT_GLOWS = new Set(["off", "soft", "neon", "strong"]);
const CHAT_FX_FONTS = new Set([
  "system",
  "inter","roboto","opensans","lato","poppins","nunito","rubik","montserrat","spacegrotesk","worksans","sourcesans3","raleway","oswald","ubuntu","firasans","gothicA1",
  "merriweather","playfair","crimson","libreserif","robotoslab","alegreya","cinzel",
  "jetbrains","inconsolata","spacemono","ibmplexmono","dmmono","pressstart",
  "anton","bebas","abril",
  "pacifico","dancing","caveat","indieflower","permanentmarker",
  "metalmania",
  "orbitron","oxanium","audiowide","rajdhani","chakrapetch","sharetechmono","electrolize","quantico","turretroad","syncopate",
  "bungee","bungeeinline","bungeeshade","monoton","righteous","luckiestguy","lilitaone","blackopsone","rubikglitch","fascinateinline",
  "vt323","silkscreen","pixelifysans","tiny5",
  "fredoka","baloo2","bubblegumsans","chewy","sniglet",
  "cormorantgaramond","ebgaramond","bodonimoda","prata","marcellus",
  "kaushanscript","greatvibes","allura","sacramento","satisfy","yellowtail","marckscript",
  "unifrakturcook","unifrakturmaguntia","pirataone","newrocker","eater","nosifer"
]);
const CHAT_FX_HEX = /^#[0-9a-f]{6}$/i;

function sanitizeTextStyle(raw) {
  if (!raw || typeof raw !== "object") return null;
  const out = {
    ...TEXT_STYLE_DEFAULTS,
    neon: { ...TEXT_STYLE_DEFAULTS.neon },
    gradient: { ...TEXT_STYLE_DEFAULTS.gradient }
  };
  const mode = String(raw.mode || "").toLowerCase();
  if (TEXT_STYLE_MODES.has(mode)) out.mode = mode;
  if (TEXT_STYLE_HEX.test(raw.color || "")) out.color = String(raw.color).trim();
  const family = String(raw.fontFamily || raw.font || "").trim();
  if (CHAT_FX_FONTS.has(family)) out.fontFamily = family;
  const fontStyle = String(raw.fontStyle || "").toLowerCase();
  if (fontStyle === "normal" || fontStyle === "bold" || fontStyle === "italic") out.fontStyle = fontStyle;

  if (raw.neon && typeof raw.neon === "object") {
    const intensity = String(raw.neon.intensity || "").toLowerCase();
    if (TEXT_STYLE_INTENSITIES.has(intensity)) out.neon.intensity = intensity;
    if (TEXT_STYLE_HEX.test(raw.neon.color || "")) out.neon.color = String(raw.neon.color).trim();
    if (typeof raw.neon.presetId === "string") out.neon.presetId = raw.neon.presetId.slice(0, 64);
  }

  if (raw.gradient && typeof raw.gradient === "object") {
    if (typeof raw.gradient.presetId === "string") out.gradient.presetId = raw.gradient.presetId.slice(0, 64);
    if (typeof raw.gradient.css === "string") out.gradient.css = raw.gradient.css.slice(0, 180);
    const intensity = String(raw.gradient.intensity || "").toLowerCase();
    if (TEXT_STYLE_GRADIENT_INTENSITIES.has(intensity)) out.gradient.intensity = intensity;
  }

  return out;
}

function sanitizeCustomization(raw, fallbackTextStyle = null) {
  if (!raw || typeof raw !== "object") {
    if (fallbackTextStyle) {
      const fallback = sanitizeTextStyle(fallbackTextStyle);
      return fallback ? { userNameStyle: fallback, messageTextStyle: fallback } : null;
    }
    return null;
  }
  const userNameRaw = raw.userNameStyle ?? raw.usernameStyle ?? raw.nameStyle;
  const messageRaw = raw.messageTextStyle ?? raw.messageStyle ?? raw.textStyle;
  const fallback = fallbackTextStyle ? sanitizeTextStyle(fallbackTextStyle) : null;
  const userNameStyle = userNameRaw ? sanitizeTextStyle(userNameRaw) : null;
  const messageTextStyle = messageRaw ? sanitizeTextStyle(messageRaw) : null;
  if (!userNameStyle && !messageTextStyle) {
    return fallback ? { userNameStyle: fallback, messageTextStyle: fallback } : null;
  }
  return {
    ...(userNameStyle ? { userNameStyle } : {}),
    ...(messageTextStyle ? { messageTextStyle } : {})
  };
}

function sanitizeChatFx(raw) {
  const out = { ...CHAT_FX_DEFAULTS };
  if (!raw || typeof raw !== "object") return out;

  if (CHAT_FX_FONTS.has(raw.font)) out.font = raw.font;

  // Username styling (shown anywhere the username appears)
  const nameFontRaw = raw.nameFont ?? raw.usernameFont ?? raw.userNameFont ?? raw.uNameFont;
  const nf = String(nameFontRaw || "").trim();
  if (CHAT_FX_FONTS.has(nf)) out.nameFont = nf;

  if (raw.accent == null) {
    out.accent = null;
  } else {
    const accent = String(raw.accent || "").trim();
    out.accent = CHAT_FX_HEX.test(accent) ? accent : null;
  }

  if (raw.textColor == null) {
    out.textColor = null;
  } else {
    const tc = String(raw.textColor || "").trim();
    out.textColor = CHAT_FX_HEX.test(tc) ? tc : null;
  }

  const nameColorRaw = raw.nameColor ?? raw.usernameColor ?? raw.userNameColor ?? raw.uNameColor;
  if (nameColorRaw == null || nameColorRaw === "") {
    out.nameColor = null;
  } else {
    const nc = String(nameColorRaw || "").trim();
    out.nameColor = CHAT_FX_HEX.test(nc) ? nc : null;
  }

  if (typeof raw.autoContrast === "boolean") out.autoContrast = raw.autoContrast;
  if (typeof raw.textBold === "boolean") out.textBold = raw.textBold;
  if (typeof raw.textItalic === "boolean") out.textItalic = raw.textItalic;
  if (CHAT_FX_TEXT_GLOWS.has(raw.textGlow)) out.textGlow = raw.textGlow;
  if (typeof raw.textGradientEnabled === "boolean") out.textGradientEnabled = raw.textGradientEnabled;
  if (raw.textGradientA == null || raw.textGradientA === "") {
    out.textGradientA = null;
  } else {
    const tga = String(raw.textGradientA || "").trim();
    out.textGradientA = CHAT_FX_HEX.test(tga) ? tga : null;
  }
  if (raw.textGradientB == null || raw.textGradientB === "") {
    out.textGradientB = null;
  } else {
    const tgb = String(raw.textGradientB || "").trim();
    out.textGradientB = CHAT_FX_HEX.test(tgb) ? tgb : null;
  }
  if (Number.isFinite(Number(raw.textGradientAngle))) {
    out.textGradientAngle = clamp(raw.textGradientAngle, 0, 360);
  }
  if (typeof raw.polishPack === "boolean") out.polishPack = raw.polishPack;
  if (typeof raw.polishAuras === "boolean") out.polishAuras = raw.polishAuras;
  if (typeof raw.polishAnimations === "boolean") out.polishAnimations = raw.polishAnimations;

  return out;
}

function mergeChatFxWithCustomization(chatFx, customization, textStyle) {
  const fx = sanitizeChatFx(chatFx);
  const custom = sanitizeCustomization(customization, textStyle);
  return custom ? { ...fx, ...custom } : fx;
}

const TONE_KEYS = new Set(["chill", "joke", "sarcastic", "serious"]);
function sanitizeTone(input) {
  const key = String(input || "").trim().toLowerCase();
  return TONE_KEYS.has(key) ? key : null;
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

// Resolve a user's current avatar URL (works for both Postgres and SQLite backends).
async function getAvatarUrlForUserId(userId){
  const uid = Number(userId) || 0;
  if (!uid) return null;
  try {
    if (PG_READY) {
      const row = await pgGetUserRowById(uid, ["id","avatar","avatar_bytes","avatar_mime","avatar_updated"]).catch(()=>null);
      return avatarUrlFromRow(row);
    }
  } catch {}
  try {
    const row = await dbGet("SELECT id, avatar FROM users WHERE id=? LIMIT 1", [uid]).catch(()=>null);
    return avatarUrlFromRow(row);
  } catch {}
  return null;
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
    `SELECT * FROM users WHERE lower(username) = lower($1) LIMIT 1`,
    [username]
  );
  return pgRowToUser(rows[0]);
}

async function pgGetUserById(id) {
  const { rows } = await pgPool.query(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
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
    "lastDiceRollAt","dice_sixes","luck","roll_streak","last_qual_msg_hash","last_qual_msg_at","vibe_tags","header_grad_a","header_grad_b"
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
      "lastDiceRollAt", dice_sixes, luck, roll_streak, last_qual_msg_hash, last_qual_msg_at
    )
    VALUES (
      $1,$2,$3,$4,
      $5,$6,$7,$8,$9,
      $10,$11,$12,
      $13,$14,$15,
      $16,$17,$18,$19,$20,
      $21,$22,$23,$24,$25,$26
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
      dice_sixes = GREATEST(users.dice_sixes, EXCLUDED.dice_sixes),
      luck = COALESCE(EXCLUDED.luck, users.luck),
      roll_streak = COALESCE(EXCLUDED.roll_streak, users.roll_streak),
      last_qual_msg_hash = COALESCE(EXCLUDED.last_qual_msg_hash, users.last_qual_msg_hash),
      last_qual_msg_at = CASE
        WHEN users.last_qual_msg_at IS NULL THEN EXCLUDED.last_qual_msg_at
        WHEN EXCLUDED.last_qual_msg_at IS NULL THEN users.last_qual_msg_at
        ELSE GREATEST(users.last_qual_msg_at, EXCLUDED.last_qual_msg_at)
      END
    RETURNING *;
  `;

  const { rows } = await pgPool.query(q, [
    username, passwordHash, role, createdAt,
    row.avatar || null, row.bio || "", row.mood || "", row.age ?? null, row.gender || "",
    row.last_seen ?? null, row.last_room || null, row.last_status || null,
    theme, row.gold ?? 0, row.xp ?? 0,
    row.lastXpMessageAt ?? null, row.lastDailyLoginAt ?? null, row.lastGoldTickAt ?? null, row.lastMessageGoldAt ?? null, row.lastDailyLoginGoldAt ?? null,
    row.lastDiceRollAt ?? null, row.dice_sixes ?? 0, row.luck ?? 0, row.roll_streak ?? 0, row.last_qual_msg_hash ?? null, row.last_qual_msg_at ?? null
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

function extractMentionId(raw) {
  const text = String(raw || "").trim();
  const match = text.match(/^<@(\d+)>$/) || text.match(/^@(\d+)$/);
  if (!match) return null;
  const id = Number(match[1]);
  return Number.isInteger(id) ? id : null;
}

function parseUserAndAmountArgs(rawArgs, amountLabel = "amount") {
  const tokens = parseQuotedArgs(rawArgs);
  if (tokens.length < 2) {
    return { error: `Missing user or ${amountLabel}.` };
  }
  const amountToken = tokens[tokens.length - 1];
  const amount = Number(amountToken);
  if (!Number.isFinite(amount)) {
    return { error: `Invalid ${amountLabel}.` };
  }
  const userRaw = tokens.slice(0, -1).join(" ").trim();
  if (!userRaw) {
    return { error: "Missing user." };
  }
  return { userRaw, amount };
}

function findUserByMention(raw, cb) {
  const rawName = String(raw || "").replace(/^@+/, "").trim().slice(0, 64);
  const cleaned = cleanUsernameForLookup(rawName);
  const legacy = sanitizeUsername(rawName);

  const candidates = [];
  for (const v of [rawName, cleaned, legacy]) {
    const s = String(v || "").trim();
    if (!s) continue;
    // de-dupe by lowercased key
    if (candidates.some((x) => normKey(x) === normKey(s))) continue;
    candidates.push(s);
  }

  const sqliteGet = (name) =>
    new Promise((resolve) => {
      db.get(
        `SELECT id, username FROM users WHERE username = ?
            OR lower(username) = lower(?)
         ORDER BY CASE WHEN username = ? THEN 0 ELSE 1 END
         LIMIT 1`,
        [name, name, name],
        (err, row) => (err ? resolve(null) : resolve(row || null))
      );
    });
  const sqliteGetById = (id) =>
    new Promise((resolve) => {
      db.get(
        "SELECT id, username FROM users WHERE id = ? LIMIT 1",
        [id],
        (err, row) => (err ? resolve(null) : resolve(row || null))
      );
    });

  (async () => {
    const mentionId = extractMentionId(raw);
    if (mentionId) {
      if (await pgUsersEnabled()) {
        try {
          const { rows } = await pgPool.query(
            "SELECT id, username FROM users WHERE id = $1 LIMIT 1",
            [mentionId]
          );
          const row = rows?.[0] || null;
          if (row?.id && row?.username) return cb(null, row);
        } catch (e) {
          console.warn("[findUserByMention][pg id] failed, falling back to sqlite:", e?.message || e);
        }
      }
      const row = await sqliteGetById(mentionId);
      if (row?.id && row?.username) return cb(null, row);
    }

    for (const name of candidates) {
      // Prefer Postgres when enabled (Render/prod), but fall back to SQLite.
      if (await pgUsersEnabled()) {
        try {
          const { rows } = await pgPool.query(
            `SELECT id, username FROM users WHERE username = $1
                OR lower(username) = lower($2)
             ORDER BY CASE WHEN username = $3 THEN 0 ELSE 1 END
             LIMIT 1`,
            [name, name, name]
          );
          const row = rows?.[0] || null;
          if (row?.id && row?.username) return cb(null, row);
        } catch (e) {
          // If PG is misbehaving, keep behavior functional via SQLite.
          console.warn("[findUserByMention][pg] failed, falling back to sqlite:", e?.message || e);
        }
      }

      const row = await sqliteGet(name);
      if (row?.id && row?.username) return cb(null, row);
    }
    return cb(new Error("User not found"));
  })().catch((e) => cb(e));
}

async function findUserByUsername(rawName) {
  const name = sanitizeUsername(rawName);
  if (!name) return null;
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        "SELECT id, username FROM users WHERE lower(username) = lower($1) LIMIT 1",
        [name]
      );
      if (rows?.[0]) return rows[0];
    } catch (e) {
      console.warn("[findUserByUsername][pg] failed, falling back to sqlite:", e?.message || e);
    }
  }
  return await dbGetAsync(
    "SELECT id, username FROM users WHERE lower(username) = lower(?) LIMIT 1",
    [name]
  ).catch(() => null);
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

function parseQuotedArgs(raw) {
  const input = String(raw || "");
  const out = [];
  let buf = "";
  let quote = null;
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (escaped) {
      buf += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        buf += ch;
      }
      continue;
    }
    if (ch === "\"" || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (buf) {
        out.push(buf);
        buf = "";
      }
      continue;
    }
    buf += ch;
  }
  if (buf) out.push(buf);
  return out;
}

function parseCommand(text) {
  const raw = String(text || "").trim();
  if (!raw.startsWith("/")) return null;
  const trimmed = raw.slice(1);
  const spaceIdx = trimmed.search(/\s/);
  const name = (spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx)).trim();
  if (!name) return null;
  const rawArgs = spaceIdx === -1 ? "" : trimmed.slice(spaceIdx + 1).trim();
  const args = rawArgs ? parseQuotedArgs(rawArgs) : [];
  return { name: name.toLowerCase(), args, rawArgs };
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
  "Cherry Blossom (Dark)",
  "Cherry Blossom (Light)",
  "420 Friendly (Light)",
  "420 Friendly (Dark)",
  "Aurora Night",
  "Mint Soda",
  "Lavender Fog",
  "Crimson Noir",
  "Ocean Mist",
  "Deep Ocean",
  "Sunlit Sand",
  "Graphite",
  "Forest Night",
  "Retro Terminal",
  "Desert Dusk",
  "Arctic Light",
  "Rose Quartz",
  "Lemonade",
  "Sunrise Sorbet",
  "Cotton Candy Sky",
  "Prismatic Pearl",
  "Citrus Splash",
  "Glacier Bloom",
  "Aurora Pastel",
  "Midnight Mirage",
  "Neon Abyss",
  "Velvet Galaxy",
  "Obsidian Aurora",
  "Iris & Lola Neon",
];
const PUBLIC_THEME_NAMES = new Set([
  "Minimal Light",
  "Minimal Dark",
  "Minimal Light (High Contrast)",
  "Minimal Dark (High Contrast)",
  "Paper / Parchment",
  "Sky Light",
  "Fantasy Tavern",
  "Fantasy Tavern (Ember)",
  "Desert Dusk",
]);
const GOLD_THEME_PRICES = Object.freeze({
  "prismatic-pearl": 2800,
  "neon-abyss": 4200,
  "velvet-galaxy": 4500,
});
function themeIdFromName(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}
const THEME_CATALOG = ALLOWED_THEMES.map((name) => {
  const id = themeIdFromName(name);
  const goldPrice = GOLD_THEME_PRICES[id] || null;
  const access = PUBLIC_THEME_NAMES.has(name) ? "public" : goldPrice ? "gold" : "vip";
  return {
    id,
    name,
    access,
    isPurchasable: Boolean(goldPrice),
    goldPrice,
  };
});
const THEME_BY_ID = new Map(THEME_CATALOG.map((theme) => [theme.id, theme]));
const THEME_ID_SET = new Set(THEME_CATALOG.map((theme) => theme.id));

// Passive gold accrues slowly over time. 5s ticks were far too fast.
// 1 gold per minute = 60 gold/hour.
const GOLD_TICK_MS = 60_000;

// Prevent double-awarding gold due to overlapping async timers/events for the same user.
const goldInFlight = new Set();
const MESSAGE_GOLD_COOLDOWN_MS = 5 * 60 * 1000;
const DAILY_GOLD_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const USERNAME_CHANGE_COST = 5000;
// ---- Real-time presence tracking
const onlineState = new Map(); // userId -> { room, status }
const socketIdByUserId = new Map(); // userId -> socket.id
const typingByRoom = new Map(); // room -> Set(username)
const dmTypingByThread = new Map(); // threadId -> Set(username)
const msgRate = new Map(); // socket.id -> { lastTs, count }
const socketEventRate = new Map(); // socket.id -> Map(eventKey -> { count, resetAt })
const socketConnByIp = new Map(); // ip -> { count, lastSeen }
const loginFailureTracker = new Map(); // key -> { count, resetAt, blockedUntil }
const securityAuditLimiter = new Map(); // key -> { count, resetAt }
const onlineXpTrack = new Map(); // userId -> { lastTs, carryMs }
const xpUpdateLocks = new Map(); // userId -> Promise chain to prevent XP races

const MAX_CHAT_MESSAGE_CHARS = Number(process.env.MAX_CHAT_MESSAGE_CHARS || 2000);
const MAX_DM_MESSAGE_CHARS = Number(process.env.MAX_DM_MESSAGE_CHARS || 2000);
const MAX_SOCKET_CONN_PER_IP = Number(process.env.MAX_SOCKET_CONN_PER_IP || 5);
const SOCKET_CONN_TTL_MS = 15 * 60 * 1000;

// ---- DM read receipts (in-memory; resets on restart)
const dmReadState = new Map(); // threadId -> Map(userId -> { messageId, ts })

db.get(`SELECT value FROM config WHERE key='maintenance'`, [], (_e, row) => {
  maintenanceState.enabled = row?.value === "on";
});

db.get(`SELECT value FROM config WHERE key='active_room_events'`, [], (_e, row) => {
  try {
    const obj = safeJsonParse(row?.value || "{}", {});
    let maxId = 0;
    for (const [room, ev] of Object.entries(obj || {})) {
      if (!ev || typeof ev !== "object") continue;
      if (ev.endsAt && Number(ev.endsAt) < Date.now()) continue;
      ACTIVE_ROOM_EVENTS.set(room, ev);
      const evId = Number(ev.id);
      if (Number.isFinite(evId) && evId > maxId) maxId = evId;
    }
    ROOM_EVENT_SEQ = Math.max(ROOM_EVENT_SEQ, maxId + 1);
  } catch {}
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

async function getConfigValue(key, fallback = null) {
  try {
    const row = await dbGetAsync("SELECT value FROM config WHERE key = ?", [key]);
    return row?.value ?? fallback;
  } catch {
    return fallback;
  }
}

async function setConfigValue(key, value) {
  const v = value == null ? "" : String(value);
  await dbRunAsync(
    "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    [key, v]
  );
  return v;
}

async function getConfigValuePg(key) {
  if (!(await pgUsersEnabled())) return null;
  try {
    const { rows } = await pgPool.query(`SELECT value FROM config WHERE key = $1 LIMIT 1`, [key]);
    return rows?.[0]?.value ?? null;
  } catch (e) {
    console.warn("[config][pg] read failed:", e?.message || e);
    return null;
  }
}

async function setConfigValuePg(key, value) {
  if (!(await pgUsersEnabled())) return null;
  const v = value == null ? "" : String(value);
  try {
    await pgPool.query(
      `INSERT INTO config (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, v]
    );
    return v;
  } catch (e) {
    console.warn("[config][pg] write failed:", e?.message || e);
    return null;
  }
}

async function getRoomStructureVersion() {
  const key = "room_structure_version";
  const pgValue = await getConfigValuePg(key);
  if (pgValue != null) return Number(pgValue) || 0;
  const sqliteValue = await getConfigValue(key, null);
  return Number(sqliteValue) || 0;
}

async function setRoomStructureVersion(version) {
  const key = "room_structure_version";
  const next = String(Number(version) || 0);
  await setConfigValue(key, next);
  await setConfigValuePg(key, next);
  return Number(next) || 0;
}

async function bumpRoomStructureVersion() {
  const current = await getRoomStructureVersion();
  const next = current + 1;
  await setRoomStructureVersion(next);
  return next;
}

function safeJsonParse(str, fallback) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

async function getConfigJson(key, fallback = {}) {
  const raw = await getConfigValue(key, null);
  if (raw == null) return fallback;
  const parsed = safeJsonParse(raw, null);
  return parsed && typeof parsed === "object" ? parsed : fallback;
}

async function setConfigJson(key, obj) {
  const raw = JSON.stringify(obj ?? {});
  await setConfigValue(key, raw);
  return obj;
}

function selectPromptText() {
  const pool = ROOM_PROMPT_TEMPLATES.filter(Boolean);
  if (!pool.length) return "💬 Prompt event started.";
  return pool[Math.floor(Math.random() * pool.length)];
}

function pruneExpiredRoomEvent(roomName) {
  const existing = ACTIVE_ROOM_EVENTS.get(roomName);
  if (!existing) return null;
  if (existing.endsAt && Number(existing.endsAt) < Date.now()) {
    ACTIVE_ROOM_EVENTS.delete(roomName);
    return null;
  }
  return existing;
}

function getActiveEventsForRoom(roomName) {
  const key = String(roomName || "");
  const existing = pruneExpiredRoomEvent(key);
  if (!existing) return [];
  return [existing];
}

async function syncActiveRoomEvents() {
  await setConfigJson("active_room_events", Object.fromEntries(ACTIVE_ROOM_EVENTS.entries()));
}

async function addRoomEvent(roomName, ev) {
  const room = String(roomName || "");
  const payload = ev && typeof ev === "object" ? ev : {};
  const next = { ...payload, room };
  ACTIVE_ROOM_EVENTS.set(room, next);
  await syncActiveRoomEvents();
  return next;
}

async function stopRoomEventById(id) {
  for (const [room, ev] of ACTIVE_ROOM_EVENTS.entries()) {
    if (Number(ev?.id) === Number(id)) {
      ACTIVE_ROOM_EVENTS.delete(room);
      await syncActiveRoomEvents();
      return { ...ev, room };
    }
  }
  return null;
}

function createChessInstance(fen) {
  const chess = new Chess();
  if (fen) {
    try {
      chess.load(fen);
    } catch {
      return chess;
    }
  }
  return chess;
}

function createChessId() {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");
}

async function chessPgEnabled() {
  if (!process.env.DATABASE_URL) return false;
  try {
    await pgInitPromise;
    return !!PG_READY;
  } catch {
    return false;
  }
}

function normalizeChessGameRow(row) {
  if (!row) return null;
  return {
    game_id: row.game_id ?? row.gameId,
    context_type: row.context_type ?? row.contextType,
    context_id: row.context_id ?? row.contextId,
    white_user_id: row.white_user_id ?? row.whiteUserId ?? null,
    black_user_id: row.black_user_id ?? row.blackUserId ?? null,
    fen: row.fen,
    pgn: row.pgn,
    status: row.status,
    turn: row.turn,
    result: row.result ?? null,
    rated: row.rated,
    rated_reason: row.rated_reason ?? row.ratedReason ?? null,
    plies_count: Number(row.plies_count ?? row.pliesCount ?? 0),
    draw_offer_by_user_id: row.draw_offer_by_user_id ?? row.drawOfferByUserId ?? null,
    draw_offer_at: row.draw_offer_at ?? row.drawOfferAt ?? null,
    white_elo_change: row.white_elo_change ?? row.whiteEloChange ?? null,
    black_elo_change: row.black_elo_change ?? row.blackEloChange ?? null,
    created_at: Number(row.created_at ?? row.createdAt ?? 0),
    updated_at: Number(row.updated_at ?? row.updatedAt ?? 0),
    last_move_at: Number(row.last_move_at ?? row.lastMoveAt ?? 0) || null,
  };
}

function normalizeChessChallengeRow(row) {
  if (!row) return null;
  return {
    challenge_id: row.challenge_id ?? row.challengeId,
    dm_thread_id: Number(row.dm_thread_id ?? row.dmThreadId ?? 0),
    challenger_user_id: Number(row.challenger_user_id ?? row.challengerUserId ?? 0),
    challenged_user_id: Number(row.challenged_user_id ?? row.challengedUserId ?? 0),
    status: row.status,
    created_at: Number(row.created_at ?? row.createdAt ?? 0),
    updated_at: Number(row.updated_at ?? row.updatedAt ?? 0),
  };
}

async function ensureChessStatsRow(userId) {
  const now = Date.now();
  if (!userId) return;
  if (await chessPgEnabled()) {
    try {
      await pgPool.query(
        `INSERT INTO chess_user_stats (user_id, chess_elo, chess_peak_elo, updated_at)
         VALUES ($1, $2, $2, $3)
         ON CONFLICT (user_id) DO NOTHING`,
        [userId, CHESS_DEFAULT_ELO, now]
      );
      return;
    } catch (e) {
      console.warn("[chess][pg] ensure stats failed:", e?.message || e);
    }
  }
  await dbRunAsync(
    `INSERT OR IGNORE INTO chess_user_stats (user_id, chess_elo, chess_peak_elo, updated_at)
     VALUES (?, ?, ?, ?)`,
    [userId, CHESS_DEFAULT_ELO, CHESS_DEFAULT_ELO, now]
  ).catch(() => {});
}

async function loadChessStats(userId) {
  if (!userId) return null;
  await ensureChessStatsRow(userId);
  if (await chessPgEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT user_id, chess_elo, chess_games_played, chess_wins, chess_losses, chess_draws, chess_peak_elo, chess_last_game_at, updated_at
         FROM chess_user_stats WHERE user_id = $1`,
        [userId]
      );
      return rows?.[0] || null;
    } catch (e) {
      console.warn("[chess][pg] load stats failed:", e?.message || e);
    }
  }
  return await dbGetAsync(
    `SELECT user_id, chess_elo, chess_games_played, chess_wins, chess_losses, chess_draws, chess_peak_elo, chess_last_game_at, updated_at
     FROM chess_user_stats WHERE user_id = ?`,
    [userId]
  ).catch(() => null);
}

function chessExpectedScore(ra, rb) {
  return 1 / (1 + Math.pow(10, (rb - ra) / 400));
}

function chessKFactor(rating, gamesPlayed) {
  if (Number(gamesPlayed) < 30) return 40;
  if (Number(rating) >= 2000) return 10;
  return 20;
}

function chessScoreForResult(result, color) {
  if (result === "draw") return 0.5;
  if (result === "white") return color === "white" ? 1 : 0;
  if (result === "black") return color === "black" ? 1 : 0;
  return 0;
}

function chessComputeElo(whiteStats, blackStats, result) {
  const whiteRating = Number(whiteStats?.chess_elo ?? CHESS_DEFAULT_ELO);
  const blackRating = Number(blackStats?.chess_elo ?? CHESS_DEFAULT_ELO);
  const whiteGames = Number(whiteStats?.chess_games_played ?? 0);
  const blackGames = Number(blackStats?.chess_games_played ?? 0);
  const expectedWhite = chessExpectedScore(whiteRating, blackRating);
  const expectedBlack = chessExpectedScore(blackRating, whiteRating);
  const scoreWhite = chessScoreForResult(result, "white");
  const scoreBlack = chessScoreForResult(result, "black");
  const whiteK = chessKFactor(whiteRating, whiteGames);
  const blackK = chessKFactor(blackRating, blackGames);
  const whiteNext = Math.round(whiteRating + whiteK * (scoreWhite - expectedWhite));
  const blackNext = Math.round(blackRating + blackK * (scoreBlack - expectedBlack));
  return {
    whiteNext,
    blackNext,
    whiteDelta: whiteNext - whiteRating,
    blackDelta: blackNext - blackRating,
  };
}

async function chessGetGameById(gameId) {
  if (!gameId) return null;
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(`SELECT * FROM chess_games WHERE game_id = $1`, [gameId]);
    return normalizeChessGameRow(rows?.[0] || null);
  }
  const row = await dbGetAsync(`SELECT * FROM chess_games WHERE game_id = ?`, [gameId]).catch(() => null);
  return normalizeChessGameRow(row);
}

async function chessGetActiveGameForContext(contextType, contextId) {
  if (!contextType || !contextId) return null;
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT * FROM chess_games
       WHERE context_type = $1 AND context_id = $2 AND status IN ('active', 'pending')
       ORDER BY updated_at DESC LIMIT 1`,
      [contextType, contextId]
    );
    return normalizeChessGameRow(rows?.[0] || null);
  }
  const row = await dbGetAsync(
    `SELECT * FROM chess_games
     WHERE context_type = ? AND context_id = ? AND status IN ('active', 'pending')
     ORDER BY updated_at DESC LIMIT 1`,
    [contextType, contextId]
  ).catch(() => null);
  return normalizeChessGameRow(row);
}

async function chessGetLatestGameForContext(contextType, contextId) {
  if (!contextType || !contextId) return null;
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT * FROM chess_games
       WHERE context_type = $1 AND context_id = $2
       ORDER BY updated_at DESC LIMIT 1`,
      [contextType, contextId]
    );
    return normalizeChessGameRow(rows?.[0] || null);
  }
  const row = await dbGetAsync(
    `SELECT * FROM chess_games
     WHERE context_type = ? AND context_id = ?
     ORDER BY updated_at DESC LIMIT 1`,
    [contextType, contextId]
  ).catch(() => null);
  return normalizeChessGameRow(row);
}

async function chessCreateGame(contextType, contextId, whiteId, blackId) {
  const now = Date.now();
  const gameId = createChessId();
  const chess = createChessInstance();
  const fen = chess.fen();
  const pgn = chess.pgn();
  const status = whiteId && blackId ? "active" : "pending";
  const turn = chess.turn();
  if (await chessPgEnabled()) {
    await pgPool.query(
      `INSERT INTO chess_games
       (game_id, context_type, context_id, white_user_id, black_user_id, fen, pgn, status, turn, created_at, updated_at, last_move_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [gameId, contextType, contextId, whiteId || null, blackId || null, fen, pgn, status, turn, now, now, now]
    );
  } else {
    await dbRunAsync(
      `INSERT INTO chess_games
       (game_id, context_type, context_id, white_user_id, black_user_id, fen, pgn, status, turn, created_at, updated_at, last_move_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [gameId, contextType, contextId, whiteId || null, blackId || null, fen, pgn, status, turn, now, now, now]
    );
  }
  return await chessGetGameById(gameId);
}

async function chessUpdateGame(gameId, updates = {}) {
  if (!gameId) return null;
  const now = Date.now();
  const columns = {
    white_user_id: updates.white_user_id,
    black_user_id: updates.black_user_id,
    fen: updates.fen,
    pgn: updates.pgn,
    status: updates.status,
    turn: updates.turn,
    result: updates.result,
    rated: updates.rated,
    rated_reason: updates.rated_reason,
    plies_count: updates.plies_count,
    draw_offer_by_user_id: updates.draw_offer_by_user_id,
    draw_offer_at: updates.draw_offer_at,
    white_elo_change: updates.white_elo_change,
    black_elo_change: updates.black_elo_change,
    updated_at: updates.updated_at ?? now,
    last_move_at: updates.last_move_at,
  };

  if (await chessPgEnabled()) {
    const set = [];
    const vals = [];
    let idx = 1;
    for (const [key, val] of Object.entries(columns)) {
      if (val === undefined) continue;
      set.push(`${key} = $${idx++}`);
      vals.push(val);
    }
    if (!set.length) return await chessGetGameById(gameId);
    vals.push(gameId);
    await pgPool.query(`UPDATE chess_games SET ${set.join(", ")} WHERE game_id = $${idx}`, vals);
  } else {
    const set = [];
    const vals = [];
    for (const [key, val] of Object.entries(columns)) {
      if (val === undefined) continue;
      set.push(`${key} = ?`);
      vals.push(val);
    }
    if (!set.length) return await chessGetGameById(gameId);
    vals.push(gameId);
    await dbRunAsync(`UPDATE chess_games SET ${set.join(", ")} WHERE game_id = ?`, vals);
  }
  return await chessGetGameById(gameId);
}

async function chessCreateChallenge(dmThreadId, challengerId, challengedId) {
  const now = Date.now();
  const challengeId = createChessId();
  if (await chessPgEnabled()) {
    await pgPool.query(
      `INSERT INTO chess_challenges
       (challenge_id, dm_thread_id, challenger_user_id, challenged_user_id, status, created_at, updated_at)
       VALUES ($1,$2,$3,$4,'pending',$5,$6)`,
      [challengeId, dmThreadId, challengerId, challengedId, now, now]
    );
  } else {
    await dbRunAsync(
      `INSERT INTO chess_challenges
       (challenge_id, dm_thread_id, challenger_user_id, challenged_user_id, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
      [challengeId, dmThreadId, challengerId, challengedId, now, now]
    );
  }
  return await chessGetChallengeById(challengeId);
}

async function chessGetChallengeById(challengeId) {
  if (!challengeId) return null;
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(`SELECT * FROM chess_challenges WHERE challenge_id = $1`, [challengeId]);
    return normalizeChessChallengeRow(rows?.[0] || null);
  }
  const row = await dbGetAsync(`SELECT * FROM chess_challenges WHERE challenge_id = ?`, [challengeId]).catch(() => null);
  return normalizeChessChallengeRow(row);
}

async function chessGetLatestChallengeForThread(dmThreadId) {
  if (!dmThreadId) return null;
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT * FROM chess_challenges WHERE dm_thread_id = $1 ORDER BY updated_at DESC LIMIT 1`,
      [dmThreadId]
    );
    return normalizeChessChallengeRow(rows?.[0] || null);
  }
  const row = await dbGetAsync(
    `SELECT * FROM chess_challenges WHERE dm_thread_id = ? ORDER BY updated_at DESC LIMIT 1`,
    [dmThreadId]
  ).catch(() => null);
  return normalizeChessChallengeRow(row);
}

async function chessUpdateChallenge(challengeId, updates = {}) {
  if (!challengeId) return null;
  const now = Date.now();
  const columns = {
    status: updates.status,
    updated_at: updates.updated_at ?? now,
  };
  if (await chessPgEnabled()) {
    const set = [];
    const vals = [];
    let idx = 1;
    for (const [key, val] of Object.entries(columns)) {
      if (val === undefined) continue;
      set.push(`${key} = $${idx++}`);
      vals.push(val);
    }
    if (!set.length) return await chessGetChallengeById(challengeId);
    vals.push(challengeId);
    await pgPool.query(`UPDATE chess_challenges SET ${set.join(", ")} WHERE challenge_id = $${idx}`, vals);
  } else {
    const set = [];
    const vals = [];
    for (const [key, val] of Object.entries(columns)) {
      if (val === undefined) continue;
      set.push(`${key} = ?`);
      vals.push(val);
    }
    if (!set.length) return await chessGetChallengeById(challengeId);
    vals.push(challengeId);
    await dbRunAsync(`UPDATE chess_challenges SET ${set.join(", ")} WHERE challenge_id = ?`, vals);
  }
  return await chessGetChallengeById(challengeId);
}

async function chessApplyEloUpdate(game, result) {
  const whiteId = Number(game.white_user_id || 0);
  const blackId = Number(game.black_user_id || 0);
  if (!whiteId || !blackId || whiteId === blackId) {
    return { rated: false, ratedReason: "invalid_players", whiteDelta: 0, blackDelta: 0 };
  }

  const whiteStats = await loadChessStats(whiteId);
  const blackStats = await loadChessStats(blackId);
  const { whiteNext, blackNext, whiteDelta, blackDelta } = chessComputeElo(whiteStats, blackStats, result);
  const now = Date.now();
  const whiteWins = Number(whiteStats?.chess_wins ?? 0);
  const whiteLosses = Number(whiteStats?.chess_losses ?? 0);
  const whiteDraws = Number(whiteStats?.chess_draws ?? 0);
  const blackWins = Number(blackStats?.chess_wins ?? 0);
  const blackLosses = Number(blackStats?.chess_losses ?? 0);
  const blackDraws = Number(blackStats?.chess_draws ?? 0);

  const whiteUpdate = {
    chess_elo: whiteNext,
    chess_games_played: Number(whiteStats?.chess_games_played ?? 0) + 1,
    chess_wins: whiteWins + (result === "white" ? 1 : 0),
    chess_losses: whiteLosses + (result === "black" ? 1 : 0),
    chess_draws: whiteDraws + (result === "draw" ? 1 : 0),
    chess_peak_elo: Math.max(Number(whiteStats?.chess_peak_elo ?? whiteNext), whiteNext),
    chess_last_game_at: now,
    updated_at: now,
  };

  const blackUpdate = {
    chess_elo: blackNext,
    chess_games_played: Number(blackStats?.chess_games_played ?? 0) + 1,
    chess_wins: blackWins + (result === "black" ? 1 : 0),
    chess_losses: blackLosses + (result === "white" ? 1 : 0),
    chess_draws: blackDraws + (result === "draw" ? 1 : 0),
    chess_peak_elo: Math.max(Number(blackStats?.chess_peak_elo ?? blackNext), blackNext),
    chess_last_game_at: now,
    updated_at: now,
  };

  if (await chessPgEnabled()) {
    await pgPool.query("BEGIN");
    try {
      await pgPool.query(
        `UPDATE chess_user_stats
         SET chess_elo = $2,
             chess_games_played = $3,
             chess_wins = $4,
             chess_losses = $5,
             chess_draws = $6,
             chess_peak_elo = $7,
             chess_last_game_at = $8,
             updated_at = $9
         WHERE user_id = $1`,
        [whiteId, whiteUpdate.chess_elo, whiteUpdate.chess_games_played, whiteUpdate.chess_wins, whiteUpdate.chess_losses, whiteUpdate.chess_draws, whiteUpdate.chess_peak_elo, whiteUpdate.chess_last_game_at, whiteUpdate.updated_at]
      );
      await pgPool.query(
        `UPDATE chess_user_stats
         SET chess_elo = $2,
             chess_games_played = $3,
             chess_wins = $4,
             chess_losses = $5,
             chess_draws = $6,
             chess_peak_elo = $7,
             chess_last_game_at = $8,
             updated_at = $9
         WHERE user_id = $1`,
        [blackId, blackUpdate.chess_elo, blackUpdate.chess_games_played, blackUpdate.chess_wins, blackUpdate.chess_losses, blackUpdate.chess_draws, blackUpdate.chess_peak_elo, blackUpdate.chess_last_game_at, blackUpdate.updated_at]
      );
      await pgPool.query("COMMIT");
    } catch (e) {
      await pgPool.query("ROLLBACK");
      throw e;
    }
  } else {
    await dbRunAsync("BEGIN");
    try {
      await dbRunAsync(
        `UPDATE chess_user_stats
         SET chess_elo = ?,
             chess_games_played = ?,
             chess_wins = ?,
             chess_losses = ?,
             chess_draws = ?,
             chess_peak_elo = ?,
             chess_last_game_at = ?,
             updated_at = ?
         WHERE user_id = ?`,
        [whiteUpdate.chess_elo, whiteUpdate.chess_games_played, whiteUpdate.chess_wins, whiteUpdate.chess_losses, whiteUpdate.chess_draws, whiteUpdate.chess_peak_elo, whiteUpdate.chess_last_game_at, whiteUpdate.updated_at, whiteId]
      );
      await dbRunAsync(
        `UPDATE chess_user_stats
         SET chess_elo = ?,
             chess_games_played = ?,
             chess_wins = ?,
             chess_losses = ?,
             chess_draws = ?,
             chess_peak_elo = ?,
             chess_last_game_at = ?,
             updated_at = ?
         WHERE user_id = ?`,
        [blackUpdate.chess_elo, blackUpdate.chess_games_played, blackUpdate.chess_wins, blackUpdate.chess_losses, blackUpdate.chess_draws, blackUpdate.chess_peak_elo, blackUpdate.chess_last_game_at, blackUpdate.updated_at, blackId]
      );
      await dbRunAsync("COMMIT");
    } catch (e) {
      await dbRunAsync("ROLLBACK");
      throw e;
    }
  }

  return { rated: true, ratedReason: null, whiteDelta, blackDelta };
}

async function chessFinalizeGame(game, { result, status, reason }) {
  const plies = Number(game.plies_count || 0);
  const whiteId = Number(game.white_user_id || 0);
  const blackId = Number(game.black_user_id || 0);
  const tooFewMoves = plies < CHESS_MIN_PLIES_RATED;
  const invalidPlayers = !whiteId || !blackId || whiteId === blackId;
  const rated = !tooFewMoves && !invalidPlayers;
  const ratedReason = rated ? null : (tooFewMoves ? "too_few_moves" : "invalid_players");
  let whiteDelta = 0;
  let blackDelta = 0;

  if (rated) {
    try {
      const eloResult = await chessApplyEloUpdate(game, result);
      whiteDelta = eloResult.whiteDelta;
      blackDelta = eloResult.blackDelta;
    } catch (e) {
      console.warn("[chess] Elo update failed:", e?.message || e);
    }
  }

  const updated = await chessUpdateGame(game.game_id, {
    status,
    result,
    rated,
    rated_reason: ratedReason,
    draw_offer_by_user_id: null,
    draw_offer_at: null,
    white_elo_change: rated ? whiteDelta : null,
    black_elo_change: rated ? blackDelta : null,
    updated_at: Date.now(),
    last_move_at: game.last_move_at || Date.now(),
  });

  return { game: updated, rated, ratedReason, whiteDelta, blackDelta };
}

function chessLegalMoves(fen) {
  const chess = createChessInstance(fen);
  return chess.moves({ verbose: true }).map((m) => ({
    from: m.from,
    to: m.to,
    promotion: m.promotion || null,
    san: m.san,
  }));
}

function isUsernameOnline(username) {
  if (!username) return false;
  return ONLINE_USERS.has(username);
}

function seatClaimable(game, seatUser) {
  if (!seatUser?.username) return false;
  if (isUsernameOnline(seatUser.username)) return false;
  const lastMoveAt = Number(game.last_move_at || game.updated_at || game.created_at || 0);
  return Date.now() - lastMoveAt > CHESS_SEAT_CLAIM_TIMEOUT_MS;
}

async function chessBuildGameState(game, viewerId) {
  if (!game) {
    return {
      gameId: null,
      status: "none",
      contextType: null,
      contextId: null,
      fen: null,
      pgn: "",
      turn: null,
      pliesCount: 0,
      whiteUser: null,
      blackUser: null,
      myColor: null,
      legalMoves: [],
      drawOfferBy: null,
      result: null,
      rated: null,
      ratedReason: null,
      whiteEloChange: null,
      blackEloChange: null,
      seatClaimable: { white: false, black: false },
    };
  }

  const whiteUser = game.white_user_id ? await getUserIdentityForMemory(game.white_user_id) : null;
  const blackUser = game.black_user_id ? await getUserIdentityForMemory(game.black_user_id) : null;
  const myColor =
    viewerId && Number(viewerId) === Number(game.white_user_id)
      ? "w"
      : viewerId && Number(viewerId) === Number(game.black_user_id)
        ? "b"
        : null;
  const drawOfferBy =
    game.draw_offer_by_user_id && Number(game.draw_offer_by_user_id) === Number(game.white_user_id)
      ? whiteUser
      : game.draw_offer_by_user_id && Number(game.draw_offer_by_user_id) === Number(game.black_user_id)
        ? blackUser
        : null;
  const legalMoves = game.status === "active" ? chessLegalMoves(game.fen) : [];

  return {
    gameId: game.game_id,
    contextType: game.context_type,
    contextId: game.context_id,
    fen: game.fen,
    pgn: game.pgn,
    status: game.status,
    turn: game.turn,
    pliesCount: game.plies_count,
    whiteUser,
    blackUser,
    myColor,
    legalMoves,
    drawOfferBy,
    result: game.result,
    rated: typeof game.rated === "boolean" ? game.rated : (game.rated == null ? null : !!game.rated),
    ratedReason: game.rated_reason || null,
    whiteEloChange: game.white_elo_change ?? null,
    blackEloChange: game.black_elo_change ?? null,
    seatClaimable: {
      white: game.context_type === "room" ? seatClaimable(game, whiteUser) : false,
      black: game.context_type === "room" ? seatClaimable(game, blackUser) : false,
    },
  };
}

async function chessBuildChallengeState(challenge) {
  if (!challenge) return null;
  const challenger = await getUserIdentityForMemory(challenge.challenger_user_id);
  const challenged = await getUserIdentityForMemory(challenge.challenged_user_id);
  return {
    challengeId: challenge.challenge_id,
    dmThreadId: challenge.dm_thread_id,
    status: challenge.status,
    challenger,
    challenged,
    createdAt: challenge.created_at,
    updatedAt: challenge.updated_at,
  };
}

async function emitChessStateToSocket(socket, game) {
  if (!socket) return;
  const payload = await chessBuildGameState(game, socket.user?.id || null);
  socket.emit("chess:game:state", payload);
}

async function emitChessStateToGameRoom(game) {
  if (!game?.game_id) return;
  const payload = await chessBuildGameState(game, null);
  io.to(`chess:${game.game_id}`).emit("chess:game:state", payload);
}

async function emitChessChallengeStateToRoom(dmThreadId, challenge) {
  const payload = await chessBuildChallengeState(challenge);
  if (!payload) return;
  io.to(`dm:${dmThreadId}`).emit("chess:challenge:state", payload);
}

async function emitChessChallengeStateToSocket(socket, challenge) {
  const payload = await chessBuildChallengeState(challenge);
  if (!payload) return;
  socket.emit("chess:challenge:state", payload);
}

async function insertDmChessMessage({ threadId, authorId, authorName, text }) {
  const ts = Date.now();
  const safeText = String(text || "").slice(0, MAX_DM_MESSAGE_CHARS);
  const payload = {
    threadId,
    messageId: null,
    userId: authorId,
    user: authorName,
    text: safeText,
    tone: "",
    ts,
    attachmentUrl: null,
    attachmentMime: null,
    attachmentType: null,
    attachmentSize: null,
    chatFx: null,
    replyToId: null,
    replyToUser: "",
    replyToText: "",
  };
  const result = await dbRunAsync(
    `INSERT INTO dm_messages (thread_id, user_id, username, text, tone, ts)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [threadId, authorId, authorName, safeText, "", ts]
  ).catch(() => null);
  if (result?.lastID) {
    payload.messageId = result.lastID;
    dbRunAsync(
      `UPDATE dm_threads SET last_message_id=?, last_message_at=? WHERE id=?`,
      [result.lastID, ts, threadId]
    ).catch(() => {});
    io.to(`dm:${threadId}`).emit("dm message", payload);
  }
}

let FEATURE_FLAGS_CACHE = {};
async function refreshFeatureFlags() {
  try {
    FEATURE_FLAGS_CACHE = await getConfigJson("feature_flags", {});
  } catch {
    FEATURE_FLAGS_CACHE = {};
  }
  return FEATURE_FLAGS_CACHE;
}

function parseFeatureAllowlist(value) {
  if (!value) return new Set();
  if (Array.isArray(value)) {
    return new Set(value.map((item) => String(item).trim().toLowerCase()).filter(Boolean));
  }
  if (typeof value === "string") {
    return new Set(
      value
        .split(",")
        .map((item) => String(item).trim().toLowerCase())
        .filter(Boolean)
    );
  }
  return new Set();
}

function isCouplesV2EnabledFor(user, flags = FEATURE_FLAGS_CACHE) {
  const enabled = !!(flags && flags.COUPLES_V2_ENABLED);
  if (!enabled) return false;

  // Owners always get access (for management/testing).
  if (requireMinRole(user?.role || "User", "Owner")) return true;

  // If no allowlist is configured, treat Couples V2 as globally enabled.
  // (This avoids the "only the acceptor sees options" problem when allowlist is empty/misconfigured.)
  const allowlist = parseFeatureAllowlist(flags?.COUPLES_V2_ALLOWLIST);
  if (!allowlist.size) return true;

  const username = String(user?.username || "").trim().toLowerCase();
  const userId = user?.id ?? user?.user_id ?? user?.userId;
  if (username && allowlist.has(username)) return true;
  if (userId != null && allowlist.has(String(userId).toLowerCase())) return true;
  return false;
}

refreshFeatureFlags().catch(() => {});

function isMemoryFeatureAvailableFor(user) {
  if (MEMORY_SYSTEM_ENABLED) return true;
  const username = String(user?.username || "").toLowerCase();
  const role = user?.role || "User";
  if (requireMinRole(role, "Owner")) return true;
  return MEMORY_SYSTEM_ALLOWLIST.has(username);
}

function normalizeMemoryBool(value) {
  return value === true || value === 1 || value === "1";
}

async function getMemorySettingsRow(userId) {
  try {
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query(
        "SELECT enabled, last_seen_at FROM memory_settings WHERE user_id = $1 LIMIT 1",
        [userId]
      );
      return rows[0] || null;
    }
  } catch (e) {
    console.warn("[memory][pg settings]", e?.message || e);
  }

  try {
    return await dbGetAsync("SELECT enabled, last_seen_at FROM memory_settings WHERE user_id = ?", [userId]);
  } catch (e) {
    console.warn("[memory][sqlite settings]", e?.message || e);
    return null;
  }
}

async function setMemorySettingsRow(userId, enabled) {
  const isEnabled = !!enabled;
  try {
    if (await pgUserExists(userId)) {
      await pgPool.query(
        `
        INSERT INTO memory_settings (user_id, enabled)
        VALUES ($1, $2)
        ON CONFLICT (user_id) DO UPDATE SET enabled = EXCLUDED.enabled
        `,
        [userId, isEnabled]
      );
      return;
    }
  } catch (e) {
    console.warn("[memory][pg settings set]", e?.message || e);
  }

  await dbRunAsync(
    `
    INSERT INTO memory_settings (user_id, enabled)
    VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET enabled = excluded.enabled
    `,
    [userId, isEnabled ? 1 : 0]
  );
}

async function getMemorySettingsForUser(user) {
  const available = isMemoryFeatureAvailableFor(user);
  if (!available) return { available: false, enabled: false, lastSeenAt: null };

  const row = await getMemorySettingsRow(user.id);
  const enabled = row ? normalizeMemoryBool(row.enabled) : MEMORY_SYSTEM_ENABLED;
  const lastSeenAt = row?.last_seen_at ?? row?.lastSeenAt ?? null;
  return { available: true, enabled: !!enabled, lastSeenAt };
}

async function getUserIdentityForMemory(userId, hint) {
  if (hint?.id && hint?.username) {
    return { id: Number(hint.id), username: hint.username, role: hint.role || "User" };
  }
  try {
    if (await pgUserExists(userId)) {
      const row = await pgGetUserRowById(userId, ["id", "username", "role"]);
      if (row) return { id: Number(row.id), username: row.username, role: row.role || "User" };
    }
  } catch (e) {
    console.warn("[memory][pg user]", e?.message || e);
  }
  try {
    const row = await dbGetAsync("SELECT id, username, role FROM users WHERE id = ?", [userId]);
    if (row) return { id: Number(row.id), username: row.username, role: row.role || "User" };
  } catch (e) {
    console.warn("[memory][sqlite user]", e?.message || e);
  }
  return null;
}

function normalizeMemoryRow(row) {
  if (!row) return null;
  const metadata = row.metadata == null ? null : (typeof row.metadata === "object" ? row.metadata : safeJsonParse(row.metadata, null));
  return {
    id: Number(row.id),
    user_id: row.user_id ?? row.userId ?? null,
    room_id: row.room_id ?? row.roomId ?? null,
    type: row.type,
    key: row.key,
    title: row.title,
    description: row.description || "",
    icon: row.icon || "",
    created_at: Number(row.created_at ?? row.createdAt ?? Date.now()),
    metadata,
    visibility: row.visibility || "private",
    pinned: normalizeMemoryBool(row.pinned),
    seen: normalizeMemoryBool(row.seen),
  };
}

async function ensureMemory(userId, key, payload, userHint) {
  const identity = await getUserIdentityForMemory(userId, userHint);
  if (!identity || !key) return null;

  const settings = await getMemorySettingsForUser(identity);
  if (!settings.available || !settings.enabled) return null;

  const now = Date.now();
  const memory = {
    user_id: identity.id,
    room_id: payload.room_id ?? payload.roomId ?? null,
    type: payload.type || "event",
    key: String(key),
    title: String(payload.title || "Memory"),
    description: payload.description ? String(payload.description) : "",
    icon: payload.icon ? String(payload.icon) : "",
    created_at: Number(payload.created_at || payload.createdAt || now),
    metadata: payload.metadata ?? null,
    visibility: payload.visibility || "private",
  };

  try {
    if (await pgUserExists(identity.id)) {
      const { rows } = await pgPool.query(
        `
        INSERT INTO memories (user_id, room_id, type, key, title, description, icon, created_at, metadata, visibility, pinned, seen)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false,false)
        ON CONFLICT (user_id, key) DO NOTHING
        RETURNING *
        `,
        [
          memory.user_id,
          memory.room_id,
          memory.type,
          memory.key,
          memory.title,
          memory.description,
          memory.icon,
          memory.created_at,
          memory.metadata,
          memory.visibility,
        ]
      );
      const created = normalizeMemoryRow(rows[0]);
      if (created) {
        const sid = socketIdByUserId.get(identity.id);
        if (sid) io.to(sid).emit("memory:created", created);
      }
      return created;
    }
  } catch (e) {
    console.warn("[memory][pg ensure]", e?.message || e);
  }

  const metadataJson = memory.metadata == null ? null : JSON.stringify(memory.metadata);
  const result = await dbRunAsync(
    `
    INSERT OR IGNORE INTO memories (user_id, room_id, type, key, title, description, icon, created_at, metadata, visibility, pinned, seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
    `,
    [
      memory.user_id,
      memory.room_id,
      memory.type,
      memory.key,
      memory.title,
      memory.description,
      memory.icon,
      memory.created_at,
      metadataJson,
      memory.visibility,
    ]
  );
  if (!result?.changes) return null;
  const row = await dbGetAsync("SELECT * FROM memories WHERE id = ?", [result.lastID]);
  const created = normalizeMemoryRow(row);
  if (created) {
    const sid = socketIdByUserId.get(identity.id);
    if (sid) io.to(sid).emit("memory:created", created);
  }
  return created;
}

const MEMORY_FILTER_TYPES = {
  all: null,
  social: ["social"],
  progress: ["progress", "milestone", "streak"],
  media: ["media"],
  rooms: ["room"],
  rare: ["rare"],
};

function resolveMemoryTypes(filter) {
  const key = String(filter || "all").toLowerCase();
  return MEMORY_FILTER_TYPES[key] ?? null;
}



// Serialize XP updates per user to prevent race conditions between concurrent XP events.
async function withXpLock(userId, fn) {
  const prev = xpUpdateLocks.get(userId) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  xpUpdateLocks.set(userId, prev.then(() => gate));
  await prev;
  try {
    return await fn();
  } finally {
    release();
    if (xpUpdateLocks.get(userId) === gate) xpUpdateLocks.delete(userId);
  }
}

function buildXpUpdateFields(newXp, opts = {}, forPg = false) {
  const sets = [forPg ? "xp = $1" : "xp = ?"];
  const params = [newXp];
  let idx = 2;

  const lastMessageXpAt = opts.lastMessageXpAt ?? opts.lastXpMessageAt ?? null;
  const lastLoginXpAt = opts.lastLoginXpAt ?? null;
  const lastOnlineXpAt = opts.lastOnlineXpAt ?? null;
  const lastDailyLoginAt = opts.lastDailyLoginAt ?? null;
  const lastXpMessageAt = opts.lastXpMessageAt ?? null;

  if (lastMessageXpAt != null) {
    sets.push(forPg ? `"lastMessageXpAt" = $${idx}` : "lastMessageXpAt = ?");
    params.push(lastMessageXpAt);
    idx += 1;
  }
  if (lastLoginXpAt != null) {
    sets.push(forPg ? `"lastLoginXpAt" = $${idx}` : "lastLoginXpAt = ?");
    params.push(lastLoginXpAt);
    idx += 1;
  }
  if (lastOnlineXpAt != null) {
    sets.push(forPg ? `"lastOnlineXpAt" = $${idx}` : "lastOnlineXpAt = ?");
    params.push(lastOnlineXpAt);
    idx += 1;
  }
  if (lastDailyLoginAt != null) {
    sets.push(forPg ? `"lastDailyLoginAt" = $${idx}` : "lastDailyLoginAt = ?");
    params.push(lastDailyLoginAt);
    idx += 1;
  }
  if (lastXpMessageAt != null) {
    sets.push(forPg ? `"lastXpMessageAt" = $${idx}` : "lastXpMessageAt = ?");
    params.push(lastXpMessageAt);
  }

  return { sets, params };
}

async function spendGoldInTransaction(client, userId, amount, reason) {
  const spendAmount = Math.max(0, Math.floor(Number(amount) || 0));
  if (!spendAmount || !Number.isFinite(spendAmount)) {
    return { ok: false, error: "INVALID_AMOUNT", message: "Invalid spend amount." };
  }
  const spendReason = String(reason || "").trim();
  if (!spendReason) {
    return { ok: false, error: "INVALID_REASON", message: "Missing spend reason." };
  }

  const { rows } = await client.query("SELECT gold FROM users WHERE id = $1 FOR UPDATE", [userId]);
  const row = rows?.[0];
  if (!row) return { ok: false, error: "NOT_FOUND", message: "User not found." };

  const current = Number(row.gold || 0);
  if (current < spendAmount) {
    return { ok: false, error: "INSUFFICIENT_GOLD", message: "Not enough gold.", gold: current };
  }

  const nextGold = current - spendAmount;
  await client.query("UPDATE users SET gold = $1 WHERE id = $2", [nextGold, userId]);
  await client.query(
    "INSERT INTO gold_transactions (user_id, amount, reason, created_at) VALUES ($1, $2, $3, $4)",
    [userId, spendAmount, spendReason, Date.now()]
  );
  return { ok: true, gold: nextGold };
}

// Centralized gold spending helper: atomic deduction + ledger logging for extensibility.
async function spendGold(userId, amount, reason, opts = {}) {
  if (!(await pgUsersEnabled())) {
    return { ok: false, error: "PG_UNAVAILABLE", message: "Gold spending is unavailable right now." };
  }
  const client = opts.client || await pgPool.connect();
  const manageTx = !opts.client;
  try {
    if (manageTx) await client.query("BEGIN");
    const result = await spendGoldInTransaction(client, userId, amount, reason);
    if (!result.ok) {
      if (manageTx) await client.query("ROLLBACK");
      return result;
    }
    if (manageTx) await client.query("COMMIT");
    return result;
  } catch (e) {
    if (manageTx) {
      try { await client.query("ROLLBACK"); } catch {}
    }
    throw e;
  } finally {
    if (manageTx) client.release();
  }
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
      if (sid) io.to(sid).emit("system", buildSystemPayload("__global__", "You were warned by " + actor.username + ": " + reason, { kind: "global" }));
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
        await dbRunAsync(`DELETE FROM reactions WHERE message_id=?`, [r.id]);
        io.to(room).emit("messageDeleted", { messageId: r.id, roomId: room });
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
      try {
        const caseRow = await createModCase({
          type: "flag",
          subjectUserId: target.id,
          createdByUserId: actor?.id || null,
          title: `Report: @${target.username}`,
          summary: reason,
        });
        if (caseRow?.id) {
          await addModCaseEvent(caseRow.id, {
            actorUserId: actor?.id || null,
            eventType: "flag_created",
            payload: { reportedUserId: target.id, reason },
          });
          emitToStaff("mod:case_created", { id: caseRow.id, type: caseRow.type, status: caseRow.status });
        }
      } catch {}
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
    handler: async ({ args, room, actor }) => {
      const name = sanitizeRoomName(args[0] || "");
      if (!name) return { ok: false, message: "Invalid room" };
      const resolved = await resolveRoomCategoryId({ isUserRoom: false });
      const categoryId = resolved?.categoryId ?? null;
      let nextSort = { maxSort: 0, maxsort: 0 };
      if (categoryId) {
        if (await pgUsersEnabled()) {
          const { rows } = await pgPool.query(
            `SELECT COALESCE(MAX(room_sort_order), 0) as maxsort FROM rooms WHERE category_id = $1`,
            [categoryId]
          );
          nextSort = rows?.[0] || nextSort;
        } else {
          nextSort = await dbGetAsync(
            `SELECT COALESCE(MAX(room_sort_order), 0) as maxSort FROM rooms WHERE category_id = ?`,
            [categoryId]
          );
        }
      }
      const sortOrder = Number(nextSort?.maxsort || nextSort?.maxSort || 0) + 1;
      if (await pgUsersEnabled()) {
        await pgPool.query(
          `INSERT INTO rooms (name, created_by, created_at, category_id, room_sort_order, created_by_user_id, is_user_room, is_system)
           VALUES ($1, $2, $3, $4, $5, $6, 0, 0)
           ON CONFLICT (name) DO NOTHING`,
          [name, actor.id, Date.now(), categoryId, sortOrder, actor.id]
        );
      } else {
        await dbRunAsync(
          `INSERT OR IGNORE INTO rooms (name, created_by, created_at, category_id, room_sort_order, created_by_user_id, is_user_room, is_system)
           VALUES (?, ?, ?, ?, ?, ?, 0, 0)`,
          [name, actor.id, Date.now(), categoryId, sortOrder, actor.id]
        );
      }
      await applyRoomStructureChange({
        action: "room.create",
        actorUserId: actor?.id,
        auditPayload: { name, category_id: categoryId },
      });
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
      if (await pgUsersEnabled()) {
        await pgPool.query(`DELETE FROM rooms WHERE name=$1`, [name]);
        await pgPool.query(`DELETE FROM messages WHERE room=$1`, [name]).catch(() => {});
      } else {
        await dbRunAsync(`DELETE FROM rooms WHERE name=?`, [name]);
        await dbRunAsync(`DELETE FROM messages WHERE room=?`, [name]);
      }
      await applyRoomStructureChange({
        action: "room.delete",
        actorUserId: null,
        auditPayload: { name },
      });
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
    handler: async ({ rawArgs }) => {
      const parsed = parseUserAndAmountArgs(rawArgs, "amount");
      if (parsed.error) return { ok: false, message: parsed.error };
      const target = await new Promise((resolve, reject) => findUserByMention(parsed.userRaw, (e, u) => (e ? reject(e) : resolve(u))));
      const amt = Number(parsed.amount);
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
    handler: async ({ rawArgs }) => {
      const parsed = parseUserAndAmountArgs(rawArgs, "amount");
      if (parsed.error) return { ok: false, message: parsed.error };
      const target = await new Promise((resolve, reject) => findUserByMention(parsed.userRaw, (e, u) => (e ? reject(e) : resolve(u))));
      const amt = Number(parsed.amount);
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
    handler: async ({ rawArgs }) => {
      const parsed = parseUserAndAmountArgs(rawArgs, "level");
      if (parsed.error) return { ok: false, message: parsed.error };
      const level = Number(parsed.amount);
      if (!Number.isFinite(level) || level < 1) return { ok: false, message: "Invalid level." };
      const target = await new Promise((resolve, reject) => findUserByMention(parsed.userRaw, (e, u) => (e ? reject(e) : resolve(u))));
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
      emitGlobalSystem("[Announcement] " + msg);
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
      emitGlobalSystem("Maintenance mode " + val);
      return { ok: true, message: `Maintenance ${val}` };
    },
  },
  event: {
    minRole: "Admin",
    description: "Start/stop a room event (admin+)",
    usage: "/event start <announcement|prompt|flair> <minutes> <text...> | /event stop",
    example: "/event start prompt 10 Quick Trivia",
    handler: async ({ args, actor }) => {
      const sub = String(args[0] || "").toLowerCase();
      if (!room) return { ok: false, message: "Join a room first." };

      if (sub === "stop") {
        const existing = ACTIVE_ROOM_EVENTS.get(room);
        if (!existing) return { ok: false, message: "No active room event." };
        ACTIVE_ROOM_EVENTS.delete(room);
        await syncActiveRoomEvents();
        io.to(room).emit("room:event", { room, active: null, at: Date.now() });
        return { ok: true, message: "Room event cleared." };
      }

      if (sub !== "start") return { ok: false, message: "Use /event start ... or /event stop" };

      const type = String(args[1] || "").toLowerCase();
      const allowed = new Set(["announcement", "prompt", "flair"]);
      if (!allowed.has(type)) return { ok: false, message: "Type must be announcement, prompt, or flair." };
      const mins = Math.max(1, Math.min(120, Math.floor(Number(args[2]) || 10)));
      const rawText = String(args.slice(3).join(" ") || "").trim();
      if (type === "announcement" && !rawText) return { ok: false, message: "Announcement text required." };
      const resolvedText = type === "prompt" ? (rawText || selectPromptText()) : rawText;
      const title = resolvedText ? resolvedText.slice(0, 80) : type === "flair" ? "Visual Flair" : "Room Event";
      const ev = {
        id: ROOM_EVENT_SEQ++,
        type,
        title,
        payload: { text: resolvedText },
        startedBy: actor?.username || "",
        startedAt: Date.now(),
        endsAt: Date.now() + mins * 60_000,
      };
      await addRoomEvent(room, ev);
      io.to(room).emit("room:event", { room, active: ev, at: Date.now() });
      if (type === "announcement" || type === "prompt") {
        emitRoomSystem(room, resolvedText || "💬 Prompt event started.");
      }
      return { ok: true, message: `Room event '${title}' started.` };
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
  rebuildleaderboards: {
    minRole: "Owner",
    description: "Rebuild leaderboards",
    usage: "/rebuildleaderboards",
    example: "/rebuildleaderboards",
    handler: async () => {
      // Safe rebuild path for admins to refresh leaderboard data on demand.
      await rebuildLeaderboards({ force: true });
      io.emit("leaderboard:update");
      return { ok: true, message: "Leaderboards rebuilt." };
    },
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
    const result = await meta.handler({ args: parsed.args, rawArgs: parsed.rawArgs, room, socket, actor, actorRole, rawText });
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
const VIP_PLUS_ROLES = new Set(["vip", "moderator", "admin", "co owner", "co-owner", "owner"]);

function isVipPlus(role) {
  const norm = String(role || "").toLowerCase();
  return VIP_PLUS_ROLES.has(norm);
}

function roleRankServer(role) {
  const order = ["Guest","User","VIP","VIP+","Moderator","Admin","Co-owner","Owner"];
  const idx = order.findIndex(r => (r||"").toLowerCase() === (role||"").toLowerCase());
  return idx === -1 ? 1 : idx;
}

function canAccessRoomBySettings(user, roomRow) {
  if (!user || !roomRow) return true;
  const role = user.role || "User";
  const level = Number(user.level || 0);
  const staffOnly = Number(roomRow.staff_only || 0) === 1;
  const vipOnly = Number(roomRow.vip_only || 0) === 1;
  const minLevel = Number(roomRow.min_level || 0) || 0;
  if (staffOnly && roleRankServer(role) < roleRankServer("Moderator")) return false;
  if (vipOnly && !isVipPlus(role)) return false;
  if (minLevel > 0 && level < minLevel) return false;
  return true;
}

function isCoreRoomName(name) {
  return CORE_ROOM_NAMES.has(String(name || "").toLowerCase());
}


function xpRatesForRole(role) {
  const vip = isVipPlus(role);
  return {
    online: vip ? 2 : 1,
    message: vip ? 10 : 3,
    login: vip ? 25 : 15,
  };
}

const MEMORY_LEVEL_MILESTONES = new Set([5, 10, 25]);

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

function liveRoleForUser(userId, fallbackRole = "User") {
  const sid = socketIdByUserId.get(userId);
  const sock = sid ? io.sockets.sockets.get(sid) : null;
  return sock?.user?.role || fallbackRole || "User";
}

async function primeOnlineXpTracker(userId) {
  const fallback = { lastTs: Date.now(), carryMs: 0 };
  onlineXpTrack.set(userId, fallback);
  try {
    const row = await getProgressionRow(userId);
    const last = Number(row?.lastOnlineXpAt || 0);
    if (Number.isFinite(last) && last > 0) {
      onlineXpTrack.set(userId, { lastTs: last, carryMs: 0 });
    }
  } catch (e) {
    console.warn("[xp][prime online]", e?.message || e);
  }
}

let leaderboardUpdateTimer = null;
function emitLeaderboardUpdateThrottled() {
  if (leaderboardUpdateTimer) return;
  leaderboardUpdateTimer = setTimeout(() => {
    leaderboardUpdateTimer = null;
    io.emit("leaderboard:update");
  }, 500);
}

async function getProgressionRow(userId) {
  try {
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query(
        'SELECT username, role, xp, "lastMessageXpAt", "lastLoginXpAt", "lastOnlineXpAt", "lastXpMessageAt", "lastDailyLoginAt" FROM users WHERE id=$1 LIMIT 1',
        [userId]
      );
      if (rows?.[0]) return rows[0];
    }
  } catch (e) {
    console.warn("[xp][pg fetch]", e?.message || e);
  }

  return await new Promise((resolve) => {
    db.get(
      "SELECT username, role, xp, lastMessageXpAt, lastLoginXpAt, lastOnlineXpAt, lastXpMessageAt, lastDailyLoginAt FROM users WHERE id = ?",
      [userId],
      (_e, row) => resolve(row || null)
    );
  });
}

async function persistXpState(userId, data) {
  const newXp = Math.max(0, Math.floor(Number(data.xp) || 0));
  const lastMessageXpAt = data.lastMessageXpAt ?? null;
  const lastLoginXpAt = data.lastLoginXpAt ?? null;
  const lastOnlineXpAt = data.lastOnlineXpAt ?? null;
  const lastDailyLoginAt = data.lastDailyLoginAt ?? null;
  const lastXpMessageAt = data.lastXpMessageAt ?? null;

  try {
    if (await pgUserExists(userId)) {
      const sets = ["xp = $1"];
      const params = [newXp];
      let idx = 2;
      if (lastMessageXpAt != null) {
        sets.push(`"lastMessageXpAt" = $${idx}`);
        params.push(lastMessageXpAt);
        idx += 1;
        sets.push(`"lastXpMessageAt" = $${idx}`);
        params.push(lastMessageXpAt);
        idx += 1;
      }
      if (lastLoginXpAt != null) {
        sets.push(`"lastLoginXpAt" = $${idx}`);
        params.push(lastLoginXpAt);
        idx += 1;
      }
      if (lastOnlineXpAt != null) {
        sets.push(`"lastOnlineXpAt" = $${idx}`);
        params.push(lastOnlineXpAt);
        idx += 1;
      }
      if (lastDailyLoginAt != null) {
        sets.push(`"lastDailyLoginAt" = $${idx}`);
        params.push(lastDailyLoginAt);
        idx += 1;
      }
      if (lastXpMessageAt != null) {
        sets.push(`"lastXpMessageAt" = $${idx}`);
        params.push(lastXpMessageAt);
        idx += 1;
      }
      params.push(userId);
      await pgPool.query(`UPDATE users SET ${sets.join(", ")} WHERE id = $${idx}`, params);
    }
  } catch (e) {
    console.warn("[xp][pg persist]", e?.message || e);
  }

  const sqliteSets = ["xp = ?"];
  const sqliteParams = [newXp];
  if (lastMessageXpAt != null) {
    sqliteSets.push("lastMessageXpAt = ?", "lastXpMessageAt = ?");
    sqliteParams.push(lastMessageXpAt, lastMessageXpAt);
  }
  if (lastLoginXpAt != null) {
    sqliteSets.push("lastLoginXpAt = ?");
    sqliteParams.push(lastLoginXpAt);
  }
  if (lastOnlineXpAt != null) {
    sqliteSets.push("lastOnlineXpAt = ?");
    sqliteParams.push(lastOnlineXpAt);
  }
  if (lastDailyLoginAt != null) {
    sqliteSets.push("lastDailyLoginAt = ?");
    sqliteParams.push(lastDailyLoginAt);
  }
  if (lastXpMessageAt != null) {
    sqliteSets.push("lastXpMessageAt = ?");
    sqliteParams.push(lastXpMessageAt);
  }

  return await dbRunAsync(`UPDATE users SET ${sqliteSets.join(", ")} WHERE id = ?`, [...sqliteParams, userId]);
}

async function maybeCreateLevelMemories(userId, prevLevel, nextLevel) {
  if (!Number.isFinite(prevLevel) || !Number.isFinite(nextLevel)) return;
  for (const milestone of MEMORY_LEVEL_MILESTONES) {
    if (milestone > prevLevel && milestone <= nextLevel) {
      await ensureMemory(userId, `level_${milestone}`, {
        type: "progress",
        title: `Level ${milestone} reached`,
        description: `You hit level ${milestone}.`,
        icon: "⭐",
        metadata: { level: milestone },
      });
    }
  }
}

async function applyXpGain(userId, delta, opts = {}) {
  const amount = Math.max(0, Math.floor(Number(delta) || 0));
  if (!amount) return null;

  return withXpLock(userId, async () => {
    let prevXp = 0;
    let prevLevel = 1;
    let newXp = 0;
    let info = null;

    if (await pgUserExists(userId)) {
      const client = await pgPool.connect();
      try {
        await client.query("BEGIN");
        const { rows } = await client.query(
          'SELECT xp FROM users WHERE id = $1 FOR UPDATE',
          [userId]
        );
        const baseRow = rows?.[0];
        if (!baseRow) {
          await client.query("ROLLBACK");
          return null;
        }

        prevXp = Math.max(0, Math.floor(Number(baseRow.xp) || 0));
        prevLevel = levelInfo(prevXp).level;
        newXp = prevXp + amount;
        info = levelInfo(newXp);

        const { sets, params } = buildXpUpdateFields(newXp, opts, true);
        params.push(userId);
        await client.query(`UPDATE users SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
        await client.query("COMMIT");
      } catch (e) {
        try { await client.query("ROLLBACK"); } catch {}
        console.warn("[xp][pg apply]", e?.message || e);
        return null;
      } finally {
        client.release();
      }

      // Best-effort mirror to SQLite so fallback reads don't show stale XP.
      try {
        const sqliteUpdate = buildXpUpdateFields(newXp, opts, false);
        await dbRunAsync(
          `UPDATE users SET ${sqliteUpdate.sets.join(", ")} WHERE id = ?`,
          [...sqliteUpdate.params, userId]
        );
      } catch (e) {
        console.warn("[xp][sqlite mirror]", e?.message || e);
      }
    } else {
      const baseRow = opts.baseRow || (await getProgressionRow(userId));
      if (!baseRow) return null;

      prevXp = Math.max(0, Math.floor(Number(baseRow.xp) || 0));
      prevLevel = levelInfo(prevXp).level;
      newXp = prevXp + amount;
      info = levelInfo(newXp);

      await persistXpState(userId, {
        xp: newXp,
        lastMessageXpAt: opts.lastMessageXpAt ?? opts.lastXpMessageAt ?? null,
        lastXpMessageAt: opts.lastXpMessageAt ?? null,
        lastLoginXpAt: opts.lastLoginXpAt ?? null,
        lastDailyLoginAt: opts.lastDailyLoginAt ?? null,
        lastOnlineXpAt: opts.lastOnlineXpAt ?? null,
      });
    }

    // Emit level-up only after the committed XP write to avoid racey toasts.
    if (info && info.level > prevLevel) {
      emitLevelUp(userId, info.level);
      void maybeCreateLevelMemories(userId, prevLevel, info.level);
    }
    emitProgressionUpdate(userId);
    emitLeaderboardUpdateThrottled();
    return info ? { xp: newXp, ...info } : null;
  });
}

async function awardMessageXp(userId, roleHint, roomName) {
  const now = Date.now();
  const row = await getProgressionRow(userId);
  if (!row) return;
  const last = Number(row.lastMessageXpAt ?? row.lastXpMessageAt ?? 0);
  if (last && now - last < 5 * 60 * 1000) {
    console.log(`[xp][msg] cooldown user=${userId}`);
    return;
  }

  const role = roleHint || row.role || "User";
  let delta = xpRatesForRole(role).message;
  const result = await applyXpGain(userId, delta, {
    baseRow: row,
    lastMessageXpAt: now,
    lastXpMessageAt: now,
  });
  if (result) console.log(`[xp][msg] +${delta} user=${userId} role=${role}`);
}

async function awardLoginXp(userId, roleHint) {
  const now = Date.now();
  const row = await getProgressionRow(userId);
  if (!row) return;
  const last = Number(row.lastLoginXpAt ?? row.lastDailyLoginAt ?? 0);
  if (last && now - last < 24 * 60 * 60 * 1000) {
    console.log(`[xp][login] cooldown user=${userId}`);
    return;
  }

  const role = roleHint || row.role || "User";
  const delta = xpRatesForRole(role).login;
  const result = await applyXpGain(userId, delta, {
    baseRow: row,
    lastLoginXpAt: now,
    lastDailyLoginAt: now,
  });
  if (result) console.log(`[xp][login] +${delta} user=${userId} role=${role}`);
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
  if (!PG_ENABLED || !pgPool) return false;
  try {
    await pgInitPromise;
    return PG_READY;
  } catch (e) {
    return false;
  }
}

async function ensureDevSeedUser() {
  if (!IS_DEV_MODE) return;
  const seed = {
    username: "Iri",
    password: "Perseverance75",
    role: "Owner",
  };
  try {
    if (PG_READY && pgPool) {
      const hash = await bcrypt.hash(seed.password, 10);
      await pgPool.query(
        `
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (username)
        DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
        `,
        [seed.username, hash, seed.role, Date.now()]
      );
      return;
    }
  } catch (e) {
    console.warn("[seed][pg] failed, falling back to sqlite:", e?.message || e);
  }
  try {
    await seedDevUser(seed);
  } catch (e) {
    console.warn("[seed][sqlite] failed:", e?.message || e);
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
        `SELECT id, username FROM users WHERE username = ANY($1::text[])
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

async function fetchSurvivalUserSnapshots(userIds) {
  const cleaned = Array.from(
    new Set((userIds || [])
      .map((id) => Number(id))
      .filter((id) => Number.isInteger(id) && id > 0))
  );
  if (!cleaned.length) return [];

  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT id, username, avatar, avatar_bytes, avatar_mime, avatar_updated FROM users WHERE id = ANY($1::int[])`,
        [cleaned]
      );
      return (rows || []).map((row) => ({
        id: row.id,
        username: row.username,
        avatar: avatarUrlFromRow(row) || null,
      }));
    } catch (e) {
      console.warn("[survival][pg] snapshot failed, falling back to sqlite:", e?.message || e);
    }
  }

  const placeholders = cleaned.map(() => "?").join(",");
  const rows = await dbAllAsync(
    `SELECT id, username, avatar, avatar_updated FROM users WHERE id IN (${placeholders})`,
    cleaned
  );
  return (rows || []).map((row) => ({
    id: row.id,
    username: row.username,
    avatar: avatarUrlFromRow(row) || null,
  }));
}

function sanitizeRoomName(r) {
  r = String(r || "").trim();
  r = r.replace(/^#+/, "");      // drop leading '#'
  r = r.toLowerCase();
  r = r.replace(/[^a-z0-9_-]/g, "");
  return r.slice(0, 24);
}

function sanitizeDisplayName(name) {
  return String(name || "").replace(/[<>"'&]/g, "").trim();
}

// Must match the client arena map zone labels.
const SURVIVAL_ZONES = [
  "Pine Woods",
  "Old Ruins",
  "Ridge",
  "Shimmer Lake",
  "Central Plaza",
  "Cave Mouth",
  "Mossy Swamp",
  "Supply Drop Zone",
];
const SURVIVAL_ZONE_ALIASES = new Map([
  ["open field", "Central Plaza"],
  ["rocky ridge", "Ridge"],
  ["ruins", "Old Ruins"],
  ["river bend", "Shimmer Lake"],
  ["caves", "Cave Mouth"],
  ["swamp", "Mossy Swamp"],
  ["cornucopia", "Supply Drop Zone"],
  ["pine woods", "Pine Woods"],
  ["old ruins", "Old Ruins"],
  ["ridge", "Ridge"],
  ["shimmer lake", "Shimmer Lake"],
  ["central plaza", "Central Plaza"],
  ["cave mouth", "Cave Mouth"],
  ["mossy swamp", "Mossy Swamp"],
  ["supply drop zone", "Supply Drop Zone"],
]);

function normalizeSurvivalZoneName(zone) {
  const raw = String(zone || "").trim();
  if (!raw) return null;
  const key = raw.toLowerCase();
  if (SURVIVAL_ZONE_ALIASES.has(key)) return SURVIVAL_ZONE_ALIASES.get(key);
  const direct = SURVIVAL_ZONES.find((z) => z.toLowerCase() === key);
  return direct || raw;
}

function pickSurvivalSpawnLocation(rng) {
  const fn = typeof rng === "function" ? rng : () => Math.random();
  return SURVIVAL_ZONES[Math.floor(fn() * SURVIVAL_ZONES.length)] || SURVIVAL_ZONES[0];
}

function buildSurvivalSeedPayload(seed, options) {
  return JSON.stringify({
    seed: String(seed || ""),
    options: options && typeof options === "object" ? options : {},
  });
}

function parseSurvivalSeedPayload(raw) {
  if (!raw) return { seed: "", options: {} };
  const parsed = safeJsonParse(raw, null);
  if (parsed && typeof parsed === "object" && parsed.seed) {
    return { seed: String(parsed.seed || ""), options: parsed.options || {} };
  }
  return { seed: String(raw || ""), options: {} };
}

function createSeededRng(seedInput) {
  const seed = String(seedInput || "");
  const hash = crypto.createHash("sha256").update(seed || "survival").digest("hex").slice(0, 8);
  let state = parseInt(hash, 16) || 1;
  return function rng() {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pickWeighted(items, rng) {
  const total = items.reduce((sum, item) => sum + (item.weight || 0), 0);
  if (!total) return null;
  let roll = rng() * total;
  for (const item of items) {
    roll -= item.weight || 0;
    if (roll <= 0) return item;
  }
  return items[items.length - 1] || null;
}

function pickRandom(items, rng) {
  if (!items?.length) return null;
  const idx = Math.floor(rng() * items.length);
  return items[idx];
}

const ALLIANCE_ADJECTIVES = [
  "Spark",
  "Howling",
  "Glitch",
  "Rogue",
  "Midnight",
  "Fuzzy",
  "Solar",
  "Static",
  "Storm",
  "Echo",
  "Velvet",
  "Hollow",
  "Brass",
  "Crimson",
  "Silver",
  "Wild",
  "Cosmic",
  "Neon",
];
const ALLIANCE_NOUNS = [
  "Crew",
  "Squad",
  "Circle",
  "Pack",
  "Alliance",
  "Cabin",
  "Cartel",
  "Band",
  "Collective",
  "Guild",
  "Gang",
  "Crewmates",
];

function generateAllianceName(existingNames, rng) {
  const used = new Set((existingNames || []).map((n) => String(n || "").toLowerCase()));
  for (let i = 0; i < 12; i += 1) {
    const name = `The ${pickRandom(ALLIANCE_ADJECTIVES, rng)} ${pickRandom(ALLIANCE_NOUNS, rng)}`;
    if (!used.has(name.toLowerCase())) return name;
  }
  return `The ${pickRandom(ALLIANCE_ADJECTIVES, rng)} ${pickRandom(ALLIANCE_NOUNS, rng)}`;
}

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function getSurvivalEventCount(aliveCount) {
  const count = Math.round(Number(aliveCount || 0) * 0.55);
  return clamp(count, 4, 16);
}

function normalizeSurvivalParticipantRow(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    season_id: Number(row.season_id),
    user_id: Number(row.user_id),
    display_name: row.display_name,
    avatar_url: row.avatar_url || null,
    alive: Number(row.alive || 0) === 1,
    hp: Number(row.hp || 0),
    kills: Number(row.kills || 0),
    alliance_id: row.alliance_id == null ? null : Number(row.alliance_id),
    inventory: Array.isArray(row.inventory) ? row.inventory : safeJsonParse(row.inventory_json || "[]", []),
    traits: row.traits || safeJsonParse(row.traits_json || "{}", {}),
    last_event_at: row.last_event_at ? Number(row.last_event_at) : null,
    location: normalizeSurvivalZoneName(row.location) || null,
    created_at: row.created_at ? Number(row.created_at) : null,
  };
}

function normalizeSurvivalEventRow(row) {
  if (!row) return null;
  const outcome = safeJsonParse(row.outcome_json || "{}", {});
  if (outcome && outcome.zone) {
    outcome.zone = normalizeSurvivalZoneName(outcome.zone) || outcome.zone;
  }
  return {
    id: Number(row.id),
    season_id: Number(row.season_id),
    day_index: Number(row.day_index),
    phase: row.phase,
    order_index: Number(row.order_index),
    text: row.text,
    involved_user_ids: safeJsonParse(row.involved_user_ids_json || "[]", []),
    outcome,
    created_at: row.created_at ? Number(row.created_at) : null,
  };
}

async function fetchSurvivalSeasonById(seasonId) {
  const sid = Number(seasonId);
  if (!sid) return null;
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(`SELECT * FROM survival_seasons WHERE id = $1 LIMIT 1`, [sid]);
      return rows[0] || null;
    } catch (e) {
      console.warn("[survival][pg] fetch season failed:", e?.message || e);
    }
  }
  return await dbGetAsync(`SELECT * FROM survival_seasons WHERE id = ? LIMIT 1`, [sid]).catch(() => null);
}

async function fetchSurvivalCurrentSeason() {
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT * FROM survival_seasons WHERE room_id = $1 AND status = 'running' ORDER BY id DESC LIMIT 1`,
        [SURVIVAL_ROOM_DB_ID]
      );
      if (rows[0]) return rows[0];
      const fallback = await pgPool.query(
        `SELECT * FROM survival_seasons WHERE room_id = $1 ORDER BY updated_at DESC, id DESC LIMIT 1`,
        [SURVIVAL_ROOM_DB_ID]
      );
      return fallback.rows[0] || null;
    } catch (e) {
      console.warn("[survival][pg] fetch current failed:", e?.message || e);
    }
  }

  const running = await dbGetAsync(
    `SELECT * FROM survival_seasons WHERE room_id = ? AND status = 'running' ORDER BY id DESC LIMIT 1`,
    [SURVIVAL_ROOM_DB_ID]
  ).catch(() => null);
  if (running) return running;
  return await dbGetAsync(
    `SELECT * FROM survival_seasons WHERE room_id = ? ORDER BY updated_at DESC, id DESC LIMIT 1`,
    [SURVIVAL_ROOM_DB_ID]
  ).catch(() => null);
}

async function fetchSurvivalParticipants(seasonId) {
  const sid = Number(seasonId);
  if (!sid) return [];
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT * FROM survival_participants WHERE season_id = $1 ORDER BY id ASC`,
        [sid]
      );
      return rows.map(normalizeSurvivalParticipantRow).filter(Boolean);
    } catch (e) {
      console.warn("[survival][pg] fetch participants failed:", e?.message || e);
    }
  }
  const rows = await dbAllAsync(
    `SELECT * FROM survival_participants WHERE season_id = ? ORDER BY id ASC`,
    [sid]
  );
  return rows.map(normalizeSurvivalParticipantRow).filter(Boolean);
}

async function fetchSurvivalAlliances(seasonId) {
  const sid = Number(seasonId);
  if (!sid) return [];
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT * FROM survival_alliances WHERE season_id = $1 ORDER BY id ASC`,
        [sid]
      );
      return rows || [];
    } catch (e) {
      console.warn("[survival][pg] fetch alliances failed:", e?.message || e);
    }
  }
  return await dbAllAsync(
    `SELECT * FROM survival_alliances WHERE season_id = ? ORDER BY id ASC`,
    [sid]
  );
}

async function fetchSurvivalEvents(seasonId, { limit = 200, beforeId = null } = {}) {
  const sid = Number(seasonId);
  const lim = clamp(Number(limit) || 200, 1, 500);
  const before = beforeId ? Number(beforeId) : null;
  if (!sid) return [];

  if (await pgUsersEnabled()) {
    try {
      if (before) {
        const { rows } = await pgPool.query(
          `SELECT * FROM survival_events WHERE season_id = $1 AND id < $2 ORDER BY id DESC LIMIT $3`,
          [sid, before, lim]
        );
        return rows.map(normalizeSurvivalEventRow).filter(Boolean).reverse();
      }
      const { rows } = await pgPool.query(
        `SELECT * FROM survival_events WHERE season_id = $1 ORDER BY id DESC LIMIT $2`,
        [sid, lim]
      );
      return rows.map(normalizeSurvivalEventRow).filter(Boolean).reverse();
    } catch (e) {
      console.warn("[survival][pg] fetch events failed:", e?.message || e);
    }
  }

  if (before) {
    const rows = await dbAllAsync(
      `SELECT * FROM survival_events WHERE season_id = ? AND id < ? ORDER BY id DESC LIMIT ?`,
      [sid, before, lim]
    );
    return rows.map(normalizeSurvivalEventRow).filter(Boolean).reverse();
  }
  const rows = await dbAllAsync(
    `SELECT * FROM survival_events WHERE season_id = ? ORDER BY id DESC LIMIT ?`,
    [sid, lim]
  );
  return rows.map(normalizeSurvivalEventRow).filter(Boolean).reverse();
}

async function fetchSurvivalHistory(limit = 10) {
  const lim = clamp(Number(limit) || 10, 1, 25);
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT * FROM survival_seasons WHERE room_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [SURVIVAL_ROOM_DB_ID, lim]
      );
      return rows || [];
    } catch (e) {
      console.warn("[survival][pg] fetch history failed:", e?.message || e);
    }
  }
  return await dbAllAsync(
    `SELECT * FROM survival_seasons WHERE room_id = ? ORDER BY created_at DESC LIMIT ?`,
    [SURVIVAL_ROOM_DB_ID, lim]
  );
}

async function fetchSurvivalWinner(seasonId) {
  const sid = Number(seasonId);
  if (!sid) return null;
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT display_name FROM survival_participants WHERE season_id = $1 AND alive = 1 LIMIT 1`,
        [sid]
      );
      return rows[0]?.display_name || null;
    } catch (e) {
      console.warn("[survival][pg] fetch winner failed:", e?.message || e);
    }
  }
  const row = await dbGetAsync(
    `SELECT display_name FROM survival_participants WHERE season_id = ? AND alive = 1 LIMIT 1`,
    [sid]
  ).catch(() => null);
  return row?.display_name || null;
}

function buildSurvivalTraits(rng, chaoticMode) {
  const bump = chaoticMode ? 0.15 : 0;
  return {
    aggression: clamp(rng(), 0, 1),
    loyalty: clamp(rng() - bump * 0.6, 0, 1),
    stealth: clamp(rng(), 0, 1),
    luck: clamp(rng(), 0, 1),
    chaos: clamp(rng() + bump, 0, 1),
  };
}

function hasInventoryTag(participant, tag) {
  return Array.isArray(participant.inventory) && participant.inventory.includes(tag);
}

function pickParticipantsForTemplate({
  template,
  alive,
  rng,
  appearanceCount,
  couples = [],
}) {
  const maxAppearance = 2;
  const keyOf = (p) => (p && p.user_id ? `u:${p.user_id}` : `p:${p?.id}`);
  const pickWithWeights = (candidates, count) => {
    const selected = [];
    const pool = [...candidates];
    while (selected.length < count && pool.length) {
      const weighted = pool.map((p) => ({
        participant: p,
        weight: 1 / (1 + (appearanceCount.get(keyOf(p)) || 0)),
      }));
      const pick = pickWeighted(weighted.map((w) => ({ ...w.participant, weight: w.weight })), rng);
      const chosen = pick?.id ? pool.find((p) => p.id === pick.id) : pool[0];
      if (!chosen) break;
      selected.push(chosen);
      const idx = pool.findIndex((p) => p.id === chosen.id);
      if (idx >= 0) pool.splice(idx, 1);
    }
    return selected;
  };

  if (template.requiresCouple) {
    const couplePairs = couples.filter((pair) => pair.length === 2);
    const available = couplePairs.filter(([a, b]) =>
      alive.some((p) => p.user_id === a) && alive.some((p) => p.user_id === b)
    );
    if (!available.length) return null;
    const pair = pickRandom(available, rng);
    return pair
      ? pair.map((id) => alive.find((p) => p.user_id === id)).filter(Boolean)
      : null;
  }

  if (template.requiresAlliance) {
    const byAlliance = new Map();
    for (const p of alive) {
      if (!p.alliance_id) continue;
      if (!byAlliance.has(p.alliance_id)) byAlliance.set(p.alliance_id, []);
      byAlliance.get(p.alliance_id).push(p);
    }
    const alliances = Array.from(byAlliance.values()).filter((group) => group.length >= template.participants);
    if (!alliances.length) return null;
    const group = pickRandom(alliances, rng);
    return pickWithWeights(group, template.participants);
  }

  let candidates = alive;
  if (template.requiresNoAlliance) {
    candidates = alive.filter((p) => !p.alliance_id);
  }
  if (candidates.length < template.participants) return null;
  return pickWithWeights(candidates, template.participants);
}

function renderSurvivalEventText(template, participants, rng) {
  let text = template.text || "";
  const replace = (token, idx) => {
    const p = participants[idx];
    if (!p) return token;
    const name = sanitizeDisplayName(p.display_name);
    // Prefix real site users with @ so clients can highlight mentions.
    return p.user_id ? `@${name}` : name;
  };
  text = text.replaceAll("{A}", replace("{A}", 0));
  text = text.replaceAll("{B}", replace("{B}", 1));
  text = text.replaceAll("{C}", replace("{C}", 2));
  text = text.replaceAll("{D}", replace("{D}", 3));
  if (text.includes("{ITEM}") && template.lootTag) {
    const pool = SURVIVAL_ITEM_POOL[template.lootTag] || ["mystery item"];
    const item = pickRandom(pool, rng) || "mystery item";
    text = text.replaceAll("{ITEM}", item);
  }
  return text;
}

function selectSurvivalTemplate({ aliveCount, phase, dayIndex, options }) {
  const baseDeathFactor = clamp(0.4 + dayIndex * 0.12 + (phase === "night" ? 0.1 : 0), 0.4, 2);
  const chaosBoost = options?.chaoticMode ? 1.25 : 1;
  const pool = SURVIVAL_EVENT_TEMPLATES.filter((t) => {
    if (t.participants > aliveCount) return false;
    if (t.requiresCouple && !options?.includeCouples) return false;
    if (Array.isArray(t.phases) && !t.phases.includes(phase)) return false;
    return true;
  }).map((t) => {
    let weight = t.weight || 1;
    if (t.type === "kill" || t.type === "betray") weight *= baseDeathFactor * chaosBoost;
    if (t.type === "alliance" && dayIndex < 3) weight *= 1.2;
    return { ...t, weight };
  });
  return pool;
}

function applySurvivalOutcome({
  template,
  participants,
  rng,
  pendingAlliances,
  existingAllianceNames,
}) {
  const outcome = { ...(template.outcome || {}) };
  const resolveTarget = (token) => {
    const idx = ["A", "B", "C", "D"].indexOf(token);
    return idx >= 0 ? participants[idx] : null;
  };

  if (outcome.type === "loot") {
    const target = resolveTarget(outcome.target || "A");
    if (target && template.lootTag) {
      target.inventory = target.inventory || [];
      if (!target.inventory.includes(template.lootTag)) target.inventory.push(template.lootTag);
      outcome.itemTag = template.lootTag;
    }
  }

  if (outcome.type === "heal") {
    const target = resolveTarget(outcome.target || "A");
    const [min, max] = outcome.amount || [10, 25];
    if (target) {
      const delta = Math.round(min + rng() * (max - min));
      target.hp = clamp(target.hp + delta, 1, 100);
      outcome.deltaHp = delta;
    }
  }

  if (outcome.type === "injure") {
    const target = resolveTarget(outcome.target || "A");
    const [min, max] = outcome.amount || [10, 25];
    if (target) {
      const delta = Math.round(min + rng() * (max - min));
      target.hp = clamp(target.hp - delta, 1, 100);
      outcome.deltaHp = -delta;
    }
    if (outcome.splashTarget) {
      const splash = resolveTarget(outcome.splashTarget);
      const [smin, smax] = outcome.splashAmount || [6, 18];
      if (splash) {
        const delta = Math.round(smin + rng() * (smax - smin));
        splash.hp = clamp(splash.hp - delta, 1, 100);
      }
    }
  }

  if (outcome.type === "protect") {
    const protectedTarget = resolveTarget(outcome.protected || "B");
    if (protectedTarget) {
      protectedTarget.hp = clamp(protectedTarget.hp + 8, 1, 100);
    }
  }

  if (outcome.type === "steal") {
    const thief = resolveTarget(outcome.thief || "A");
    const victim = resolveTarget(outcome.victim || "B");
    if (thief && victim && Array.isArray(victim.inventory) && victim.inventory.length) {
      const stolenTag = pickRandom(victim.inventory, rng);
      victim.inventory = victim.inventory.filter((tag) => tag !== stolenTag);
      thief.inventory = thief.inventory || [];
      thief.inventory.push(stolenTag);
      outcome.itemTag = stolenTag;
    } else {
      outcome.type = "nothing";
    }
  }

  if (outcome.type === "kill" || outcome.type === "betray") {
    const killer = resolveTarget(outcome.killer || "A");
    const victim = resolveTarget(outcome.victim || "B");
    if (victim) {
      victim.alive = false;
      victim.hp = 0;
      victim.alliance_id = null;
    }
    if (killer) {
      killer.kills = (killer.kills || 0) + 1;
      if (outcome.type === "betray") killer.alliance_id = null;
    }
  }

  if (outcome.type === "alliance") {
    const members = (outcome.members || []).map(resolveTarget).filter(Boolean);
    if (members.length >= 2) {
      const tempId = -1 * (pendingAlliances.length + 1);
      const name = generateAllianceName(existingAllianceNames, rng);
      existingAllianceNames.push(name);
      pendingAlliances.push({ tempId, name, members });
      for (const member of members) {
        member.alliance_id = tempId;
      }
      outcome.alliance = { id: tempId, name };
    } else {
      outcome.type = "nothing";
    }
  }

  return outcome;
}


function survivalNameTag(p){
  if(!p) return "Someone";
  const name = sanitizeDisplayName(p.display_name);
  return p.user_id ? `@${name}` : name;
}

function pickZoneFromAlive(alive, rng){
  if(!alive.length) return pickRandom(SURVIVAL_ZONES, rng) || SURVIVAL_ZONES[0];
  // Prefer zones that currently have people (so the map feels alive).
  const counts = new Map();
  for(const p of alive){
    const z = normalizeSurvivalZoneName(p.location) || SURVIVAL_ZONES[0];
    counts.set(z, (counts.get(z) || 0) + 1);
  }
  const weighted = Array.from(counts.entries()).map(([zone, c]) => ({ zone, weight: Math.max(1, c) }));
  const pick = pickWeighted(weighted.map((w)=>({ ...w, user_id: w.zone })), rng); // hack: reuse pickWeighted shape
  const zone = pick?.user_id || pickRandom(Array.from(counts.keys()), rng);
  return zone || SURVIVAL_ZONES[0];
}

function maybeGenerateArenaEvent({ season, participants, rng, now }) {
  const alive = (participants || []).filter((p) => p.alive);
  if (alive.length < 3) return null;

  const dayIndex = Number(season?.day_index || 1);
  const baseChance = clamp(0.16 + dayIndex * 0.03 + (alive.length >= 12 ? 0.06 : 0), 0.14, 0.36);
  if (rng() > baseChance) return null;

  const scope = rng() < 0.62 ? "zone" : "global";
  const zone = scope === "zone" ? pickZoneFromAlive(alive, rng) : null;

  const population = scope === "zone"
    ? alive.filter((p) => normalizeSurvivalZoneName(p.location) === normalizeSurvivalZoneName(zone))
    : alive;

  if (!population.length) return null;

  const kindRoll = rng();
  const kind =
    kindRoll < 0.34 ? "storm" :
    kindRoll < 0.64 ? "wildfire" :
    kindRoll < 0.82 ? "supply_drop" :
    "fog";

  // Determine victims (for supply drops we may still injure a couple via scramble).
  const maxVictims = scope === "global"
    ? clamp(Math.round(population.length * 0.12), 1, 4)
    : clamp(Math.round(population.length * 0.22), 1, 6);

  const victims = [];
  const pool = [...population];
  while (victims.length < maxVictims && pool.length) {
    const v = pickRandom(pool, rng);
    if (!v) break;
    victims.push(v);
    pool.splice(pool.findIndex((p) => p.id === v.id), 1);
  }

  const outcome = { type: "arena", scope, zone: zone || null, kind, affected_user_ids: victims.map((v) => v.user_id) };

  // Apply effects
  if (kind === "supply_drop") {
    // Small heal/loot vibe.
    for (const v of victims) {
      v.hp = clamp(v.hp + Math.round(6 + rng() * 10), 1, 100);
      v.last_event_at = now;
      v.inventory = v.inventory || [];
      if (!v.inventory.includes("food")) v.inventory.push("food");
      if (rng() < 0.35 && !v.inventory.includes("weapon")) v.inventory.push("weapon");
    }
  } else {
    const minD = kind === "storm" ? 10 : kind === "fog" ? 8 : 16;
    const maxD = kind === "storm" ? 28 : kind === "fog" ? 20 : 38;
    for (const v of victims) {
      const delta = Math.round(minD + rng() * (maxD - minD));
      v.hp = clamp(v.hp - delta, 0, 100);
      v.last_event_at = now;
      if (v.hp <= 0) {
        // Don't over-kill early days.
        if (dayIndex <= 1 && rng() < 0.7) v.hp = 1;
        else {
          v.alive = false;
          v.alliance_id = null;
          v.kills = v.kills || 0;
        }
      }
      // Forced movement makes the map feel dynamic.
      if (v.alive && rng() < 0.55) {
        v.location = pickRandom(SURVIVAL_ZONES, rng) || v.location || SURVIVAL_ZONES[0];
      }
    }
  }

  const victimTags = victims.map(survivalNameTag);
  let text = "";
  if (kind === "storm") {
    text = scope === "global"
      ? `⚡ A brutal storm sweeps the arena — ${victimTags.join(", ")} struggle to stay on their feet.`
      : `⚡ A sudden storm hits ${zone} — ${victimTags.join(", ")} take the worst of it.`;
  } else if (kind === "wildfire") {
    text = scope === "global"
      ? `🔥 Wildfires spread across the arena — ${victimTags.join(", ")} get caught in the chaos.`
      : `🔥 A wildfire erupts in ${zone} — ${victimTags.join(", ")} scramble for safety.`;
  } else if (kind === "fog") {
    text = scope === "global"
      ? `🌫️ A thick fog blankets the arena — ${victimTags.join(", ")} stumble into danger.`
      : `🌫️ A choking fog rolls into ${zone} — ${victimTags.join(", ")} lose their bearings.`;
  } else {
    text = scope === "global"
      ? `🎁 Supply pods crash down all over — ${victimTags.join(", ")} snatch up provisions.`
      : `🎁 A supply pod lands in ${zone} — ${victimTags.join(", ")} race for it.`;
  }

  return {
    text,
    outcome,
  };
}

const DEFAULT_ROOM_MASTERS = ["Site Rooms", "User Rooms"];
const DEFAULT_ROOM_CATEGORY = "Uncategorized";

function sanitizeRoomGroupName(name) {
  const clean = String(name || "").trim().replace(/\s+/g, " ");
  return clean.slice(0, 40);
}

function normalizeRoomGroupName(name) {
  return String(name || "").trim().toLowerCase();
}

async function getUserRoomCollapseState(userId) {
  const fallback = { master: {}, category: {} };
  if (!userId) return fallback;
  let row = null;
  try {
    const { rows } = await pgPool.query(
      `SELECT room_master_collapsed, room_category_collapsed FROM users WHERE id = $1 LIMIT 1`,
      [userId]
    );
    row = rows[0] || null;
  } catch {}

  if (!row) {
    try {
      row = await dbGetAsync(
        "SELECT room_master_collapsed, room_category_collapsed FROM users WHERE id = ?",
        [userId]
      );
    } catch {}
  }

  const master = safeJsonParse(row?.room_master_collapsed || "{}", {});
  const category = safeJsonParse(row?.room_category_collapsed || "{}", {});
  return {
    master: master && typeof master === "object" ? master : {},
    category: category && typeof category === "object" ? category : {},
  };
}

async function buildRoomStructure() {
  // Discovery: room structure is sourced from room_master_categories/room_categories/rooms tables.
  if (await pgUsersEnabled()) {
    const mastersRes = await pgPool.query(
      `SELECT id, name, sort_order FROM room_master_categories ORDER BY sort_order ASC, id ASC`
    );
    const categoriesRes = await pgPool.query(
      `SELECT id, master_id, name, sort_order FROM room_categories ORDER BY sort_order ASC, id ASC`
    );
    const roomsRes = await pgPool.query(
      `SELECT name, category_id, room_sort_order, slowmode_seconds, is_locked, maintenance_mode, vip_only, staff_only, min_level, events_enabled, archived,
              created_by, created_by_user_id, is_user_room, is_system
         FROM rooms
        ORDER BY room_sort_order ASC, name ASC`
    );
    const rooms = roomsRes.rows || [];
    return {
      masters: mastersRes.rows || [],
      categories: categoriesRes.rows || [],
      rooms: (rooms || []).map((r) => ({
        id: r.name,
        name: r.name,
        category_id: r.category_id,
        room_sort_order: Number(r.room_sort_order || 0),
        slowmode_seconds: Number(r.slowmode_seconds || 0),
        is_locked: Number(r.is_locked || 0),
        maintenance_mode: Number(r.maintenance_mode || 0),
        vip_only: Number(r.vip_only || 0),
        staff_only: Number(r.staff_only || 0),
        min_level: Number(r.min_level || 0),
        events_enabled: Number(r.events_enabled ?? 1),
        archived: Number(r.archived || 0),
        created_by: r.created_by ?? null,
        created_by_user_id: r.created_by_user_id ?? null,
        is_user_room: Number(r.is_user_room || 0),
        is_system: Number(r.is_system || 0),
      })),
    };
  }

  const masters = await dbAllAsync(
    `SELECT id, name, sort_order FROM room_master_categories ORDER BY sort_order ASC, id ASC`
  );
  const categories = await dbAllAsync(
    `SELECT id, master_id, name, sort_order FROM room_categories ORDER BY sort_order ASC, id ASC`
  );
  const rooms = await dbAllAsync(
    `SELECT name, category_id, room_sort_order, slowmode_seconds, is_locked, maintenance_mode, vip_only, staff_only, min_level, events_enabled, archived,
            created_by, created_by_user_id, is_user_room, is_system
       FROM rooms
      ORDER BY room_sort_order ASC, name ASC`
  );
  return {
    masters,
    categories,
    rooms: (rooms || []).map((r) => ({
      id: r.name,
      name: r.name,
      category_id: r.category_id,
      room_sort_order: Number(r.room_sort_order || 0),
      slowmode_seconds: Number(r.slowmode_seconds || 0),
      is_locked: Number(r.is_locked || 0),
      maintenance_mode: Number(r.maintenance_mode || 0),
      vip_only: Number(r.vip_only || 0),
      staff_only: Number(r.staff_only || 0),
      min_level: Number(r.min_level || 0),
      events_enabled: Number(r.events_enabled ?? 1),
      archived: Number(r.archived || 0),
      created_by: r.created_by ?? null,
      created_by_user_id: r.created_by_user_id ?? null,
      is_user_room: Number(r.is_user_room || 0),
      is_system: Number(r.is_system || 0),
    })),
  };
}

async function buildRoomStructurePayload(userId) {
  const base = await buildRoomStructure();
  const version = await getRoomStructureVersion();
  let user = null;
  try {
    if (userId) user = await dbGetAsync(`SELECT id, role, level FROM users WHERE id = ?`, [userId]);
  } catch (_) {}
  const isAdmin = user && roleRankServer(user.role) >= roleRankServer("Admin");
  const filteredRooms = (base.rooms || []).filter((room) => {
    if (!room) return false;
    if (Number(room.archived || 0) === 1 && !isAdmin) return false;
    // Legacy VIP prefix gate remains, but new settings gate applies too.
    const isVipPrefix = /^vip[_-]/i.test(room.name || "");
    if (isVipPrefix) {
      if (!user) return false;
      if (!isVipPlus(user.role)) return false;
      if (Number(user.level || 0) < 25) return false;
    }
    return canAccessRoomBySettings(user, room);
  });
  const userCollapse = await getUserRoomCollapseState(userId);
  return { ...base, rooms: filteredRooms, userCollapse, version };
}

async function logRoomStructureAudit({ action, actorUserId, payload }) {
  const now = Date.now();
  const serialized = payload ? JSON.stringify(payload) : null;
  if (await pgUsersEnabled()) {
    try {
      await pgPool.query(
        `INSERT INTO room_structure_audit (action, actor_user_id, payload, created_at)
         VALUES ($1, $2, $3, $4)`,
        [action, actorUserId || null, serialized ? JSON.parse(serialized) : null, now]
      );
      return;
    } catch (e) {
      console.warn("[room-audit][pg] failed:", e?.message || e);
    }
  }
  try {
    await dbRunAsync(
      `INSERT INTO room_structure_audit (action, actor_user_id, payload, created_at)
       VALUES (?, ?, ?, ?)`,
      [action, actorUserId || null, serialized, now]
    );
  } catch (e) {
    console.warn("[room-audit][sqlite] failed:", e?.message || e);
  }
}

async function emitRoomStructureUpdate({ bumpVersion = false } = {}) {
  const version = bumpVersion ? await bumpRoomStructureVersion() : await getRoomStructureVersion();
  const payload = await buildRoomStructure();
  io.emit("roomStructure:update", { ...payload, version });
  io.emit("rooms:structure_updated", { version });
  io.emit("rooms update", (payload.rooms || []).map((r) => r.name));
}

async function ensureRoomStructureVersionMatch(expectedVersion) {
  if (!Number.isFinite(expectedVersion)) return { ok: true };
  const current = await getRoomStructureVersion();
  if (Number(expectedVersion) !== Number(current)) {
    return { ok: false, version: current };
  }
  return { ok: true, version: current };
}

async function applyRoomStructureChange({ action, actorUserId, auditPayload }) {
  await logRoomStructureAudit({ action, actorUserId, payload: auditPayload });
  await emitRoomStructureUpdate({ bumpVersion: true });
}

function extractExpectedRoomVersion(req) {
  const raw = req?.body?.expectedVersion ?? req?.query?.expectedVersion;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

async function getDefaultMasterIds() {
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT id, name FROM room_master_categories WHERE name = ANY($1::text[])`,
      [DEFAULT_ROOM_MASTERS]
    );
    const map = new Map((rows || []).map((row) => [row.name, row.id]));
    return {
      site: map.get("Site Rooms") || null,
      user: map.get("User Rooms") || null,
    };
  }
  const rows = await dbAllAsync(
    `SELECT id, name FROM room_master_categories WHERE name IN (?, ?)`,
    DEFAULT_ROOM_MASTERS
  );
  const map = new Map(rows.map((row) => [row.name, row.id]));
  return {
    site: map.get("Site Rooms") || null,
    user: map.get("User Rooms") || null,
  };
}

async function resolveSiteUncategorizedCategoryId() {
  try {
    const ids = await getDefaultMasterIds();
    if (!ids.site) return null;
    if (await pgUsersEnabled()) {
      const { rows } = await pgPool.query(
        `SELECT id FROM room_categories WHERE master_id = $1 AND lower(name) = lower('Uncategorized') LIMIT 1`,
        [ids.site]
      );
      return rows?.[0]?.id ?? null;
    }
    const row = await dbGetAsync(
      `SELECT id FROM room_categories WHERE master_id = ? AND lower(name) = lower('Uncategorized') LIMIT 1`,
      [ids.site]
    );
    return row?.id ?? null;
  } catch {
    return null;
  }
}

async function ensureCoreRoomsExist() {
  const now = Date.now();
  const categoryId = await resolveSiteUncategorizedCategoryId();
  for (const room of CORE_ROOMS) {
    const existing = await dbGetAsync(`SELECT name, category_id FROM rooms WHERE name = ?`, [room.name]).catch(() => null);
    if (!existing) {
      await dbRunAsync(
        `INSERT OR IGNORE INTO rooms
          (name, created_by, created_at, category_id, room_sort_order, is_user_room, vip_only, staff_only, min_level, is_locked, maintenance_mode, events_enabled, slowmode_seconds, archived, is_system)
         VALUES (?, NULL, ?, ?, ?, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1)`,
        [room.name, now, categoryId, room.sortOrder ?? 0]
      );
    } else {
      await dbRunAsync(
        `UPDATE rooms
            SET category_id = COALESCE(category_id, ?),
                room_sort_order = COALESCE(room_sort_order, ?),
                archived = 0,
                is_system = 1
          WHERE name = ?`,
        [categoryId, room.sortOrder ?? 0, room.name]
      ).catch(() => {});
    }
  }

  if (!PG_READY) return;
  const pgCategoryId = await (async () => {
    try {
      const { rows } = await pgPool.query(
        `SELECT c.id
           FROM room_categories c
           JOIN room_master_categories m ON m.id = c.master_id
          WHERE m.name = 'Site Rooms' AND lower(c.name) = lower('Uncategorized')
          LIMIT 1`
      );
      return rows?.[0]?.id ?? null;
    } catch {
      return null;
    }
  })();
  for (const room of CORE_ROOMS) {
    try {
      const { rows } = await pgPool.query(`SELECT name, category_id FROM rooms WHERE name = $1 LIMIT 1`, [room.name]);
      const existing = rows?.[0] || null;
      if (!existing) {
        await pgPool.query(
          `INSERT INTO rooms
            (name, created_by, created_at, category_id, room_sort_order, is_user_room, vip_only, staff_only, min_level, is_locked, maintenance_mode, events_enabled, slowmode_seconds, archived, is_system)
           VALUES ($1, NULL, $2, $3, $4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1)
           ON CONFLICT (name) DO NOTHING`,
          [room.name, now, pgCategoryId, room.sortOrder ?? 0]
        );
      } else {
        await pgPool.query(
          `UPDATE rooms
              SET category_id = COALESCE(category_id, $1),
                  room_sort_order = COALESCE(room_sort_order, $2),
                  archived = 0,
                  is_system = 1
            WHERE name = $3`,
          [pgCategoryId, room.sortOrder ?? 0, room.name]
        );
      }
    } catch (e) {
      console.warn("[rooms] core room seed failed:", e?.message || e);
    }
  }
}

async function getUncategorizedCategoryId(masterId) {
  if (!masterId) return null;
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT id FROM room_categories WHERE master_id = $1 AND lower(name) = lower($2) LIMIT 1`,
      [masterId, DEFAULT_ROOM_CATEGORY]
    );
    return rows?.[0]?.id ?? null;
  }
  const row = await dbGetAsync(
    `SELECT id FROM room_categories WHERE master_id = ? AND lower(name) = lower(?) LIMIT 1`,
    [masterId, DEFAULT_ROOM_CATEGORY]
  );
  return row?.id ?? null;
}

async function resolveRoomCategoryId({ categoryId, masterId, isUserRoom }) {
  let categoryRow = null;
  if (categoryId) {
    if (await pgUsersEnabled()) {
      const { rows } = await pgPool.query(
        `SELECT id, master_id FROM room_categories WHERE id = $1 LIMIT 1`,
        [categoryId]
      );
      categoryRow = rows?.[0] || null;
    } else {
      categoryRow = await dbGetAsync(
        `SELECT id, master_id FROM room_categories WHERE id = ? LIMIT 1`,
        [categoryId]
      );
    }
  }
  if (!categoryRow && masterId) {
    const fallbackId = await getUncategorizedCategoryId(masterId);
    if (fallbackId) return { categoryId: fallbackId, masterId };
  }
  if (categoryRow) return { categoryId: categoryRow.id, masterId: categoryRow.master_id };

  const defaults = await getDefaultMasterIds();
  const fallbackMasterId = isUserRoom ? defaults.user : defaults.site;
  const fallbackCategoryId = await getUncategorizedCategoryId(fallbackMasterId);
  return { categoryId: fallbackCategoryId, masterId: fallbackMasterId };
}
function normalizeDmPair(a, b) {
  const aId = Number(a);
  const bId = Number(b);
  if (!Number.isInteger(aId) || !Number.isInteger(bId) || aId <= 0 || bId <= 0 || aId === bId) {
    return null;
  }
  return { low: Math.min(aId, bId), high: Math.max(aId, bId) };
}

function normalizeDmParticipants(ids = []) {
  return Array.from(
    new Set(
      (ids || [])
        .map((v) => Number(v))
        .filter((n) => Number.isInteger(n) && n > 0)
    )
  ).sort((a, b) => a - b);
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

function resolveOrCreateThread({ participantIds, isGroup, title, createdBy }, cb) {
  const ids = normalizeDmParticipants(participantIds);
  const now = Date.now();

  if (!isGroup) {
    if (ids.length !== 2) return cb(new Error("invalid participants"));
    const pair = normalizeDmPair(ids[0], ids[1]);
    if (!pair) return cb(new Error("invalid participants"));

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

    return lookup();
  }

  if (ids.length < 2) return cb(new Error("invalid participants"));
  const participantsKey = ids.join(",");
  const participantsJson = JSON.stringify(ids);

  const finish = (row, created) => {
    ensureDmParticipants(row.id, ids, createdBy, now, () => {
      cb(null, { id: row.id, created: !!created, participants_key: participantsKey });
    });
  };

  const lookup = () => {
    db.get(
      `SELECT id FROM dm_threads WHERE is_group=1 AND participants_key=?`,
      [participantsKey],
      (err, row) => {
        if (row && row.id) return finish(row, false);
        if (err) return cb(err);

        const placeholders = ids.map(() => "?").join(",");
        if (!placeholders) return insert();
        db.get(
          `SELECT t.id FROM dm_threads t
             JOIN dm_participants dp ON dp.thread_id=t.id
            WHERE t.is_group=1 AND dp.user_id IN (${placeholders})
            GROUP BY t.id
            HAVING COUNT(DISTINCT dp.user_id)=? AND (SELECT COUNT(*) FROM dm_participants WHERE thread_id=t.id)=?
            ORDER BY t.id DESC LIMIT 1`,
          [...ids, ids.length, ids.length],
          (legacyErr, legacyRow) => {
            if (legacyErr) return cb(legacyErr);
            if (legacyRow && legacyRow.id) {
              db.run(
                `UPDATE dm_threads SET participants_key=?, participants_json=? WHERE id=?`,
                [participantsKey, participantsJson, legacyRow.id],
                () => finish({ id: legacyRow.id }, false)
              );
              return;
            }
            return insert();
          }
        );
      }
    );
  };

  const insert = () => {
    db.run(
      `INSERT INTO dm_threads (title, is_group, created_by, created_at, participants_key, participants_json)
       VALUES (?, 1, ?, ?, ?, ?)`,
      [title || null, createdBy, now, participantsKey, participantsJson],
      function (insertErr) {
        if (insertErr) {
          if (String(insertErr.message || "").toLowerCase().includes("unique")) return lookup();
          return cb(insertErr);
        }
        finish({ id: this.lastID }, true);
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
  logSecurityEvent("moderation_action", {
    actor: actor?.username || null,
    actorId: actor?.id || null,
    action,
    targetUsername: targetUsername || null,
    targetUserId: targetUserId || null,
    room: room || null,
  });
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

// Discovery: moderation actions are stored in mod_logs; cases unify flags/appeals/referrals.
function isStaffRole(role) {
  return requireMinRole(role, "Moderator");
}

function canViewAllCases(role) {
  return requireMinRole(role, "Admin") || requireMinRole(role, "Co-owner") || requireMinRole(role, "Owner");
}

function emitToStaff(event, payload) {
  try {
    for (const sock of io.sockets.sockets.values()) {
      const role = sock?.user?.role || sock?.request?.session?.user?.role;
      if (!role || !isStaffRole(role)) continue;
      sock.emit(event, payload);
    }
  } catch (e) {
    console.warn("[staff-emit] failed:", e?.message || e);
  }
}

async function findUserIdByUsername(username) {
  const clean = String(username || "").trim();
  if (!clean) return null;
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT id FROM users WHERE lower(username) = lower($1) LIMIT 1`,
        [clean]
      );
      return rows?.[0]?.id ?? null;
    } catch {
      return null;
    }
  }
  const row = await dbGetAsync(`SELECT id FROM users WHERE lower(username) = lower(?) LIMIT 1`, [clean]).catch(() => null);
  return row?.id ?? null;
}

async function createModCase({
  type,
  status = "open",
  priority = "normal",
  subjectUserId = null,
  createdByUserId = null,
  assignedToUserId = null,
  roomId = null,
  title = null,
  summary = null,
}) {
  const now = Date.now();
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(
      `INSERT INTO mod_cases
        (type, status, priority, subject_user_id, created_by_user_id, assigned_to_user_id, room_id, title, summary, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [type, status, priority, subjectUserId, createdByUserId, assignedToUserId, roomId, title, summary, now, now]
    );
    return rows?.[0] || null;
  }
  const result = await dbRunAsync(
    `INSERT INTO mod_cases
      (type, status, priority, subject_user_id, created_by_user_id, assigned_to_user_id, room_id, title, summary, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [type, status, priority, subjectUserId, createdByUserId, assignedToUserId, roomId, title, summary, now, now]
  );
  return dbGetAsync(`SELECT * FROM mod_cases WHERE id = ?`, [result.lastID]);
}

async function addModCaseEvent(caseId, { actorUserId = null, eventType, payload = null }) {
  const now = Date.now();
  if (await pgUsersEnabled()) {
    await pgPool.query(
      `INSERT INTO mod_case_events (case_id, actor_user_id, event_type, event_payload, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [caseId, actorUserId, eventType, payload ?? null, now]
    );
    await pgPool.query(`UPDATE mod_cases SET updated_at = $1 WHERE id = $2`, [now, caseId]).catch(() => {});
    return;
  }
  await dbRunAsync(
    `INSERT INTO mod_case_events (case_id, actor_user_id, event_type, event_payload, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [caseId, actorUserId, eventType, payload ? JSON.stringify(payload) : null, now]
  );
  await dbRunAsync(`UPDATE mod_cases SET updated_at = ? WHERE id = ?`, [now, caseId]).catch(() => {});
}

async function addModCaseNote(caseId, { authorUserId = null, body }) {
  const now = Date.now();
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(
      `INSERT INTO mod_case_notes (case_id, author_user_id, body, created_at)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [caseId, authorUserId, body, now]
    );
    await pgPool.query(`UPDATE mod_cases SET updated_at = $1 WHERE id = $2`, [now, caseId]).catch(() => {});
    return rows?.[0] || null;
  }
  const result = await dbRunAsync(
    `INSERT INTO mod_case_notes (case_id, author_user_id, body, created_at)
     VALUES (?, ?, ?, ?)`,
    [caseId, authorUserId, body, now]
  );
  await dbRunAsync(`UPDATE mod_cases SET updated_at = ? WHERE id = ?`, [now, caseId]).catch(() => {});
  return dbGetAsync(`SELECT * FROM mod_case_notes WHERE id = ?`, [result.lastID]);
}

async function addModCaseEvidence(caseId, { createdByUserId = null, evidenceType, roomId = null, messageId = null, messageExcerpt = null, url = null, text = null }) {
  const now = Date.now();
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(
      `INSERT INTO mod_case_evidence
        (case_id, evidence_type, room_id, message_id, message_excerpt, url, text, created_by_user_id, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [caseId, evidenceType, roomId, messageId, messageExcerpt, url, text, createdByUserId, now]
    );
    await pgPool.query(`UPDATE mod_cases SET updated_at = $1 WHERE id = $2`, [now, caseId]).catch(() => {});
    return rows?.[0] || null;
  }
  const result = await dbRunAsync(
    `INSERT INTO mod_case_evidence
      (case_id, evidence_type, room_id, message_id, message_excerpt, url, text, created_by_user_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [caseId, evidenceType, roomId, messageId, messageExcerpt, url, text, createdByUserId, now]
  );
  await dbRunAsync(`UPDATE mod_cases SET updated_at = ? WHERE id = ?`, [now, caseId]).catch(() => {});
  return dbGetAsync(`SELECT * FROM mod_case_evidence WHERE id = ?`, [result.lastID]);
}

async function fetchModCaseById(caseId) {
  if (await pgUsersEnabled()) {
    const { rows } = await pgPool.query(`SELECT * FROM mod_cases WHERE id = $1`, [caseId]);
    return rows?.[0] || null;
  }
  return dbGetAsync(`SELECT * FROM mod_cases WHERE id = ?`, [caseId]);
}

function shouldLogSecurityEvent(key, limit = 5, windowMs = 60_000) {
  const now = Date.now();
  const state = securityAuditLimiter.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + windowMs;
  }
  state.count += 1;
  securityAuditLimiter.set(key, state);
  return state.count <= limit;
}

function logSecurityEvent(type, meta = {}) {
  try {
    const safeMeta = {
      ...meta,
      type,
      ts: new Date().toISOString(),
    };
    const key = `${type}:${meta.ip || "unknown"}`;
    if (!shouldLogSecurityEvent(key)) return;
    fs.appendFile(
      path.join(__dirname, "security-audit.log"),
      `${JSON.stringify(safeMeta)}\n`,
      () => {}
    );
  } catch {}
}

function checkLoginBackoff(key) {
  const now = Date.now();
  const state = loginFailureTracker.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000, blockedUntil: 0 };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + 15 * 60 * 1000;
    state.blockedUntil = 0;
  }
  if (state.blockedUntil && now < state.blockedUntil) {
    return { blocked: true, retryAfterMs: state.blockedUntil - now };
  }
  return { blocked: false };
}

function recordLoginFailure(key) {
  const now = Date.now();
  const state = loginFailureTracker.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000, blockedUntil: 0 };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + 15 * 60 * 1000;
    state.blockedUntil = 0;
  }
  state.count += 1;
  if (state.count >= 5) {
    const exponent = Math.min(5, state.count - 4);
    const delay = Math.min(30 * 60 * 1000, 30_000 * (2 ** exponent));
    state.blockedUntil = now + delay;
  }
  loginFailureTracker.set(key, state);
}

function clearLoginFailures(key) {
  loginFailureTracker.delete(key);
}

function getPasswordUpgradeAttemptState(req) {
  const now = Date.now();
  const state = req.session?.passwordUpgradeAttempts || { count: 0, resetAt: now + 15 * 60 * 1000, lockedUntil: 0 };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + 15 * 60 * 1000;
    state.lockedUntil = 0;
  }
  if (state.lockedUntil && now < state.lockedUntil) {
    return { blocked: true, retryAfterMs: state.lockedUntil - now, state };
  }
  return { blocked: false, state };
}

function recordPasswordUpgradeFailure(req) {
  const now = Date.now();
  const state = getPasswordUpgradeAttemptState(req).state || { count: 0, resetAt: now + 15 * 60 * 1000, lockedUntil: 0 };
  state.count += 1;
  if (state.count >= 5) {
    state.lockedUntil = now + 15 * 60 * 1000;
  }
  req.session.passwordUpgradeAttempts = state;
}

function clearPasswordUpgradeFailures(req) {
  if (req.session?.passwordUpgradeAttempts) delete req.session.passwordUpgradeAttempts;
}

async function invalidateSessionsForUserId(userId) {
  if (!userId || !PG_READY) return;
  try {
    await pgPool.query(
      `DELETE FROM session WHERE (sess->'user'->>'id')::int = $1`,
      [Number(userId)]
    );
  } catch (e) {
    console.warn("[session] failed to invalidate sessions:", e?.message || e);
  }
}

function requireLogin(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  next();
}

const CHANGELOG_TITLE_MAX = 120;
const CHANGELOG_BODY_MAX = 8000;
const CHANGELOG_REACTIONS = ["heart", "clap", "down", "eyes"];
const FAQ_TITLE_MAX = 140;
// FAQ questions are title-only; answer_body is staff-editable.
// Keep question_details column for backwards compatibility but do not accept user input.
const FAQ_DETAILS_MAX = 0;
const FAQ_REACTIONS = ["helpful", "love", "funny", "confusing"];
const FAQ_RATE_LIMIT_MS = 30000;
const faqAskCooldown = new Map();

function emptyFaqReactions(){
  return { helpful:0, love:0, funny:0, confusing:0 };
}

function emptyMyFaqReactions(){
  return { helpful:false, love:false, funny:false, confusing:false };
}

function normalizeFaqReactionKey(reaction){
  const key = String(reaction || "").toLowerCase();
  return FAQ_REACTIONS.includes(key) ? key : null;
}

function emptyChangelogReactions(){
  return { heart:0, clap:0, down:0, eyes:0 };
}

function emptyMyChangelogReactions(){
  return { heart:false, clap:false, down:false, eyes:false };
}

function normalizeReactionKey(reaction){
  const key = String(reaction || "").toLowerCase();
  return CHANGELOG_REACTIONS.includes(key) ? key : null;
}

function requireOwner(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  if (!requireMinRole(req.session.user.role, "Owner")) return res.status(403).send("Forbidden");
  next();
}

function requireCoOwner(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  if (!requireMinRole(req.session.user.role, "Co-owner")) return res.status(403).send("Forbidden");
  next();
}



function requireAdminPlus(req, res, next) {
  if (!req.session?.user?.id) return res.status(401).send("Not logged in");
  if (!requireMinRole(req.session.user.role, "Admin")) return res.status(403).send("Forbidden");
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
    reactions: row.reactions || emptyChangelogReactions(),
    myReactions: row.myReactions || emptyMyChangelogReactions(),
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

function toFaqPayload(row){
  if(!row || row.is_deleted) return null;
  const normalizeEpoch = (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  return {
    id: row.id,
    question_title: row.question_title,
    question_details: row.question_details || "",
    answer_body: row.answer_body || "",
    created_at: normalizeEpoch(row.created_at),
    answered_at: normalizeEpoch(row.answered_at),
    reactions: row.reactions || emptyFaqReactions(),
    myReactions: row.myReactions || emptyMyFaqReactions(),
  };
}

function cleanFaqInput(title, details){
  const cleanTitle = String(title || "").trim();
  // Ignore user-provided details: questions are title-only.
  const cleanDetails = "";
  if(!cleanTitle) return { error: "Question title is required" };
  if(cleanTitle.length > FAQ_TITLE_MAX) return { error: `Title must be at most ${FAQ_TITLE_MAX} characters` };
  if(cleanDetails.length > FAQ_DETAILS_MAX) return { error: `Details must be at most ${FAQ_DETAILS_MAX} characters` };
  return { title: cleanTitle, details: cleanDetails };
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

async function pgChangelogByIds(ids = []){
  await pgInitPromise;
  if(!ids?.length) return [];
  const { rows } = await pgPool.query(
    "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries WHERE id = ANY($1) ORDER BY seq DESC",
    [ids]
  );
  return rows;
}

async function pgFetchChangelogReactionCounts(entryIds = []){
  if(!entryIds.length) return {};
  const map = {};
  const { rows } = await pgPool.query(
    "SELECT entry_id, reaction, COUNT(*) as count FROM changelog_reactions WHERE entry_id = ANY($1) GROUP BY entry_id, reaction",
    [entryIds]
  );
  for(const row of rows || []){
    const id = Number(row.entry_id);
    const key = normalizeReactionKey(row.reaction);
    if(!id || !key) continue;
    if(!map[id]) map[id] = emptyChangelogReactions();
    map[id][key] = Number(row.count) || 0;
  }
  return map;
}

async function pgFetchFaqReactionCounts(questionIds = []){
  if(!questionIds.length) return {};
  const map = {};
  const { rows } = await pgPool.query(
    "SELECT question_id, reaction_key, COUNT(*) as count FROM faq_reactions WHERE question_id = ANY($1) GROUP BY question_id, reaction_key",
    [questionIds]
  );
  for(const row of rows || []){
    const id = Number(row.question_id);
    const key = normalizeFaqReactionKey(row.reaction_key);
    if(!id || !key) continue;
    if(!map[id]) map[id] = emptyFaqReactions();
    map[id][key] = Number(row.count) || 0;
  }
  return map;
}

async function pgFaqMyReactions(questionIds = [], username){
  if(!questionIds.length || !username) return {};
  const map = {};
  const { rows } = await pgPool.query(
    "SELECT question_id, reaction_key FROM faq_reactions WHERE question_id = ANY($1) AND username=$2",
    [questionIds, username]
  );
  for(const row of rows || []){
    const id = Number(row.question_id);
    const key = normalizeFaqReactionKey(row.reaction_key);
    if(!id || !key) continue;
    if(!map[id]) map[id] = emptyMyFaqReactions();
    map[id][key] = true;
  }
  return map;
}

async function pgFetchChangelogUserReactions(entryIds = [], userId){
  if(!entryIds.length || !userId) return {};
  const mine = {};
  const { rows } = await pgPool.query(
    "SELECT entry_id, reaction FROM changelog_reactions WHERE entry_id = ANY($1) AND user_id=$2",
    [entryIds, userId]
  );
  for(const row of rows || []){
    const id = Number(row.entry_id);
    const key = normalizeReactionKey(row.reaction);
    if(!id || !key) continue;
    if(!mine[id]) mine[id] = emptyMyChangelogReactions();
    mine[id][key] = true;
  }
  return mine;
}

async function pgFetchChangelogEntriesWithReactions({ limit = 0, ids = null, userId } = {}){
  await pgInitPromise;
  const rows = ids?.length ? await pgChangelogByIds(ids) : await pgAllChangelog(limit);
  const payloads = (rows || []).map((r) => toChangelogPayload(r));
  const entryIds = payloads.map((p) => p.id).filter(Boolean);
  if(!entryIds.length) return payloads;
  const counts = await pgFetchChangelogReactionCounts(entryIds);
  const mine = await pgFetchChangelogUserReactions(entryIds, userId);
  return payloads.map((p) => ({
    ...p,
    reactions: counts[p.id] || emptyChangelogReactions(),
    myReactions: mine[p.id] || emptyMyChangelogReactions(),
  }));
}

async function pgFetchFaqQuestionsWithReactions(username){
  await pgInitPromise;
  const { rows } = await pgPool.query(
    "SELECT id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted FROM faq_questions WHERE is_deleted=0 ORDER BY created_at DESC"
  );
  const payloads = (rows || []).map((r) => toFaqPayload(r)).filter(Boolean);
  const ids = payloads.map((p) => p.id).filter(Boolean);
  if(!ids.length) return payloads;
  const counts = await pgFetchFaqReactionCounts(ids);
  const mine = await pgFaqMyReactions(ids, username);
  return payloads.map((p) => ({
    ...p,
    reactions: counts[p.id] || emptyFaqReactions(),
    myReactions: mine[p.id] || emptyMyFaqReactions(),
  }));
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

async function pgCreateFaqQuestion({ title, details }){
  await pgInitPromise;
  const now = Date.now();
  const { rows } = await pgPool.query(
    "INSERT INTO faq_questions (created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted) VALUES ($1,$2,$3,'', NULL, NULL, 0) RETURNING id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted",
    [now, title, details]
  );
  return rows[0] || null;
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

async function pgUpdateFaqAnswer({ id, answerBody, answeredBy }){
  await pgInitPromise;
  const now = Date.now();
  const { rowCount, rows } = await pgPool.query(
    "UPDATE faq_questions SET answer_body=$1, answered_at=$2, answered_by=$3 WHERE id=$4 AND is_deleted=0 RETURNING id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted",
    [answerBody, now, answeredBy, id]
  );
  if(!rowCount) return null;
  return rows[0] || null;
}

async function pgDeleteChangelogEntry(id){
  await pgInitPromise;
  await pgPool.query("DELETE FROM changelog_reactions WHERE entry_id=$1", [id]);
  const { rowCount } = await pgPool.query("DELETE FROM changelog_entries WHERE id=$1", [id]);
  return rowCount > 0;
}

async function pgChangelogEntryExists(entryId){
  await pgInitPromise;
  const { rowCount } = await pgPool.query("SELECT 1 FROM changelog_entries WHERE id=$1", [entryId]);
  return rowCount > 0;
}

async function pgFaqQuestionExists(questionId){
  await pgInitPromise;
  const { rowCount } = await pgPool.query("SELECT 1 FROM faq_questions WHERE id=$1 AND is_deleted=0", [questionId]);
  return rowCount > 0;
}

async function pgDeleteFaqQuestion(id){
  await pgInitPromise;
  // Soft-delete to preserve audit/history and avoid breaking references.
  await pgPool.query("DELETE FROM faq_reactions WHERE question_id=$1", [id]);
  const { rowCount } = await pgPool.query("UPDATE faq_questions SET is_deleted=1 WHERE id=$1", [id]);
  return rowCount > 0;
}

async function pgToggleChangelogReaction(entryId, userId, reaction){
  await pgInitPromise;
  const client = await pgPool.connect();
  try{
    await client.query("BEGIN");
    const existing = await client.query(
      "DELETE FROM changelog_reactions WHERE entry_id=$1 AND user_id=$2 AND reaction=$3 RETURNING 1",
      [entryId, userId, reaction]
    );
    if(!existing.rowCount){
      await client.query(
        "INSERT INTO changelog_reactions (entry_id, user_id, reaction, created_at) VALUES ($1,$2,$3,$4)",
        [entryId, userId, reaction, Date.now()]
      );
    }
    await client.query("COMMIT");
  }catch(err){
    await client.query("ROLLBACK");
    throw err;
  }finally{
    client.release();
  }
}

async function pgToggleFaqReaction(questionId, username, reaction){
  await pgInitPromise;
  const client = await pgPool.connect();
  try{
    await client.query("BEGIN");
    const existing = await client.query(
      "DELETE FROM faq_reactions WHERE question_id=$1 AND username=$2 AND reaction_key=$3 RETURNING 1",
      [questionId, username, reaction]
    );
    if(!existing.rowCount){
      await client.query(
        "INSERT INTO faq_reactions (question_id, username, reaction_key, created_at) VALUES ($1,$2,$3,$4)",
        [questionId, username, reaction, Date.now()]
      );
    }
    await client.query("COMMIT");
  }catch(err){
    await client.query("ROLLBACK");
    throw err;
  }finally{
    client.release();
  }
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

async function sqliteFetchChangelogEntries({ limit = 0, ids = null } = {}) {
  if (ids?.length) {
    const ph = ids.map(() => "?").join(",");
    return dbAllAsync(
      `SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries WHERE id IN (${ph}) ORDER BY seq DESC`,
      ids
    );
  }
  const sql =
    "SELECT id, seq, title, body, created_at, updated_at, author_id FROM changelog_entries ORDER BY seq DESC" +
    (limit ? " LIMIT ?" : "");
  return dbAllAsync(sql, limit ? [limit] : []);
}

async function sqliteFetchChangelogReactionCounts(entryIds = []) {
  if (!entryIds.length) return {};
  const ph = entryIds.map(() => "?").join(",");
  const rows = await dbAllAsync(
    `SELECT entry_id, reaction, COUNT(*) as count FROM changelog_reactions WHERE entry_id IN (${ph}) GROUP BY entry_id, reaction`,
    entryIds
  );
  const map = {};
  for (const row of rows || []) {
    const id = Number(row.entry_id);
    const key = normalizeReactionKey(row.reaction);
    if (!id || !key) continue;
    if (!map[id]) map[id] = emptyChangelogReactions();
    map[id][key] = Number(row.count) || 0;
  }
  return map;
}

async function sqliteFetchChangelogUserReactions(entryIds = [], userId) {
  if (!entryIds.length || !userId) return {};
  const ph = entryIds.map(() => "?").join(",");
  const rows = await dbAllAsync(
    `SELECT entry_id, reaction FROM changelog_reactions WHERE entry_id IN (${ph}) AND user_id=?`,
    [...entryIds, userId]
  );
  const mine = {};
  for (const row of rows || []) {
    const id = Number(row.entry_id);
    const key = normalizeReactionKey(row.reaction);
    if (!id || !key) continue;
    if (!mine[id]) mine[id] = emptyMyChangelogReactions();
    mine[id][key] = true;
  }
  return mine;
}

async function sqliteFetchChangelogEntriesWithReactions({ limit = 0, ids = null, userId } = {}) {
  const rows = await sqliteFetchChangelogEntries({ limit, ids });
  const payloads = (rows || []).map((r) => toChangelogPayload(r));
  const entryIds = payloads.map((p) => p.id).filter(Boolean);
  if (!entryIds.length) return payloads;
  const counts = await sqliteFetchChangelogReactionCounts(entryIds);
  const mine = await sqliteFetchChangelogUserReactions(entryIds, userId);
  return payloads.map((p) => ({
    ...p,
    reactions: counts[p.id] || emptyChangelogReactions(),
    myReactions: mine[p.id] || emptyMyChangelogReactions(),
  }));
}

async function sqliteToggleChangelogReaction(entryId, userId, reaction) {
  await dbRunAsync("BEGIN");
  try {
    const existing = await dbGetAsync(
      `SELECT 1 FROM changelog_reactions WHERE entry_id=? AND user_id=? AND reaction=?`,
      [entryId, userId, reaction]
    );
    if (existing) {
      await dbRunAsync(`DELETE FROM changelog_reactions WHERE entry_id=? AND user_id=? AND reaction=?`, [entryId, userId, reaction]);
    } else {
      await dbRunAsync(
        `INSERT INTO changelog_reactions (entry_id, user_id, reaction, created_at) VALUES (?, ?, ?, ?)`,
        [entryId, userId, reaction, Date.now()]
      );
    }
    await dbRunAsync("COMMIT");
  } catch (e) {
    await dbRunAsync("ROLLBACK");
    throw e;
  }
}

async function sqliteChangelogEntryExists(entryId) {
  const row = await dbGetAsync(`SELECT 1 FROM changelog_entries WHERE id=?`, [entryId]);
  return !!row;
}

async function fetchChangelogEntriesWithReactions({ limit = 0, ids = null, userId } = {}) {
  if (await pgChangelogEnabled()) {
    try {
      return await pgFetchChangelogEntriesWithReactions({ limit, ids, userId });
    } catch (e) {
      console.warn("[changelog] PG reactions fallback:", e?.message || e);
    }
  }

  return sqliteFetchChangelogEntriesWithReactions({ limit, ids, userId });
}

async function pgChangelogReactionPayload(entryId, userId) {
  const rows = await pgFetchChangelogEntriesWithReactions({ ids: [entryId], userId });
  return rows?.[0] || null;
}

async function sqliteChangelogReactionPayload(entryId, userId) {
  const rows = await sqliteFetchChangelogEntriesWithReactions({ ids: [entryId], userId });
  return rows?.[0] || null;
}

async function sqliteFetchFaqQuestions(){
  return dbAllAsync(
    `SELECT id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted FROM faq_questions WHERE is_deleted=0 ORDER BY created_at DESC`
  );
}

async function sqliteFetchFaqReactionCounts(questionIds = []){
  if(!questionIds.length) return {};
  const ph = questionIds.map(() => "?").join(",");
  const rows = await dbAllAsync(
    `SELECT question_id, reaction_key, COUNT(*) as count FROM faq_reactions WHERE question_id IN (${ph}) GROUP BY question_id, reaction_key`,
    questionIds
  );
  const map = {};
  for(const row of rows || []){
    const id = Number(row.question_id);
    const key = normalizeFaqReactionKey(row.reaction_key);
    if(!id || !key) continue;
    if(!map[id]) map[id] = emptyFaqReactions();
    map[id][key] = Number(row.count) || 0;
  }
  return map;
}

async function sqliteFetchFaqUserReactions(questionIds = [], username){
  if(!questionIds.length || !username) return {};
  const ph = questionIds.map(() => "?").join(",");
  const rows = await dbAllAsync(
    `SELECT question_id, reaction_key FROM faq_reactions WHERE question_id IN (${ph}) AND username=?`,
    [...questionIds, username]
  );
  const mine = {};
  for(const row of rows || []){
    const id = Number(row.question_id);
    const key = normalizeFaqReactionKey(row.reaction_key);
    if(!id || !key) continue;
    if(!mine[id]) mine[id] = emptyMyFaqReactions();
    mine[id][key] = true;
  }
  return mine;
}

async function sqliteFetchFaqQuestionsWithReactions(username){
  const rows = await sqliteFetchFaqQuestions();
  const payloads = (rows || []).map(toFaqPayload).filter(Boolean);
  const ids = payloads.map((p) => p.id).filter(Boolean);
  if(!ids.length) return payloads;
  const counts = await sqliteFetchFaqReactionCounts(ids);
  const mine = await sqliteFetchFaqUserReactions(ids, username);
  return payloads.map((p) => ({
    ...p,
    reactions: counts[p.id] || emptyFaqReactions(),
    myReactions: mine[p.id] || emptyMyFaqReactions(),
  }));
}

async function sqliteToggleFaqReaction(questionId, username, reaction){
  await dbRunAsync("BEGIN");
  try {
    const existing = await dbGetAsync(
      `SELECT 1 FROM faq_reactions WHERE question_id=? AND username=? AND reaction_key=?`,
      [questionId, username, reaction]
    );
    if(existing){
      await dbRunAsync(`DELETE FROM faq_reactions WHERE question_id=? AND username=? AND reaction_key=?`, [questionId, username, reaction]);
    } else {
      await dbRunAsync(
        `INSERT INTO faq_reactions (question_id, username, reaction_key, created_at) VALUES (?, ?, ?, ?)`,
        [questionId, username, reaction, Date.now()]
      );
    }
    await dbRunAsync("COMMIT");
  } catch (e) {
    await dbRunAsync("ROLLBACK");
    throw e;
  }
}

async function sqliteFaqQuestionExists(questionId){
  const row = await dbGetAsync(`SELECT 1 FROM faq_questions WHERE id=? AND is_deleted=0`, [questionId]);
  return !!row;
}

async function sqliteCreateFaqQuestion({ title, details }){
  const now = Date.now();
  const result = await dbRunAsync(
    `INSERT INTO faq_questions (created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted) VALUES (?, ?, ?, '', NULL, NULL, 0)`,
    [now, title, details]
  );
  const row = await dbGetAsync(
    `SELECT id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted FROM faq_questions WHERE id=?`,
    [result.lastID]
  );
  return row;
}

async function sqliteUpdateFaqAnswer({ id, answerBody, answeredBy }){
  const now = Date.now();
  const result = await dbRunAsync(
    `UPDATE faq_questions SET answer_body=?, answered_at=?, answered_by=? WHERE id=? AND is_deleted=0`,
    [answerBody, now, answeredBy, id]
  );
  if(!result?.changes) return null;
  return dbGetAsync(
    `SELECT id, created_at, question_title, question_details, answer_body, answered_at, answered_by, is_deleted FROM faq_questions WHERE id=?`,
    [id]
  );
}

async function sqliteDeleteFaqQuestion(id){
  await dbRunAsync(`DELETE FROM faq_reactions WHERE question_id=?`, [id]);
  const result = await dbRunAsync(`UPDATE faq_questions SET is_deleted=1 WHERE id=?`, [id]);
  return !!result?.changes;
}

async function fetchFaqQuestionsWithReactions(username){
  if(await pgChangelogEnabled()){
    try{
      return await pgFetchFaqQuestionsWithReactions(username);
    }catch(e){
      console.warn("[faq] PG fetch fallback:", e?.message || e);
    }
  }
  return sqliteFetchFaqQuestionsWithReactions(username);
}

async function faqReactionPayload(questionId, username){
  if(await pgChangelogEnabled()){
    try{
      const rows = await pgFetchFaqQuestionsWithReactions(username);
      return rows.find((r)=> String(r.id) === String(questionId)) || null;
    }catch(e){
      console.warn("[faq] PG reaction payload fallback:", e?.message || e);
    }
  }
  const rows = await sqliteFetchFaqQuestionsWithReactions(username);
  return rows.find((r)=> String(r.id) === String(questionId)) || null;
}

const COMMON_PASSWORDS = new Set([
  "123456",
  "password",
  "password123",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "12345678910",
  "111111",
  "000000",
  "qwerty",
  "qwerty123",
  "qwertyuiop",
  "abc123",
  "abc12345",
  "letmein",
  "letmein123",
  "iloveyou",
  "welcome",
  "welcome123",
  "admin",
  "admin123",
  "monkey",
  "dragon",
  "football",
  "princess",
  "sunshine",
  "trustno1",
]);

function isPasswordTooWeak(password) {
  const lower = String(password || "").toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return true;
  if (lower.includes("password") && lower.length <= 12) return true;
  return false;
}

function captchaEnabled() {
  return (CAPTCHA_PROVIDER === "turnstile" || CAPTCHA_PROVIDER === "hcaptcha")
    && CAPTCHA_SECRET_KEY
    && CAPTCHA_SITE_KEY;
}

async function verifyCaptcha(token, ip) {
  if (!captchaEnabled()) return { ok: true };
  if (!token) return { ok: false, message: "Captcha required." };
  try {
    if (CAPTCHA_PROVIDER === "turnstile") {
      const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: CAPTCHA_SECRET_KEY,
          response: token,
          remoteip: ip || "",
        }),
      });
      const data = await resp.json();
      return data?.success ? { ok: true } : { ok: false, message: "Captcha failed." };
    }
    if (CAPTCHA_PROVIDER === "hcaptcha") {
      const resp = await fetch("https://hcaptcha.com/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: CAPTCHA_SECRET_KEY,
          response: token,
          remoteip: ip || "",
        }),
      });
      const data = await resp.json();
      return data?.success ? { ok: true } : { ok: false, message: "Captcha failed." };
    }
  } catch (e) {
    console.warn("[captcha] verify failed:", e?.message || e);
    return { ok: false, message: "Captcha unavailable." };
  }
  return { ok: true };
}

app.get("/api/captcha-config", (_req, res) => {
  if (!captchaEnabled()) return res.json({ provider: "none" });
  return res.json({ provider: CAPTCHA_PROVIDER, siteKey: CAPTCHA_SITE_KEY });
});

// ---- Auth routes
// ---- Auth routes
app.post("/register", registerLimiter, async (req, res) => {
  try {
    const username = sanitizeUsername(req.body?.username);
    const password = String(req.body?.password || "");

    if (!username || username.length < 2) return res.status(400).send("Invalid username");
    if (!password || password.length < 12) return res.status(400).send("Password must be 12+ chars");
    if (isPasswordTooWeak(password)) return res.status(400).send("Password is too common");

    const captchaToken = String(req.body?.captchaToken || "");
    const captcha = await verifyCaptcha(captchaToken, getClientIp(req));
    if (!captcha.ok) return res.status(400).send(captcha.message || "Captcha failed");

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

    req.session.regenerate((regenErr) => {
      if (regenErr) return res.status(500).send("Session failed");
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
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("Registration failed");
  }
});
app.post("/login", loginIpLimiter, async (req, res) => {
  try {
    const raw = String(req.body?.username || "").trim().slice(0, 64);
    const cleaned = cleanUsernameForLookup(raw);
    const legacy = sanitizeUsername(raw);
    const candidates = Array.from(new Set([raw, cleaned, legacy].filter(Boolean)));

    const password = String(req.body?.password || "");
    if (!candidates.length || !password) return res.status(400).send("Missing credentials");

    const ip = getClientIp(req);
    const usernameKey = normKey(raw || cleaned || legacy || "");
    const loginKey = `${ip}:${usernameKey || "unknown"}`;
    const ipKey = `ip:${ip}`;
    const backoff = checkLoginBackoff(loginKey);
    const ipBackoff = checkLoginBackoff(ipKey);
    if (backoff.blocked || ipBackoff.blocked) {
      return res.status(429).send("Too many attempts. Try again later.");
    }

    const captchaToken = String(req.body?.captchaToken || "");
    const captcha = await verifyCaptcha(captchaToken, ip);
    if (!captcha.ok) {
      recordLoginFailure(loginKey);
      recordLoginFailure(ipKey);
      return res.status(400).send(captcha.message || "Captcha failed");
    }

    // 1) Prefer Postgres users (new registrations land here)
    let pgUser = null;
    for (const cand of candidates) {
      pgUser = await pgGetUserByUsername(cand);
      if (pgUser) break;
    }
    if (pgUser && pgUser.password_hash) {
      const stored = String(pgUser.password_hash || "").trim();

      // Backwards compatibility: some legacy accounts may have a non-bcrypt value in password_hash.
      // If it looks like a bcrypt hash, verify normally; otherwise treat it as plaintext and upgrade on success.
      const looksBcrypt = stored.startsWith("$2");
      let ok = false;

      if (looksBcrypt) {
        ok = await bcrypt.compare(password, stored);
      } else {
        ok = password === stored;
        if (ok) {
          const upgraded = await bcrypt.hash(password, 10);
          await pgPool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [upgraded, pgUser.id]).catch(() => {});
          pgUser.password_hash = upgraded;
        }
      }

      if (!ok) {
        recordLoginFailure(loginKey);
        recordLoginFailure(ipKey);
        logSecurityEvent("login_failure", { ip, username: raw, store: "pg" });
        return res.status(401).send("Invalid username or password");
      }

      if (password.length < 12) {
        const nonce = crypto.randomBytes(18).toString("hex");
        req.session.user = null;
        req.session.passwordUpgrade = {
          userId: pgUser.id,
          username: pgUser.username,
          issuedAt: Date.now(),
          nonce,
        };
        clearPasswordUpgradeFailures(req);
        clearLoginFailures(loginKey);
        clearLoginFailures(ipKey);
        logSecurityEvent("password_upgrade_required", { ip, username: pgUser.username, userId: pgUser.id, store: "pg" });
        return req.session.save((saveErr) => {
          if (saveErr) return res.status(500).send("Session save failed");
          return res.json({ ok: false, code: "PASSWORD_UPGRADE_REQUIRED" });
        });
      }

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
      req.session.regenerate((regenErr) => {
        if (regenErr) return res.status(500).send("Session failed");
        req.session.user = {
          id: pgUser.id,
          username: pgUser.username,
          role: pgUser.role,
          theme,
          avatar: avatarUrlFromRow(pgUser) || "",
          avatar_updated: pgUser.avatar_updated ?? pgUser.avatarUpdated ?? null,
        };
        dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", pgUser.id]).catch(() => {});
        initGoldTick(pgUser.id);
        clearLoginFailures(loginKey);
        clearLoginFailures(ipKey);
        req.session.save((saveErr) => {
          if (saveErr) return res.status(500).send("Session save failed");
          return res.json({ ok: true });
        });
      });
      return;
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
    if (!row) {
      recordLoginFailure(loginKey);
      recordLoginFailure(ipKey);
      logSecurityEvent("login_failure", { ip, username: raw, store: "sqlite" });
      return res.status(401).send("Invalid username or password");
    }

    // Handle legacy password column (if present)
    let passwordHash = typeof row.password_hash === "string" ? row.password_hash : "";

    if (!passwordHash) {
      const legacyPassword = typeof row.password === "string" ? row.password : "";
      if (!legacyPassword) return res.status(401).send("Invalid username or password");

      const legacyMatches = legacyPassword.startsWith("$2")
        ? await bcrypt.compare(password, legacyPassword)
        : legacyPassword === password;

      if (!legacyMatches) {
        recordLoginFailure(loginKey);
        recordLoginFailure(ipKey);
        logSecurityEvent("login_failure", { ip, username: raw, store: "sqlite" });
        return res.status(401).send("Invalid username or password");
      }

      passwordHash = legacyPassword.startsWith("$2") ? legacyPassword : await bcrypt.hash(password, 10);

      await dbRunAsync("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [passwordHash, row.id]);
      row.password_hash = passwordHash;
    }

    {
      const stored = String(row.password_hash || "").trim();
      const looksBcrypt = stored.startsWith("$2");
      let ok = false;

      if (looksBcrypt) {
        ok = await bcrypt.compare(password, stored);
      } else {
        // Legacy plaintext stored in password_hash (or other non-bcrypt formats).
        ok = password === stored;
        if (ok) {
          const upgraded = await bcrypt.hash(password, 10);
          await dbRunAsync("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [upgraded, row.id]).catch(() => {});
          row.password_hash = upgraded;
        }
      }

      if (!ok) {
        recordLoginFailure(loginKey);
        recordLoginFailure(ipKey);
        logSecurityEvent("login_failure", { ip, username: raw, store: "sqlite" });
        return res.status(401).send("Invalid username or password");
      }
    }
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

    if (password.length < 12) {
      const nonce = crypto.randomBytes(18).toString("hex");
      req.session.user = null;
      req.session.passwordUpgrade = {
        userId: row.id,
        username: row.username,
        issuedAt: Date.now(),
        nonce,
      };
      clearPasswordUpgradeFailures(req);
      clearLoginFailures(loginKey);
      clearLoginFailures(ipKey);
      logSecurityEvent("password_upgrade_required", { ip, username: row.username, userId: row.id, store: "sqlite" });
      return req.session.save((saveErr) => {
        if (saveErr) return res.status(500).send("Session save failed");
        return res.json({ ok: false, code: "PASSWORD_UPGRADE_REQUIRED" });
      });
    }

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

    req.session.regenerate((regenErr) => {
      if (regenErr) return res.status(500).send("Session failed");
      req.session.user = { id: row.id, username: row.username, role: row.role, theme, avatar: avatarUrlFromRow(row) || "", avatar_updated: row.avatar_updated ?? row.avatarUpdated ?? null };
      dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", row.id]).catch(() => {});
      awardLoginXp(row.id, row.role);
      awardDailyLoginGold(row);
      initGoldTick(row.id);
      clearLoginFailures(loginKey);
      clearLoginFailures(ipKey);
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).send("Session save failed");
        return res.json({ ok: true });
      });
    });
    return;
  } catch (e) {
    console.error(e);
    return res.status(500).send("Login failed");
  }
});

app.get("/password-upgrade/status", (req, res) => {
  const pending = req.session?.passwordUpgrade || null;
  if (!pending?.userId) return res.json({ required: false });
  return res.json({ required: true, nonce: pending.nonce || "" });
});

app.get("/password-upgrade", (req, res) => {
  if (!req.session?.passwordUpgrade?.userId) return res.redirect("/");
  return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.post("/password-upgrade", passwordUpgradeLimiter, async (req, res) => {
  const pending = req.session?.passwordUpgrade || null;
  if (!pending?.userId) return res.status(401).json({ ok: false, message: "No password upgrade pending." });

  const ip = getClientIp(req);
  const attemptState = getPasswordUpgradeAttemptState(req);
  if (attemptState.blocked) {
    return res.status(429).json({ ok: false, code: "PASSWORD_UPGRADE_LOCKED", message: "Too many attempts. Try again later." });
  }

  const currentPassword = String(req.body?.currentPassword || "");
  const newPassword = String(req.body?.newPassword || "");
  const confirmPassword = String(req.body?.confirmPassword || "");
  const nonce = String(req.body?.nonce || "");

  if (pending.nonce && nonce !== pending.nonce) {
    return res.status(403).json({ ok: false, message: "Invalid session." });
  }

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ ok: false, message: "Missing required fields." });
  }

  if (newPassword.length < 12) {
    return res.status(400).json({ ok: false, message: "Password must be 12+ chars." });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ ok: false, message: "Passwords do not match." });
  }
  if (isPasswordTooWeak(newPassword)) {
    return res.status(400).json({ ok: false, message: "Password is too common." });
  }

  try {
    const userId = Number(pending.userId);
    const pgUser = await pgGetUserById(userId).catch(() => null);
    const sqliteRow = await dbGetAsync("SELECT * FROM users WHERE id = ?", [userId]).catch(() => null);

    if (!pgUser && !sqliteRow) {
      recordPasswordUpgradeFailure(req);
      logSecurityEvent("password_upgrade_failed", { ip, userId, username: pending.username, reason: "user_not_found" });
      return res.status(401).json({ ok: false, message: "Password upgrade failed." });
    }

    let stored = "";
    if (pgUser?.password_hash) stored = String(pgUser.password_hash || "").trim();
    else if (sqliteRow?.password_hash) stored = String(sqliteRow.password_hash || "").trim();
    else if (sqliteRow?.password) stored = String(sqliteRow.password || "").trim();

    const looksBcrypt = stored.startsWith("$2");
    const matches = looksBcrypt
      ? await bcrypt.compare(currentPassword, stored)
      : currentPassword === stored;

    if (!matches) {
      recordPasswordUpgradeFailure(req);
      logSecurityEvent("password_upgrade_failed", { ip, userId, username: pending.username, reason: "password_mismatch" });
      return res.status(401).json({ ok: false, message: "Current password incorrect." });
    }

    const newHash = await bcrypt.hash(newPassword, 12);

    if (pgUser?.id) {
      await pgPool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, pgUser.id]).catch(() => {});
    } else if (sqliteRow?.id) {
      const createdAtValue = PG_USERS_CREATED_AT_IS_TIMESTAMP
        ? new Date(Number(sqliteRow.created_at || Date.now()))
        : Number(sqliteRow.created_at || Date.now());
      await pgPool.query(
        `INSERT INTO users (id, username, password_hash, role, created_at, theme, gold, xp)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (username) DO UPDATE
           SET password_hash = EXCLUDED.password_hash,
               role = COALESCE(users.role, EXCLUDED.role),
               theme = COALESCE(users.theme, EXCLUDED.theme),
               gold = COALESCE(users.gold, EXCLUDED.gold),
               xp = COALESCE(users.xp, EXCLUDED.xp)`,
        [
          sqliteRow.id,
          sqliteRow.username,
          newHash,
          sqliteRow.role || "User",
          createdAtValue,
          sanitizeThemeNameServer(sqliteRow.theme || DEFAULT_THEME),
          Number(sqliteRow.gold || 0),
          Number(sqliteRow.xp || 0),
        ]
      ).catch(() => {});
    }

    if (sqliteRow?.id) {
      await dbRunAsync("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [newHash, sqliteRow.id]).catch(() => {});
    } else if (pgUser?.id) {
      await dbRunAsync(
        `INSERT INTO users (id, username, password_hash, role, created_at, gold, xp, theme)
         VALUES (?,?,?,?,?,?,?,?)`,
        [
          pgUser.id,
          pgUser.username,
          newHash,
          pgUser.role || "User",
          Number(pgUser.created_at || Date.now()),
          Number(pgUser.gold || 0),
          Number(pgUser.xp || 0),
          sanitizeThemeNameServer(pgUser.theme || DEFAULT_THEME),
        ]
      ).catch(() => {});
    }

    const refreshedPgUser = await pgGetUserById(userId).catch(() => null);
    const sessionRow = refreshedPgUser || sqliteRow || pgUser;
    const role = sessionRow?.role || "User";
    const theme = sanitizeThemeNameServer(sessionRow?.theme || DEFAULT_THEME);
    const avatar = avatarUrlFromRow(sessionRow) || "";
    const avatarUpdated = sessionRow?.avatar_updated ?? sessionRow?.avatarUpdated ?? null;

    clearPasswordUpgradeFailures(req);
    delete req.session.passwordUpgrade;

    req.session.regenerate((regenErr) => {
      if (regenErr) return res.status(500).json({ ok: false, message: "Session failed." });
      req.session.user = {
        id: userId,
        username: sessionRow?.username || pending.username,
        role,
        theme,
        avatar,
        avatar_updated: avatarUpdated,
      };
      dbRunAsync("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", userId]).catch(() => {});
      if (!pgUser && sqliteRow) {
        awardLoginXp(userId, role);
        awardDailyLoginGold(sqliteRow);
      }
      initGoldTick(userId);
      logSecurityEvent("password_upgrade_success", { ip, userId, username: sessionRow?.username || pending.username });
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ ok: false, message: "Session save failed." });
        return res.json({ ok: true });
      });
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Password upgrade failed." });
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
    // IMPORTANT: /me is used to hydrate the session and client state.
    // We MUST select role/theme and avatar fields; otherwise we may overwrite
    // req.session.user.role/theme with undefined, which breaks permission gating.
    const { rows } = await pgPool.query(
      `SELECT id,
              username,
              role,
              theme,
              avatar,
              avatar_updated,
              avatar_bytes
         FROM users
        WHERE id = $1
        LIMIT 1`,
      [req.session.user.id]
    );

    let row = rows[0];

    // If not in Postgres yet, fallback to SQLite and (optionally) sync
    if (!row) {
      const srow = await dbGet(
        "SELECT id, username FROM users WHERE id = ?",
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

app.get("/api/restriction", async (req, res) => {
  try {
    const username = req.session?.user?.username;
    if (!username) return res.json({ type: "none" });
    const r = await getRestrictionByUsername(username);
    res.json({ type: r.type || "none", reason: r.reason || "", expiresAt: r.expiresAt || null, now: Date.now() });
  } catch (e) {
    res.json({ type: "none" });
  }
});



//
// Owner-only: live feature flags
//
app.get("/api/owner/flags", requireOwner, async (_req, res) => {
  try {
    const flags = await refreshFeatureFlags();
    res.json({ ok: true, flags });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_load_flags" });
  }
});

app.post("/api/owner/flags", moderationHttpLimiter, requireOwner, express.json({ limit: "64kb" }), async (req, res) => {
  try {
    const incoming = req.body?.flags;
    if (!incoming || typeof incoming !== "object") return res.status(400).json({ ok: false, error: "bad_flags" });
    // sanitize: flat object of booleans/numbers/strings
    const next = {};
    for (const [k, v] of Object.entries(incoming)) {
      if (!k || typeof k !== "string") continue;
      if (typeof v === "boolean" || typeof v === "number" || typeof v === "string") next[k] = v;
    }
    await setConfigJson("feature_flags", next);
    FEATURE_FLAGS_CACHE = { ...next };
    try { io.emit("featureFlags:update", next); } catch {}
    res.json({ ok: true, flags: next });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_save_flags" });
  }
});

//
// Owner-only: session map
//
app.get("/api/owner/sessions", requireOwner, async (_req, res) => {
  try {
    const out = [];
    for (const [sid, meta] of sessionMetaBySocketId.entries()) {
      if (!meta) continue;
      out.push({ socketId: sid, ...meta });
    }
    // Sort: newest first
    out.sort((a, b) => (b.connectedAt || 0) - (a.connectedAt || 0));
    res.json({ ok: true, sessions: out, now: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_load_sessions" });
  }
});

//
// Admin/Owner: heat score snapshot (invisible to users)
//
app.get("/api/mod/heat", requireLogin, async (req, res) => {
  try {
    if (!requireMinRole(req.session.user.role, "Admin")) return res.status(403).send("Forbidden");
    const rows = [];
    for (const [uid, heat] of heatByUserId.entries()) {
      rows.push({ userId: uid, heat });
    }
    rows.sort((a, b) => b.heat - a.heat);
    res.json({ ok: true, rows, now: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_load_heat" });
  }
});

//
// Daily micro-challenges
//
function dayKeyNow() {
  // UTC day key to keep consistent across timezones
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const da = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${da}`;
}

const DAILY_CHALLENGE_POOL = [
  { id: "room_msgs_5", label: "Send 5 room messages", type: "room_messages", goal: 5, rewardXp: 30, rewardGold: 25 },
  { id: "react_3", label: "React 3 times", type: "reactions", goal: 3, rewardXp: 25, rewardGold: 20 },
  { id: "rooms_2", label: "Visit 2 different rooms", type: "unique_rooms", goal: 2, rewardXp: 25, rewardGold: 15 },
];

function pickDailyChallenges() {
  // deterministic order for now (stable + simple)
  return DAILY_CHALLENGE_POOL.slice(0, 3);
}

async function loadDailyProgress(userId, dayKey) {
  const now = Date.now();
  // prefer PG if user exists there
  if (await pgUserExists(userId)) {
    const { rows } = await pgPool.query(
      "SELECT progress_json, claimed_json FROM daily_challenge_progress WHERE user_id=$1 AND day_key=$2",
      [userId, dayKey]
    );
    if (rows?.length) return { progress: rows[0].progress_json || {}, claimed: rows[0].claimed_json || {}, updatedAt: now, pg: true };
    return { progress: {}, claimed: {}, updatedAt: now, pg: true };
  }
  const row = await dbGetAsync(
    "SELECT progress_json, claimed_json FROM daily_challenge_progress WHERE user_id=? AND day_key=?",
    [userId, dayKey]
  );
  return {
    progress: safeJsonParse(row?.progress_json || "{}", {}),
    claimed: safeJsonParse(row?.claimed_json || "{}", {}),
    updatedAt: now,
    pg: false,
  };
}

async function saveDailyProgress(userId, dayKey, progress, claimed, pg) {
  const now = Date.now();
  if (pg) {
    await pgPool.query(
      `INSERT INTO daily_challenge_progress (user_id, day_key, progress_json, claimed_json, updated_at)
       VALUES ($1,$2,$3::jsonb,$4::jsonb,$5)
       ON CONFLICT (user_id, day_key)
       DO UPDATE SET progress_json=EXCLUDED.progress_json, claimed_json=EXCLUDED.claimed_json, updated_at=EXCLUDED.updated_at`,
      [userId, dayKey, JSON.stringify(progress || {}), JSON.stringify(claimed || {}), now]
    );
    return;
  }
  await dbRunAsync(
    `INSERT INTO daily_challenge_progress (user_id, day_key, progress_json, claimed_json, updated_at)
     VALUES (?,?,?,?,?)
     ON CONFLICT(user_id, day_key) DO UPDATE SET progress_json=excluded.progress_json, claimed_json=excluded.claimed_json, updated_at=excluded.updated_at`,
    [userId, dayKey, JSON.stringify(progress || {}), JSON.stringify(claimed || {}), now]
  );
}



async function bumpDailyProgress(userId, dayKey, challengeId, delta, pgHint = null) {
  const d = Math.max(0, Math.floor(Number(delta) || 0));
  if (!userId || !challengeId || !d) return;
  try {
    const prog = await loadDailyProgress(userId, dayKey);
    const progress = prog.progress || {};
    const claimed = prog.claimed || {};
    progress[challengeId] = Math.max(0, Math.floor(Number(progress[challengeId] || 0) + d));
    await saveDailyProgress(userId, dayKey, progress, claimed, prog.pg);
  } catch {}
}

async function bumpDailyUniqueRoom(userId, dayKey, roomName, pgHint = null) {
  if (!userId || !roomName) return;
  const key = "__rooms";
  try {
    const prog = await loadDailyProgress(userId, dayKey);
    const progress = prog.progress || {};
    const claimed = prog.claimed || {};
    const arr = Array.isArray(progress[key]) ? progress[key] : [];
    if (!arr.includes(roomName)) arr.push(roomName);
    progress[key] = arr.slice(0, 25);
    // mirror into rooms_2 challenge progress as count
    progress["rooms_2"] = arr.length;
    await saveDailyProgress(userId, dayKey, progress, claimed, prog.pg);
  } catch {}
}

async function creditGold(userId, amount, reason = "reward") {
  const amt = Math.max(0, Math.floor(Number(amount) || 0));
  if (!amt) return null;

  if (await pgUserExists(userId)) {
    const client = await pgPool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query("SELECT gold FROM users WHERE id=$1 FOR UPDATE", [userId]);
      const current = Number(rows?.[0]?.gold || 0);
      const next = current + amt;
      await client.query("UPDATE users SET gold=$1 WHERE id=$2", [next, userId]);
      await client.query(
        "INSERT INTO gold_transactions (user_id, amount, reason, created_at) VALUES ($1,$2,$3,$4)",
        [userId, amt, String(reason || "reward"), Date.now()]
      );
      await client.query("COMMIT");
      try { emitProgressionUpdate(userId); } catch {}
      return { ok: true, gold: next };
    } catch (e) {
      try { await client.query("ROLLBACK"); } catch {}
      return null;
    } finally {
      client.release();
    }
  }

  await dbRunAsync("UPDATE users SET gold = gold + ? WHERE id = ?", [amt, userId]);
  try { emitProgressionUpdate(userId); } catch {}
  return { ok: true };
}

app.get("/api/challenges/today", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const dk = dayKeyNow();
    const picked = pickDailyChallenges();
    const prog = await loadDailyProgress(userId, dk);
    const progress = prog.progress || {};
    const claimed = prog.claimed || {};
    const challenges = picked.map((c) => {
      const p = Number(progress[c.id] || 0);
      const done = p >= c.goal;
      return {
        ...c,
        progress: p,
        done,
        claimed: !!claimed[c.id],
      };
    });
    res.json({ ok: true, dayKey: dk, challenges });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_load_challenges" });
  }
});

app.post("/api/challenges/claim", strictLimiter, requireLogin, express.json({ limit: "32kb" }), async (req, res) => {
  try {
    const userId = req.session.user.id;
    const dk = dayKeyNow();
    const id = String(req.body?.id || "");
    const picked = pickDailyChallenges();
    const challenge = picked.find((c) => c.id === id);
    if (!challenge) return res.status(400).json({ ok: false, error: "unknown_challenge" });

    const prog = await loadDailyProgress(userId, dk);
    const progress = prog.progress || {};
    const claimed = prog.claimed || {};
    if (claimed[id]) return res.json({ ok: true, already: true });

    const p = Number(progress[id] || 0);
    if (p < challenge.goal) return res.status(400).json({ ok: false, error: "not_complete" });

    claimed[id] = true;
    await saveDailyProgress(userId, dk, progress, claimed, prog.pg);

    // reward
    try { await applyXpGain(userId, challenge.rewardXp || 0, { reason: "daily_challenge" }); } catch {}
    try { await creditGold(userId, challenge.rewardGold || 0, `daily_challenge:${id}`); } catch {}

    res.json({ ok: true, claimed: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: "failed_to_claim" });
  }
});

app.get("/api/vibes", (_req, res) => {
  res.json({ limit: VIBE_TAG_LIMIT, vibes: VIBE_TAGS });
});

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

app.post("/api/me/username", strictLimiter, requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const raw = String(req.body?.username || "").trim();
  const newName = sanitizeUsername(raw);

  if (!newName || newName.length < 2) {
    return res.status(400).json({ ok: false, message: "Invalid username." });
  }
  if (normKey(newName) === normKey(req.session.user.username)) {
    return res.status(400).json({ ok: false, message: "That is already your username." });
  }
  if (!(await pgUsersEnabled())) {
    return res.status(503).json({ ok: false, message: "Username changes are unavailable right now." });
  }

  let nextGold = null;
  const client = await pgPool.connect();
  try {
    await client.query("BEGIN");

    const existing = await client.query(
      "SELECT id FROM users WHERE lower(username) = lower($1) AND id <> $2 LIMIT 1",
      [newName, userId]
    );
    if (existing.rows?.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ ok: false, message: "Username already taken." });
    }

    const spend = await spendGoldInTransaction(client, userId, USERNAME_CHANGE_COST, "username_change");
    if (!spend.ok) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, message: spend.message || "Not enough gold.", gold: spend.gold ?? null });
    }

    await client.query("UPDATE users SET username = $1 WHERE id = $2", [newName, userId]);
    await client.query("COMMIT");
    nextGold = spend.gold;
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    if (e?.code === "23505") {
      return res.status(409).json({ ok: false, message: "Username already taken." });
    }
    console.error("[username change]", e);
    return res.status(500).json({ ok: false, message: "Failed to update username." });
  } finally {
    client.release();
  }

  // Best-effort mirror to SQLite so legacy lookups remain consistent.
  try {
    await dbRunAsync("UPDATE users SET username = ? WHERE id = ?", [newName, userId]);
  } catch (e) {
    console.warn("[username change][sqlite]", e?.message || e);
  }

  req.session.user.username = newName;
  return req.session.save((saveErr) => {
    if (saveErr) return res.status(500).json({ ok: false, message: "Session save failed." });
    updateLiveUsername(userId, newName);
    return res.json({ ok: true, username: newName, gold: nextGold, cost: USERNAME_CHANGE_COST });
  });
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


app.post("/api/me/theme", strictLimiter, requireLogin, async (req, res) => {
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

app.post("/api/themes/purchase", strictLimiter, requireLogin, express.json({ limit: "8kb" }), async (req, res) => {
  const userId = req.session.user.id;
  const themeId = String(req.body?.themeId || "").trim();
  const theme = THEME_BY_ID.get(themeId);
  if (!theme) return res.status(404).json({ ok: false, error: "theme_not_found" });
  if (!theme.isPurchasable || !theme.goldPrice) {
    return res.status(400).json({ ok: false, error: "theme_not_purchasable" });
  }

  try {
    if (await pgUserExists(userId)) {
      const client = await pgPool.connect();
      try {
        await client.query("BEGIN");
        const { rows } = await client.query(
          "SELECT gold, prefs_json FROM users WHERE id = $1 LIMIT 1 FOR UPDATE",
          [userId]
        );
        const row = rows?.[0];
        if (!row) {
          await client.query("ROLLBACK");
          return res.status(404).json({ ok: false, error: "user_not_found" });
        }
        const gold = Number(row.gold || 0);
        const prefs = normalizePrefs(safeJsonParse(row.prefs_json, {}));
        const owned = new Set(normalizeThemeIdList(prefs.ownedThemeIds));
        if (owned.has(themeId)) {
          await client.query("COMMIT");
          return res.json({ ok: true, gold, ownedThemeIds: Array.from(owned) });
        }
        if (gold < theme.goldPrice) {
          await client.query("ROLLBACK");
          return res.status(400).json({ ok: false, error: "insufficient_gold", gold });
        }
        const nextGold = gold - theme.goldPrice;
        owned.add(themeId);
        const nextPrefs = normalizePrefs({ ...prefs, ownedThemeIds: Array.from(owned) });
        await client.query("UPDATE users SET gold = $1, prefs_json = $2::jsonb WHERE id = $3", [
          nextGold,
          JSON.stringify(nextPrefs),
          userId,
        ]);
        await client.query("COMMIT");
        db.run("UPDATE users SET gold = ?, prefs_json = ? WHERE id = ?", [
          nextGold,
          JSON.stringify(nextPrefs),
          userId,
        ]);
        return res.json({ ok: true, gold: nextGold, ownedThemeIds: nextPrefs.ownedThemeIds });
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    }
  } catch (e) {
    console.warn("[themes][purchase][pg] failed, falling back to sqlite:", e?.message || e);
  }

  db.get("SELECT gold, prefs_json FROM users WHERE id = ?", [userId], (_e, row) => {
    if (!row) return res.status(404).json({ ok: false, error: "user_not_found" });
    const gold = Number(row.gold || 0);
    const prefs = normalizePrefs(safeJsonParse(row.prefs_json, {}));
    const owned = new Set(normalizeThemeIdList(prefs.ownedThemeIds));
    if (owned.has(themeId)) {
      return res.json({ ok: true, gold, ownedThemeIds: Array.from(owned) });
    }
    if (gold < theme.goldPrice) {
      return res.status(400).json({ ok: false, error: "insufficient_gold", gold });
    }
    const nextGold = gold - theme.goldPrice;
    owned.add(themeId);
    const nextPrefs = normalizePrefs({ ...prefs, ownedThemeIds: Array.from(owned) });
    db.run(
      "UPDATE users SET gold = ?, prefs_json = ? WHERE id = ?",
      [nextGold, JSON.stringify(nextPrefs), userId],
      (err2) => {
        if (err2) return res.status(500).json({ ok: false, error: "purchase_failed" });
        return res.json({ ok: true, gold: nextGold, ownedThemeIds: nextPrefs.ownedThemeIds });
      }
    );
  });
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
function safeString(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return fallback;
  return String(value);
}
function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}
const PREFS_DEFAULTS = Object.freeze({
  dmBadgePrefs: { direct: "#ed4245", group: "#5865f2" },
  dmNeonColor: "#5865f2",
  dmThemePrefs: { background: "#1e1f22" },
  pinnedThemeIds: [],
  favoriteThemeIds: [],
  ownedThemeIds: [],
  sound: {
    enabled: false,
    room: true,
    dm: true,
    mention: true,
    sent: false,
    receive: false,
    reaction: false,
  },
});
function normalizeSoundPrefs(raw) {
  const base = { ...PREFS_DEFAULTS.sound };
  if (!raw || typeof raw !== "object") return base;
  for (const key of Object.keys(base)) {
    if (typeof raw[key] === "boolean") base[key] = raw[key];
  }
  return base;
}
function normalizeThemeIdList(raw) {
  if (!Array.isArray(raw)) return [];
  const unique = [];
  const seen = new Set();
  for (const id of raw) {
    const key = String(id || "");
    if (!THEME_ID_SET.has(key) || seen.has(key)) continue;
    seen.add(key);
    unique.push(key);
  }
  return unique;
}
function enforcePinnedLimit(prefs, role) {
  const maxPins = roleRank(role || "User") >= roleRank("VIP") ? 5 : 2;
  prefs.pinnedThemeIds = normalizeThemeIdList(prefs.pinnedThemeIds).slice(0, maxPins);
  return prefs;
}
function normalizePrefs(raw) {
  const prefs = raw && typeof raw === "object" ? raw : {};
  const dmBadgePrefs = { ...PREFS_DEFAULTS.dmBadgePrefs };
  if (prefs.dmBadgePrefs && typeof prefs.dmBadgePrefs === "object") {
    if (typeof prefs.dmBadgePrefs.direct === "string") dmBadgePrefs.direct = prefs.dmBadgePrefs.direct;
    if (typeof prefs.dmBadgePrefs.group === "string") dmBadgePrefs.group = prefs.dmBadgePrefs.group;
  }
  const dmNeonColor = typeof prefs.dmNeonColor === "string"
    ? prefs.dmNeonColor
    : (typeof prefs.dmThemePrefs?.background === "string" ? prefs.dmThemePrefs.background : PREFS_DEFAULTS.dmNeonColor);
  const dmThemePrefs = { ...PREFS_DEFAULTS.dmThemePrefs };
  if (prefs.dmThemePrefs && typeof prefs.dmThemePrefs === "object") {
    if (typeof prefs.dmThemePrefs.background === "string") dmThemePrefs.background = prefs.dmThemePrefs.background;
  }
  return {
    ...prefs,
    pinnedThemeIds: normalizeThemeIdList(prefs.pinnedThemeIds),
    favoriteThemeIds: normalizeThemeIdList(prefs.favoriteThemeIds),
    ownedThemeIds: normalizeThemeIdList(prefs.ownedThemeIds),
    dmBadgePrefs,
    dmNeonColor,
    dmThemePrefs,
    sound: normalizeSoundPrefs(prefs.sound),
    chatFx: sanitizeChatFx(prefs.chatFx),
    textStyle: sanitizeTextStyle(prefs.textStyle),
    customization: sanitizeCustomization(prefs.customization, prefs.textStyle)
  };
}
function sanitizePrefsInput(p) {
  const out = {};
  if (p && typeof p === "object") {
    if (p.dmBadgePrefs && typeof p.dmBadgePrefs === "object") out.dmBadgePrefs = p.dmBadgePrefs;
    if (typeof p.dmNeonColor === "string") out.dmNeonColor = p.dmNeonColor;
    if (p.dmThemePrefs && typeof p.dmThemePrefs === "object") out.dmThemePrefs = p.dmThemePrefs;
    if (Array.isArray(p.pinnedThemeIds)) out.pinnedThemeIds = normalizeThemeIdList(p.pinnedThemeIds);
    if (Array.isArray(p.favoriteThemeIds)) out.favoriteThemeIds = normalizeThemeIdList(p.favoriteThemeIds);
    if (p.chatFx && typeof p.chatFx === "object") out.chatFx = sanitizeChatFx(p.chatFx);
    if (p.textStyle && typeof p.textStyle === "object") out.textStyle = sanitizeTextStyle(p.textStyle);
    if (p.customization && typeof p.customization === "object") {
      out.customization = sanitizeCustomization(p.customization, p.textStyle);
    }
    if (p.userNameStyle && typeof p.userNameStyle === "object") {
      out.customization = sanitizeCustomization({ userNameStyle: p.userNameStyle }, p.textStyle);
    }
    if (p.messageTextStyle && typeof p.messageTextStyle === "object") {
      const existing = out.customization || sanitizeCustomization(p.customization, p.textStyle) || {};
      out.customization = sanitizeCustomization({ ...existing, messageTextStyle: p.messageTextStyle }, p.textStyle);
    }
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

function buildAuthorsFxMap(usernames, cb) {
  const unique = Array.from(new Set((usernames || []).filter((name) => typeof name === "string" && name.trim())));
  if (!unique.length) return cb({});

  // Prefer Postgres during the SQLite -> PG migration.
  (async () => {
    const base = {};
    for (const name of unique) base[name] = mergeChatFxWithCustomization(null, null, null);

    try {
      if (pgPool) {
          const { rows } = await pgPool.query(
            "SELECT username, prefs_json FROM users WHERE username = ANY($1::text[])",
            [unique]
          );
          for (const row of rows || []) {
            const prefs = safeJsonParse(row?.prefs_json, {});
            base[row.username] = mergeChatFxWithCustomization(prefs?.chatFx, prefs?.customization, prefs?.textStyle);
          }
          return cb(base);
        }
    } catch (e) {
      console.warn("[chatFx][authorsFx][pg] failed, falling back to sqlite:", e?.message || e);
    }

    const placeholders = unique.map(() => "?").join(",");
    db.all(
      `SELECT username, prefs_json FROM users WHERE username IN (${placeholders})`,
      unique,
      (_e, rows) => {
        for (const row of rows || []) {
          const prefs = safeJsonParse(row?.prefs_json, {});
          base[row.username] = mergeChatFxWithCustomization(prefs?.chatFx, prefs?.customization, prefs?.textStyle);
        }
        cb(base);
      }
    );
  })();
}

function emitUserFxUpdate(socket) {
  if (!socket?.user) return;
  io.emit("user fx updated", {
    userId: socket.user.id,
    username: socket.user.username,
    chatFx: mergeChatFxWithCustomization(socket.user.chatFx, socket.user.customization, socket.user.textStyle),
    customization: sanitizeCustomization(socket.user.customization, socket.user.textStyle)
  });
}

function updateLiveChatFx(userId, chatFx) {
  const sid = socketIdByUserId.get(userId);
  const s = sid ? io.sockets.sockets.get(sid) : null;
  if (!s?.user) return;
  s.user.chatFx = sanitizeChatFx(chatFx);
  if (s.currentRoom) emitUserList(s.currentRoom);
  emitUserFxUpdate(s);
}

function updateLiveCustomization(userId, customization, textStyle) {
  const sid = socketIdByUserId.get(userId);
  const s = sid ? io.sockets.sockets.get(sid) : null;
  if (!s?.user) return;
  s.user.customization = sanitizeCustomization(customization, textStyle);
  s.user.textStyle = sanitizeTextStyle(textStyle);
  if (s.currentRoom) emitUserList(s.currentRoom);
  emitUserFxUpdate(s);
}

app.get("/api/me/prefs", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  try {
    // Prefer Postgres if the user exists there
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query("SELECT prefs_json FROM users WHERE id = $1 LIMIT 1", [userId]);
      const prefs = normalizePrefs(safeJsonParse(rows?.[0]?.prefs_json, {}));
      return res.json({ prefs });
    }
  } catch (e) {
    console.warn("[prefs][pg] read failed, falling back to sqlite:", e?.message || e);
  }

  db.get("SELECT prefs_json FROM users WHERE id = ?", [userId], (err, row) => {
    if (err) return res.status(500).send("Failed");
    const prefs = normalizePrefs(safeJsonParse(row?.prefs_json, {}));
    return res.json({ prefs });
  });
});

app.post("/api/me/prefs", strictLimiter, requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const incoming = sanitizePrefsInput(req.body?.prefs ?? req.body);
  const shouldUpdateChatFx = Object.prototype.hasOwnProperty.call(incoming || {}, "chatFx");
  const shouldUpdateTextStyle = Object.prototype.hasOwnProperty.call(incoming || {}, "textStyle");
  const shouldUpdateCustomization = Object.prototype.hasOwnProperty.call(incoming || {}, "customization")
    || Object.prototype.hasOwnProperty.call(incoming || {}, "userNameStyle")
    || Object.prototype.hasOwnProperty.call(incoming || {}, "messageTextStyle");

  try {
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query("SELECT prefs_json FROM users WHERE id = $1 LIMIT 1", [userId]);
      const current = safeJsonParse(rows?.[0]?.prefs_json, {});
      const currentPrefs = normalizePrefs(current || {});
      const mergedCustomization = sanitizeCustomization(
        { ...(currentPrefs.customization || {}), ...(incoming.customization || {}) },
        currentPrefs.textStyle || incoming.textStyle
      );
      const merged = enforcePinnedLimit(
        normalizePrefs({ ...(current || {}), ...(incoming || {}), customization: mergedCustomization }),
        req.session.user.role
      );
      // IMPORTANT: node-postgres does not reliably serialize plain JS objects to JSON/JSONB.
      // Always stringify and cast to jsonb to ensure prefs are actually persisted.
      await pgPool.query("UPDATE users SET prefs_json = $1::jsonb WHERE id = $2", [JSON.stringify(merged), userId]);

      // Keep SQLite in sync
      db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId]);
      if (shouldUpdateChatFx) {
        req.session.user.chatFx = sanitizeChatFx(merged.chatFx);
        updateLiveChatFx(userId, merged.chatFx);
      }
      if (shouldUpdateTextStyle) {
        req.session.user.textStyle = sanitizeTextStyle(merged.textStyle);
      }
      if (shouldUpdateCustomization) {
        req.session.user.customization = sanitizeCustomization(merged.customization, merged.textStyle);
        updateLiveCustomization(userId, merged.customization, merged.textStyle);
      }
      return res.json({ ok: true, prefs: merged });
    }
  } catch (e) {
    console.warn("[prefs][pg] update failed, falling back to sqlite:", e?.message || e);
  }

  // SQLite fallback
  db.get("SELECT prefs_json FROM users WHERE id = ?", [userId], (_e, row) => {
    const current = safeJsonParse(row?.prefs_json, {});
    const currentPrefs = normalizePrefs(current || {});
    const mergedCustomization = sanitizeCustomization(
      { ...(currentPrefs.customization || {}), ...(incoming.customization || {}) },
      currentPrefs.textStyle || incoming.textStyle
    );
    const merged = enforcePinnedLimit(
      normalizePrefs({ ...(current || {}), ...(incoming || {}), customization: mergedCustomization }),
      req.session.user.role
    );
    db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId], (err2) => {
      if (err2) return res.status(500).send("Failed");
      if (shouldUpdateChatFx) {
        req.session.user.chatFx = sanitizeChatFx(merged.chatFx);
        updateLiveChatFx(userId, merged.chatFx);
      }
      if (shouldUpdateTextStyle) {
        req.session.user.textStyle = sanitizeTextStyle(merged.textStyle);
      }
      if (shouldUpdateCustomization) {
        req.session.user.customization = sanitizeCustomization(merged.customization, merged.textStyle);
        updateLiveCustomization(userId, merged.customization, merged.textStyle);
      }
      return res.json({ ok: true, prefs: merged });
    });
  });
});

app.post("/api/profile/customization", strictLimiter, requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const rawCustomization = req.body?.customization ?? {
    userNameStyle: req.body?.userNameStyle,
    messageTextStyle: req.body?.messageTextStyle
  };
  const incoming = sanitizePrefsInput({ customization: rawCustomization, textStyle: req.body?.textStyle });
  const shouldUpdateCustomization = Object.prototype.hasOwnProperty.call(incoming || {}, "customization");
  if (!shouldUpdateCustomization) return res.status(400).send("Invalid customization");

  try {
    if (await pgUserExists(userId)) {
      const { rows } = await pgPool.query("SELECT prefs_json FROM users WHERE id = $1 LIMIT 1", [userId]);
      const current = safeJsonParse(rows?.[0]?.prefs_json, {});
      const currentPrefs = normalizePrefs(current || {});
      const mergedCustomization = sanitizeCustomization(
        { ...(currentPrefs.customization || {}), ...(incoming.customization || {}) },
        currentPrefs.textStyle || incoming.textStyle
      );
      const merged = enforcePinnedLimit(
        normalizePrefs({ ...(current || {}), ...(incoming || {}), customization: mergedCustomization }),
        req.session.user.role
      );
      await pgPool.query("UPDATE users SET prefs_json = $1::jsonb WHERE id = $2", [JSON.stringify(merged), userId]);
      db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId]);
      req.session.user.customization = sanitizeCustomization(merged.customization, merged.textStyle);
      updateLiveCustomization(userId, merged.customization, merged.textStyle);
      return res.json({ ok: true, customization: merged.customization, prefs: merged });
    }
  } catch (e) {
    console.warn("[prefs][pg] customization update failed, falling back to sqlite:", e?.message || e);
  }

  db.get("SELECT prefs_json FROM users WHERE id = ?", [userId], (_e, row) => {
    const current = safeJsonParse(row?.prefs_json, {});
    const currentPrefs = normalizePrefs(current || {});
    const mergedCustomization = sanitizeCustomization(
      { ...(currentPrefs.customization || {}), ...(incoming.customization || {}) },
      currentPrefs.textStyle || incoming.textStyle
    );
    const merged = enforcePinnedLimit(
      normalizePrefs({ ...(current || {}), ...(incoming || {}), customization: mergedCustomization }),
      req.session.user.role
    );
    db.run("UPDATE users SET prefs_json = ? WHERE id = ?", [JSON.stringify(merged), userId], (err2) => {
      if (err2) return res.status(500).send("Failed");
      req.session.user.customization = sanitizeCustomization(merged.customization, merged.textStyle);
      updateLiveCustomization(userId, merged.customization, merged.textStyle);
      return res.json({ ok: true, customization: merged.customization, prefs: merged });
    });
  });
});

function sortLeaderboardRows(rows, valueKey) {
  return rows
    .map((r) => ({ ...r, username: r.username || "" }))
    .sort((a, b) => {
      const diff = Number(b[valueKey] || 0) - Number(a[valueKey] || 0);
      if (diff !== 0) return diff;
      const base = String(a.username).localeCompare(String(b.username), undefined, { sensitivity: "base" });
      if (base !== 0) return base;
      return String(a.username).localeCompare(String(b.username));
    });
}

let leaderboardCache = { payload: null, updatedAt: 0, inFlight: null };

async function buildLeaderboardPayload() {
  const merged = new Map();

  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT u.id,
                u.username,
                COALESCE(u.xp, 0) AS xp,
                COALESCE(u.gold, 0) AS gold,
                COALESCE(u.dice_sixes, 0) AS dice_sixes,
                COALESCE(COUNT(pl.user_id), 0) AS likes
           FROM users u
           LEFT JOIN profile_likes pl ON pl.target_user_id = u.id
          GROUP BY u.id`
      );
      for (const row of rows || []) {
        const id = Number(row.id);
        if (!Number.isInteger(id)) continue;
        merged.set(id, row);
      }
    } catch (e) {
      console.warn("[leaderboard][pg] failed, falling back to sqlite:", e?.message || e);
    }
  }

  // Backfill any users that only exist in SQLite so the leaderboard includes everyone.
  const sqliteRows = await dbAllAsync(
    `SELECT u.id,
            u.username,
            COALESCE(u.xp, 0) AS xp,
            COALESCE(u.gold, 0) AS gold,
            COALESCE(u.dice_sixes, 0) AS dice_sixes,
            COALESCE(COUNT(pl.user_id), 0) AS likes
       FROM users u
       LEFT JOIN profile_likes pl ON pl.target_user_id = u.id
      GROUP BY u.id`
  );
  for (const row of sqliteRows || []) {
    const id = Number(row.id);
    if (!Number.isInteger(id) || merged.has(id)) continue;
    merged.set(id, row);
  }

  const rows = Array.from(merged.values());
  const xpRowsRaw = rows.map((r) => ({ username: r.username, xp: r.xp }));
  const goldRowsRaw = rows.map((r) => ({ username: r.username, gold: r.gold }));
  const diceRowsRaw = rows.map((r) => ({ username: r.username, dice_sixes: r.dice_sixes }));
  const likeRowsRaw = rows.map((r) => ({ username: r.username, likes: r.likes }));

  const xpRows = sortLeaderboardRows(xpRowsRaw, "xp");
  const goldRows = sortLeaderboardRows(goldRowsRaw, "gold");
  const diceRows = sortLeaderboardRows(diceRowsRaw, "dice_sixes");
  const likeRows = sortLeaderboardRows(likeRowsRaw, "likes");

  return {
    xp: xpRows.map((r) => ({ username: r.username, level: levelInfo(r.xp || 0).level, xp: Number(r.xp || 0) })),
    gold: goldRows.map((r) => ({ username: r.username, gold: Number(r.gold || 0) })),
    dice: diceRows.map((r) => ({ username: r.username, sixes: Number(r.dice_sixes || 0) })),
    likes: likeRows.map((r) => ({ username: r.username, likes: Number(r.likes || 0) })),
  };
}

async function rebuildLeaderboards({ force = false } = {}) {
  if (leaderboardCache.inFlight && !force) return leaderboardCache.inFlight;
  leaderboardCache.inFlight = (async () => {
    const payload = await buildLeaderboardPayload();
    leaderboardCache.payload = payload;
    leaderboardCache.updatedAt = Date.now();
    return payload;
  })();
  try {
    return await leaderboardCache.inFlight;
  } finally {
    leaderboardCache.inFlight = null;
  }
}

async function sendLeaderboard(res) {
  try {
    const now = Date.now();
    const shouldRefresh = !leaderboardCache.payload || (now - leaderboardCache.updatedAt > 10_000);
    const payload = shouldRefresh ? await rebuildLeaderboards({ force: true }) : leaderboardCache.payload;
    return res.json(payload);
  } catch (err) {
    return res.status(500).json({ ok: false });
  }
}

async function fetchChessLeaderboard(limit = 50, offset = 0) {
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  if (await chessPgEnabled()) {
    const { rows } = await pgPool.query(
      `SELECT s.user_id,
              u.username,
              s.chess_elo,
              s.chess_games_played,
              s.chess_wins,
              s.chess_losses,
              s.chess_draws,
              s.chess_peak_elo
         FROM chess_user_stats s
         JOIN users u ON u.id = s.user_id
        ORDER BY s.chess_elo DESC, s.chess_games_played DESC, u.username ASC
        LIMIT $1 OFFSET $2`,
      [safeLimit, safeOffset]
    );
    return rows || [];
  }

  const rows = await dbAllAsync(
    `SELECT s.user_id,
            u.username,
            s.chess_elo,
            s.chess_games_played,
            s.chess_wins,
            s.chess_losses,
            s.chess_draws,
            s.chess_peak_elo
       FROM chess_user_stats s
       JOIN users u ON u.id = s.user_id
      ORDER BY s.chess_elo DESC, s.chess_games_played DESC, u.username ASC
      LIMIT ? OFFSET ?`,
    [safeLimit, safeOffset]
  );
  return rows || [];
}

app.get("/api/leaderboard", requireLogin, async (_req, res) => sendLeaderboard(res));
app.get("/api/leaderboards", requireLogin, async (_req, res) => sendLeaderboard(res));

app.get("/api/chess/leaderboard", requireLogin, async (req, res) => {
  try {
    const rows = await fetchChessLeaderboard(req.query?.limit, req.query?.offset);
    const payload = rows.map((row) => {
      const games = Number(row.chess_games_played || 0);
      const wins = Number(row.chess_wins || 0);
      const losses = Number(row.chess_losses || 0);
      const draws = Number(row.chess_draws || 0);
      const winrate = games > 0 ? Math.round((wins / games) * 1000) / 10 : 0;
      return {
        userId: Number(row.user_id),
        username: row.username,
        elo: Number(row.chess_elo || CHESS_DEFAULT_ELO),
        gamesPlayed: games,
        wins,
        losses,
        draws,
        winrate,
        peakElo: Number(row.chess_peak_elo || row.chess_elo || CHESS_DEFAULT_ELO),
      };
    });
    return res.json({ rows: payload, limit: Number(req.query?.limit || 50), offset: Number(req.query?.offset || 0) });
  } catch (err) {
    console.warn("[chess] leaderboard failed:", err?.message || err);
    return res.status(500).json({ ok: false });
  }
});

app.post("/api/me/award-gold", strictLimiter, requireLogin, (req, res) => {
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
app.get("/rooms", requireLogin, async (req, res) => {
  try {
    const payload = await buildRoomStructurePayload(req.session?.user?.id);
    return res.json(payload);
  } catch (e) {
    console.warn("[rooms] failed to load room structure", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.get("/api/rooms/structure", requireLogin, async (req, res) => {
  try {
    const payload = await buildRoomStructurePayload(req.session?.user?.id);
    return res.json(payload);
  } catch (e) {
    console.warn("[rooms] failed to load room structure", e?.message || e);
    return res.status(500).send("Failed");
  }
});

async function buildSurvivalHistoryPayload() {
  const seasons = await fetchSurvivalHistory(10);
  const result = [];
  for (const season of seasons || []) {
    const winner = season.status === "finished" ? await fetchSurvivalWinner(season.id) : null;
    result.push({
      id: season.id,
      title: season.title,
      status: season.status,
      created_at: season.created_at,
      winner,
    });
  }
  return result;
}

function formatSurvivalSeason(season) {
  if (!season) return null;
  const { seed, options } = parseSurvivalSeedPayload(season.rng_seed);
  return {
    id: season.id,
    room_id: season.room_id,
    created_by_user_id: season.created_by_user_id,
    title: season.title,
    status: season.status,
    day_index: season.day_index,
    phase: season.phase,
    rng_seed: seed || null,
    options: options || {},
    created_at: season.created_at,
    updated_at: season.updated_at,
  };
}


function buildSurvivalArenaPayload(season, participants = []) {
  if (!season) return null;
  const { seed } = parseSurvivalSeedPayload(season.rng_seed);
  const rng = createSeededRng(`${seed || "survival"}:arena:${season.day_index}:${season.phase}`);
  const dangerLevels = {};
  for (const z of SURVIVAL_ZONES) {
    // 0–5, lightly influenced by population + RNG (purely cosmetic for now).
    const pop = participants.filter((p) => p.alive && normalizeSurvivalZoneName(p.location) === z).length;
    const base = clamp(Math.round(rng() * 3) + (pop ? 1 : 0), 0, 5);
    dangerLevels[z] = base;
  }
  const lobbySet = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
  return {
    zones: [...SURVIVAL_ZONES],
    dangerLevels,
    lobbyUserIds: Array.from(lobbySet.values()),
  };
}

async function buildSurvivalPayload(season, { beforeId = null, limit = 200 } = {}) {
  if (!season) {
    return { season: null, participants: [], alliances: [], events: [], history: await buildSurvivalHistoryPayload() };
  }
  const [participants, alliances, events, history, winner] = await Promise.all([
    fetchSurvivalParticipants(season.id),
    fetchSurvivalAlliances(season.id),
    fetchSurvivalEvents(season.id, { limit, beforeId }),
    buildSurvivalHistoryPayload(),
    season.status === "finished" ? fetchSurvivalWinner(season.id) : Promise.resolve(null),
  ]);
  return {
    season: formatSurvivalSeason(season),
    participants,
    alliances,
    events,
    winner,
    history,
    arena: buildSurvivalArenaPayload(season, participants),
  };
}

// Admin+ can create rooms
app.post("/rooms", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const actor = req.session.user;
  if (!requireMinRole(actor.role, "Admin")) return res.status(403).send("Forbidden");

  const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
  if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });

  const name = sanitizeRoomName(req.body?.name || req.body?.room || "");
  if (!name) return res.status(400).send("Invalid room name");

  try {
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [name]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name=?`, [name]);
    if (row) return res.status(409).send("Room already exists");

    const requestedCategoryId = Number(req.body?.category_id) || null;
    const requestedMasterId = Number(req.body?.master_id) || null;
    const requestedUserRoom = req.body?.is_user_room ? true : false;
    const resolved = await resolveRoomCategoryId({
      categoryId: requestedCategoryId,
      masterId: requestedMasterId,
      isUserRoom: requestedUserRoom,
    });
    const categoryId = resolved?.categoryId ?? null;
    let categoryRow = null;
    if (categoryId) {
      if (await pgUsersEnabled()) {
        const { rows } = await pgPool.query(
          `SELECT c.id, c.master_id, m.name as master_name
             FROM room_categories c
             JOIN room_master_categories m ON m.id = c.master_id
            WHERE c.id = $1 LIMIT 1`,
          [categoryId]
        );
        categoryRow = rows?.[0] || null;
      } else {
        categoryRow = await dbGetAsync(
          `SELECT c.id, c.master_id, m.name as master_name
             FROM room_categories c
             JOIN room_master_categories m ON m.id = c.master_id
            WHERE c.id = ? LIMIT 1`,
          [categoryId]
        );
      }
    }
    const isUserRoom = categoryRow?.master_name === "User Rooms" ? 1 : 0;
    let nextSort = { maxSort: 0, maxsort: 0 };
    if (categoryId) {
      if (await pgUsersEnabled()) {
        const { rows } = await pgPool.query(
          `SELECT COALESCE(MAX(room_sort_order), 0) as maxsort FROM rooms WHERE category_id = $1`,
          [categoryId]
        );
        nextSort = rows?.[0] || nextSort;
      } else {
        nextSort = await dbGetAsync(
          `SELECT COALESCE(MAX(room_sort_order), 0) as maxSort FROM rooms WHERE category_id = ?`,
          [categoryId]
        );
      }
    }
    const sortOrder = Number(nextSort?.maxsort || nextSort?.maxSort || 0) + 1;

    if (await pgUsersEnabled()) {
      await pgPool.query(
        `INSERT INTO rooms (name, created_by, created_at, category_id, room_sort_order, created_by_user_id, is_user_room, vip_only, staff_only, min_level, is_locked, maintenance_mode, events_enabled, slowmode_seconds, archived, is_system)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [name, actor.id, Date.now(), categoryId, sortOrder, actor.id, isUserRoom,
         Number(req.body?.vip_only)||0,
         Number(req.body?.staff_only)||0,
         Math.max(0, Math.min(999, Number(req.body?.min_level)||0)),
         Number(req.body?.is_locked)||0,
         Number(req.body?.maintenance_mode)||0,
         (req.body?.events_enabled === 0 || req.body?.events_enabled === "0") ? 0 : 1,
         Math.max(0, Math.min(3600, Number(req.body?.slowmode_seconds)||0)),
         0,
         0]
      );
    } else {
      await dbRunAsync(
        `INSERT INTO rooms (name, created_by, created_at, category_id, room_sort_order, created_by_user_id, is_user_room, vip_only, staff_only, min_level, is_locked, maintenance_mode, events_enabled, slowmode_seconds, archived, is_system)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, actor.id, Date.now(), categoryId, sortOrder, actor.id, isUserRoom,
         Number(req.body?.vip_only)||0,
         Number(req.body?.staff_only)||0,
         Math.max(0, Math.min(999, Number(req.body?.min_level)||0)),
         Number(req.body?.is_locked)||0,
         Number(req.body?.maintenance_mode)||0,
         (req.body?.events_enabled === 0 || req.body?.events_enabled === "0") ? 0 : 1,
         Math.max(0, Math.min(3600, Number(req.body?.slowmode_seconds)||0)),
         0,
         0]
      );
    }

    logModAction({ actor, action: "room.create", room: name, details: null });
    await applyRoomStructureChange({
      action: "room.create",
      actorUserId: actor.id,
      auditPayload: { name, category_id: categoryId, is_user_room: isUserRoom },
    });

    return res.json({ ok: true, name });
  } catch (e) {
    console.warn("[rooms] create failed", e?.message || e);
    return res.status(500).send("Failed to create room");
  }
});

// ---- Survival Simulator API

// Lobby endpoints (opt-in list for quick season fills)
app.get("/api/survival/lobby", requireLogin, async (_req, res) => {
  try {
    const set = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
    return res.json({ user_ids: Array.from(set.values()) });
  } catch {
    return res.json({ user_ids: [] });
  }
});

app.post("/api/survival/lobby/join", requireLogin, async (req, res) => {
  try {
    const uid = Number(req.session?.user?.id);
    if (!uid) return res.status(401).send("Unauthorized");
    const set = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
    set.add(uid);
    io.to(SURVIVAL_ROOM_ID).emit("survival:lobby", { user_ids: Array.from(set.values()) });
    return res.json({ ok: true, user_ids: Array.from(set.values()) });
  } catch (e) {
    return res.status(500).send("Failed");
  }
});

app.post("/api/survival/lobby/leave", requireLogin, async (req, res) => {
  try {
    const uid = Number(req.session?.user?.id);
    if (!uid) return res.status(401).send("Unauthorized");
    const set = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
    set.delete(uid);
    io.to(SURVIVAL_ROOM_ID).emit("survival:lobby", { user_ids: Array.from(set.values()) });
    return res.json({ ok: true, user_ids: Array.from(set.values()) });
  } catch (e) {
    return res.status(500).send("Failed");
  }
});

app.get("/api/survival/current", requireLogin, async (_req, res) => {
  try {
    const season = await fetchSurvivalCurrentSeason();
    const payload = await buildSurvivalPayload(season);
    return res.json(payload);
  } catch (e) {
    console.warn("[survival] current failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.get("/api/survival/seasons/:id", requireLogin, async (req, res) => {
  try {
    const beforeId = req.query?.before ? Number(req.query.before) : null;
    const season = await fetchSurvivalSeasonById(req.params.id);
    if (!season) return res.status(404).send("Not found");
    const payload = await buildSurvivalPayload(season, { beforeId });
    return res.json(payload);
  } catch (e) {
    console.warn("[survival] fetch season failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.post("/api/survival/seasons", survivalLimiter, requireCoOwner, express.json({ limit: "32kb" }), async (req, res) => {
  const now = Date.now();
  const lastStart = survivalSeasonCooldownByRoom.get(SURVIVAL_ROOM_DB_ID) || 0;
  if (now - lastStart < SURVIVAL_SEASON_COOLDOWN_MS) {
    return res.status(429).json({ message: "Please wait before starting another season." });
  }

  const running = await fetchSurvivalCurrentSeason();
  if (running && running.status === "running") {
    return res.status(409).json({ message: "A season is already running." });
  }

  const titleRaw = String(req.body?.title || "").trim();
  const title = titleRaw || `Season — ${new Date(now).toLocaleString()}`;
  const participantIds = Array.isArray(req.body?.participant_user_ids)
    ? req.body.participant_user_ids
    : [];
  const npcRaw = String(req.body?.npc_names || "").trim();
  const fillSlots = Number(req.body?.fill_slots || 0) || 0;
  // include_lobby is accepted for client compatibility; if you later persist lobby signups,
  // this flag can add them here.
  const includeLobby = !!req.body?.include_lobby;
  const options = {
    includeCouples: !!req.body?.options?.includeCouples,
    chaoticMode: !!req.body?.options?.chaoticMode,
  };

  // If requested, merge in current lobby signups as participants (deduped).
  if (includeLobby) {
    const set = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
    const lobbyIds = Array.from(set.values()).map((x) => Number(x)).filter((x) => x > 0);
    if (lobbyIds.length) {
      const merged = new Set([...(participantIds || []).map((x) => Number(x)).filter((x) => x > 0), ...lobbyIds]);
      participantIds.length = 0;
      for (const id of merged.values()) participantIds.push(id);
    }
  }
  // User snapshots (real site users)
  const userSnapshots = await fetchSurvivalUserSnapshots(participantIds);

  // NPC names typed by owner (comma/newline separated)
  const npcTyped = npcRaw
    ? npcRaw
        .split(/[\n,]/g)
        .map((s) => String(s || "").trim())
        .filter(Boolean)
    : [];
  const npcNames = [];
  {
    const seen = new Set();
    for (const n of npcTyped) {
      const key = n.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      npcNames.push(n.slice(0, 40));
      if (npcNames.length >= 80) break;
    }
  }

  // Total participants can be users + NPCs. We only require at least two TOTAL.
  const baseCount = userSnapshots.length + npcNames.length;
  const desiredCount = fillSlots > 0 ? Math.max(fillSlots, baseCount) : baseCount;
  if (desiredCount < 2) {
    return res.status(400).json({ message: "Add at least two total participants (users or NPC names)." });
  }

  const seed = crypto.randomBytes(8).toString("hex");
  const rng = createSeededRng(seed);

  // Auto-fill NPC slots to desiredCount using a fixed pool (25 male / 25 female)
  if (desiredCount > baseCount) {
    const used = new Set([
      ...userSnapshots.map((u) => String(u.display_name || "").toLowerCase()),
      ...npcNames.map((n) => String(n).toLowerCase()),
    ]);
    const pool = [...SURVIVAL_AUTOFILL_POOL.female, ...SURVIVAL_AUTOFILL_POOL.male];
    // Shuffle with seeded RNG
    for (let i = pool.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const tmp = pool[i];
      pool[i] = pool[j];
      pool[j] = tmp;
    }
    let need = desiredCount - baseCount;
    for (const name of pool) {
      if (need <= 0) break;
      const key = String(name).toLowerCase();
      if (used.has(key)) continue;
      used.add(key);
      npcNames.push(String(name));
      need--;
    }
    // Hard fallback if pool exhausted
    let t = 1;
    while (need > 0) {
      const name = `Tribute ${t++}`;
      const key = name.toLowerCase();
      if (!used.has(key)) {
        used.add(key);
        npcNames.push(name);
        need--;
      }
    }
  }
  const seasonPayload = {
    room_id: SURVIVAL_ROOM_DB_ID,
    created_by_user_id: req.session.user.id,
    title: title.slice(0, 120),
    status: "running",
    day_index: 1,
    phase: "day",
    rng_seed: buildSurvivalSeedPayload(seed, options),
    created_at: now,
    updated_at: now,
  };

  let seasonId = null;
  try {
    if (await pgUsersEnabled()) {
      await pgPool.query("BEGIN");
      const { rows } = await pgPool.query(
        `INSERT INTO survival_seasons (room_id, created_by_user_id, title, status, day_index, phase, rng_seed, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING id`,
        [
          seasonPayload.room_id,
          seasonPayload.created_by_user_id,
          seasonPayload.title,
          seasonPayload.status,
          seasonPayload.day_index,
          seasonPayload.phase,
          seasonPayload.rng_seed,
          seasonPayload.created_at,
          seasonPayload.updated_at,
        ]
      );
      seasonId = rows[0]?.id;
      if (!seasonId) throw new Error("missing season id");
      for (const user of userSnapshots) {
        const traits = buildSurvivalTraits(rng, options.chaoticMode);
        const location = pickSurvivalSpawnLocation(rng);
        await pgPool.query(
          `INSERT INTO survival_participants
           (season_id, user_id, display_name, avatar_url, alive, hp, kills, alliance_id, inventory_json, traits_json, location, last_event_at, created_at)
           VALUES ($1,$2,$3,$4,1,100,0,NULL,$5,$6,$7,NULL,$8)`,
          [
            seasonId,
            user.id,
            user.username,
            user.avatar || null,
            JSON.stringify([]),
            JSON.stringify(traits),
            location,
            now,
          ]
        );
      }

      // NPC participants (custom + autofill)
      for (const name of npcNames) {
        const traits = buildSurvivalTraits(rng, options.chaoticMode);
        const location = pickSurvivalSpawnLocation(rng);
        await pgPool.query(
          `INSERT INTO survival_participants
           (season_id, user_id, display_name, avatar_url, alive, hp, kills, alliance_id, inventory_json, traits_json, location, last_event_at, created_at)
           VALUES ($1, NULL, $2, NULL, 1, 100, 0, NULL, $3, $4, $5, NULL, $6)`,
          [
            seasonId,
            String(name).slice(0, 40),
            JSON.stringify([]),
            JSON.stringify(traits),
            location,
            now,
          ]
        );
      }
      await pgPool.query("COMMIT");
    } else {
      await dbRunAsync("BEGIN");
      const result = await dbRunAsync(
        `INSERT INTO survival_seasons
         (room_id, created_by_user_id, title, status, day_index, phase, rng_seed, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          seasonPayload.room_id,
          seasonPayload.created_by_user_id,
          seasonPayload.title,
          seasonPayload.status,
          seasonPayload.day_index,
          seasonPayload.phase,
          seasonPayload.rng_seed,
          seasonPayload.created_at,
          seasonPayload.updated_at,
        ]
      );
      seasonId = result.lastID;
      for (const user of userSnapshots) {
        const traits = buildSurvivalTraits(rng, options.chaoticMode);
        const location = pickSurvivalSpawnLocation(rng);
        await dbRunAsync(
          `INSERT INTO survival_participants
           (season_id, user_id, display_name, avatar_url, alive, hp, kills, alliance_id, inventory_json, traits_json, location, last_event_at, created_at)
           VALUES (?, ?, ?, ?, 1, 100, 0, NULL, ?, ?, ?, NULL, ?)`,
          [
            seasonId,
            user.id,
            user.username,
            user.avatar || null,
            JSON.stringify([]),
            JSON.stringify(traits),
            location,
            now,
          ]
        );
      }

      // NPC participants (custom + autofill). SQLite has no FK on user_id here, so we use 0.
      for (const name of npcNames) {
        const traits = buildSurvivalTraits(rng, options.chaoticMode);
        const location = pickSurvivalSpawnLocation(rng);
        await dbRunAsync(
          `INSERT INTO survival_participants
           (season_id, user_id, display_name, avatar_url, alive, hp, kills, alliance_id, inventory_json, traits_json, location, last_event_at, created_at)
           VALUES (?, 0, ?, NULL, 1, 100, 0, NULL, ?, ?, ?, NULL, ?)`,
          [
            seasonId,
            String(name).slice(0, 40),
            JSON.stringify([]),
            JSON.stringify(traits),
            location,
            now,
          ]
        );
      }
      await dbRunAsync("COMMIT");
    }
  } catch (e) {
    try { await dbRunAsync("ROLLBACK"); } catch {}
    try { if (await pgUsersEnabled()) await pgPool.query("ROLLBACK"); } catch {}
    console.warn("[survival] create season failed", e?.message || e);
    return res.status(500).json({ message: "Failed to start season." });
  }

  survivalSeasonCooldownByRoom.set(SURVIVAL_ROOM_DB_ID, now);

  // Clear lobby signups when a season starts (so the next season starts fresh).
  try {
    const set = getSurvivalLobbySet(SURVIVAL_ROOM_DB_ID);
    if (set.size) {
      set.clear();
      io.to(SURVIVAL_ROOM_ID).emit("survival:lobby", { user_ids: [] });
    }
  } catch {}
  const season = await fetchSurvivalSeasonById(seasonId);
  const payload = await buildSurvivalPayload(season);
  io.to(SURVIVAL_ROOM_ID).emit("survival:update", payload);
  // Mirror the narrative into the room as system messages.
  try {
    emitRoomSystem(SURVIVAL_ROOM_ID, `🏟️ Survival season started: ${payload?.season?.title || title}`, { kind: "survival" });
    emitRoomSystem(SURVIVAL_ROOM_ID, `Day ${payload?.season?.day_index || 1} — ${String(payload?.season?.phase || "day").toUpperCase()}`, { kind: "survival" });
  } catch {}
  return res.json(payload);
});

app.post("/api/survival/seasons/:id/advance", survivalLimiter, requireCoOwner, express.json({ limit: "16kb" }), async (req, res) => {
  const seasonId = Number(req.params.id);
  if (!seasonId) return res.status(400).json({ message: "Invalid season." });
  const now = Date.now();
  const lastAdvance = survivalAdvanceCooldownBySeason.get(seasonId) || 0;
  if (now - lastAdvance < SURVIVAL_ADVANCE_COOLDOWN_MS) {
    return res.status(429).json({ message: "Slow down." });
  }
  survivalAdvanceCooldownBySeason.set(seasonId, now);

  const season = await fetchSurvivalSeasonById(seasonId);
  if (!season) return res.status(404).json({ message: "Season not found." });
  if (season.status !== "running") return res.status(400).json({ message: "Season is not running." });

  const participants = await fetchSurvivalParticipants(seasonId);
  const alliances = await fetchSurvivalAlliances(seasonId);
  participants.forEach((p) => {
    p.location = normalizeSurvivalZoneName(p.location) || SURVIVAL_ZONES[0];
  });
  const alive = participants.filter((p) => p.alive);
  if (alive.length <= 1) {
    season.status = "finished";
  }

  const { seed, options } = parseSurvivalSeedPayload(season.rng_seed);
  const rng = createSeededRng(`${seed || "survival"}:${season.day_index}:${season.phase}:${now}`);
  const couples = options?.includeCouples
    ? await (async () => {
      try {
        if (await pgUsersEnabled()) {
          const ids = alive.map((p) => p.user_id);
          const { rows } = await pgPool.query(
            `SELECT user1_id, user2_id FROM couple_links WHERE user1_id = ANY($1::int[]) OR user2_id = ANY($1::int[])`,
            [ids]
          );
          return (rows || []).map((row) => [Number(row.user1_id), Number(row.user2_id)]);
        }
      } catch (e) {
        console.warn("[survival] couple lookup failed:", e?.message || e);
      }
      const rows = await dbAllAsync(
        `SELECT user1_id, user2_id FROM couple_links`
      );
      return (rows || []).map((row) => [Number(row.user1_id), Number(row.user2_id)]);
    })()
    : [];

  
  // Chaos baseline (extra events after the guaranteed participation pass)
  // NOTE: We enforce EXACTLY one participant-scoped event per alive participant per phase
  // (day + night), so we disable extra participant-scoped "chaos" events here.
  // Arena / zone-wide events still provide chaos without starving or spamming individuals.
  const chaosEventCount = 0;

  const events = [];
  const pendingAlliances = [];
  const appearanceCount = new Map();
  const existingAllianceNames = alliances.map((a) => a.name);
  const templatePool = selectSurvivalTemplate({
    aliveCount: alive.length,
    phase: season.phase,
    dayIndex: season.day_index,
    options,
  });

  let orderIndex = 0;

  // GUARANTEE: Every alive participant appears in EXACTLY ONE participant-scoped event per phase.
  // IMPORTANT: If someone is included in a multi-person event, they do NOT get an additional solo event in the same phase.
  // We track by participant.id (NOT user_id) so NPCs are treated as unique individuals.
  const remainingForGuarantee = new Set(alive.map((p) => p.id));

  let guard = 0;
  while (remainingForGuarantee.size > 0 && guard < 5000) {
    guard += 1;

    // Only pick from participants that haven't yet appeared this phase (and are still alive).
    const eligibleAlive = participants.filter((p) => p.alive && remainingForGuarantee.has(p.id));
    if (eligibleAlive.length < 1) break;

    // Constrain templates so we never request more participants than we have eligible.
    const constrainedPool = templatePool.filter((t) => Number(t?.participants || 1) <= eligibleAlive.length);

    let selectedTemplate = null;
    let selectedParticipants = null;

    for (let attempt = 0; attempt < 30; attempt += 1) {
      const template = pickWeighted(constrainedPool, rng);
      if (!template) break;

      const picked = pickParticipantsForTemplate({
        template,
        alive: eligibleAlive,
        rng,
        appearanceCount,
        couples,
      });

      if (!picked || picked.length < template.participants) continue;

      selectedTemplate = template;
      selectedParticipants = picked;
      break;
    }

    if (!selectedTemplate || !selectedParticipants) {
      // Guaranteed fallback: at least a solo neutral event for one remaining participant.
      const fallback = SURVIVAL_EVENT_TEMPLATES.find((t) => t.id.startsWith("solo_neutral_"));
      selectedTemplate = fallback || SURVIVAL_EVENT_TEMPLATES.find((t) => Number(t?.participants || 1) === 1) || null;
      if (!selectedTemplate) break;
      selectedParticipants = [eligibleAlive[0]];
    }

    selectedParticipants.forEach((p) => {
      const k = p.user_id ? `u:${p.user_id}` : `p:${p.id}`;
      appearanceCount.set(k, (appearanceCount.get(k) || 0) + 1);
      p.last_event_at = now;
      remainingForGuarantee.delete(p.id);
    });

    const text = renderSurvivalEventText(selectedTemplate, selectedParticipants, rng);
    const outcome = applySurvivalOutcome({
      template: selectedTemplate,
      participants: selectedParticipants,
      rng,
      pendingAlliances,
      existingAllianceNames,
    });

    // Attach a best-guess zone for this event so the arena map can filter/animate.
    try {
      const zones = (selectedParticipants || [])
        .map((p) => normalizeSurvivalZoneName(p.location))
        .filter(Boolean);
      const zone = zones.length
        ? zones
            .sort(
              (a, b) =>
                zones.filter((z) => z === a).length - zones.filter((z) => z === b).length
            )
            .pop()
        : null;
      if (zone) outcome.zone = normalizeSurvivalZoneName(zone) || zone;
    } catch {}

    orderIndex += 1;
    events.push({
      id: null,
      season_id: seasonId,
      day_index: season.day_index,
      phase: season.phase,
      order_index: orderIndex,
      text,
      // Only store real user IDs (NPCs have user_id NULL/0 and should not collide in logs).
      involved_user_ids: selectedParticipants.map((p) => p.user_id).filter((id) => Number(id) > 0),
      outcome,
      created_at: now,
    });
  }

  // NOTE: participant-scoped chaos events intentionally disabled (see chaosEventCount above).



  // Occasional zone-wide / arena-wide events (adds variety + makes the map feel alive).
  try {
    const arenaEv = maybeGenerateArenaEvent({ season, participants, rng, now });
    if (arenaEv && arenaEv.text) {
      orderIndex += 1;
      events.push({
        id: null,
        season_id: seasonId,
        day_index: season.day_index,
        phase: season.phase,
        order_index: orderIndex,
        text: arenaEv.text,
        involved_user_ids: Array.isArray(arenaEv.outcome?.affected_user_ids)
          ? arenaEv.outcome.affected_user_ids.filter((id) => Number(id) > 0)
          : [],
        outcome: arenaEv.outcome || { type: "arena", scope: "global" },
        created_at: now,
      });
    }
  } catch (e) {
    console.warn("[survival] arena event failed:", e?.message || e);
  }

  const aliveAfter = participants.filter((p) => p.alive);
  if (aliveAfter.length <= 1 && season.status !== "finished") {
    season.status = "finished";
    const winner = aliveAfter[0];
    if (winner) {
      const winnerName = sanitizeDisplayName(winner.display_name);
      const winnerTag = winner.user_id ? `@${winnerName}` : winnerName;
      events.push({
        id: null,
        season_id: seasonId,
        day_index: season.day_index,
        phase: season.phase,
        order_index: orderIndex + 1,
        text: `🏆 ${winnerTag} wins the season!`,
        involved_user_ids: winner.user_id ? [winner.user_id] : [],
        outcome: { type: "winner" },
        created_at: now,
      });
    } else {
      events.push({
        id: null,
        season_id: seasonId,
        day_index: season.day_index,
        phase: season.phase,
        order_index: orderIndex + 1,
        text: "No one survived the season. Wild.",
        involved_user_ids: [],
        outcome: { type: "draw" },
        created_at: now,
      });
    }
  }

  if (season.status !== "finished") {
    if (season.phase === "day") {
      season.phase = "night";
    } else {
      season.phase = "day";
      season.day_index = Number(season.day_index || 1) + 1;
    }
  }
  season.updated_at = now;

  const pendingMap = new Map();
  try {
    if (await pgUsersEnabled()) {
      await pgPool.query("BEGIN");
      for (const pending of pendingAlliances) {
        const { rows } = await pgPool.query(
          `INSERT INTO survival_alliances (season_id, name, created_at) VALUES ($1,$2,$3) RETURNING id`,
          [seasonId, pending.name, now]
        );
        const actualId = rows[0]?.id;
        pendingMap.set(pending.tempId, actualId);
      }

      for (const participant of participants) {
        const allianceId = pendingMap.get(participant.alliance_id) || participant.alliance_id;
        participant.alliance_id = allianceId && allianceId < 0 ? null : allianceId;
        await pgPool.query(
          `UPDATE survival_participants
           SET alive=$1, hp=$2, kills=$3, alliance_id=$4, inventory_json=$5, traits_json=$6, location=$7, last_event_at=$8
           WHERE id=$9`,
          [
            participant.alive ? 1 : 0,
            participant.hp,
            participant.kills,
            participant.alliance_id,
            JSON.stringify(participant.inventory || []),
            JSON.stringify(participant.traits || {}),
            participant.location || null,
            participant.last_event_at,
            participant.id,
          ]
        );
      }

      for (const event of events) {
        if (event.outcome?.alliance?.id && pendingMap.has(event.outcome.alliance.id)) {
          event.outcome.alliance.id = pendingMap.get(event.outcome.alliance.id);
        }
        const { rows } = await pgPool.query(
          `INSERT INTO survival_events
           (season_id, day_index, phase, order_index, text, involved_user_ids_json, outcome_json, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id`,
          [
            seasonId,
            event.day_index,
            event.phase,
            event.order_index,
            event.text,
            JSON.stringify(event.involved_user_ids || []),
            JSON.stringify(event.outcome || {}),
            event.created_at,
          ]
        );
        event.id = rows[0]?.id;
      }

      await pgPool.query(
        `UPDATE survival_seasons SET status=$1, day_index=$2, phase=$3, updated_at=$4 WHERE id=$5`,
        [season.status, season.day_index, season.phase, season.updated_at, seasonId]
      );
      await pgPool.query("COMMIT");
    } else {
      await dbRunAsync("BEGIN");
      for (const pending of pendingAlliances) {
        const result = await dbRunAsync(
          `INSERT INTO survival_alliances (season_id, name, created_at) VALUES (?, ?, ?)`,
          [seasonId, pending.name, now]
        );
        pendingMap.set(pending.tempId, result.lastID);
      }

      for (const participant of participants) {
        const allianceId = pendingMap.get(participant.alliance_id) || participant.alliance_id;
        participant.alliance_id = allianceId && allianceId < 0 ? null : allianceId;
        await dbRunAsync(
          `UPDATE survival_participants
           SET alive=?, hp=?, kills=?, alliance_id=?, inventory_json=?, traits_json=?, location=?, last_event_at=?
           WHERE id=?`,
          [
            participant.alive ? 1 : 0,
            participant.hp,
            participant.kills,
            participant.alliance_id,
            JSON.stringify(participant.inventory || []),
            JSON.stringify(participant.traits || {}),
            participant.location || null,
            participant.last_event_at,
            participant.id,
          ]
        );
      }

      for (const event of events) {
        if (event.outcome?.alliance?.id && pendingMap.has(event.outcome.alliance.id)) {
          event.outcome.alliance.id = pendingMap.get(event.outcome.alliance.id);
        }
        const result = await dbRunAsync(
          `INSERT INTO survival_events
           (season_id, day_index, phase, order_index, text, involved_user_ids_json, outcome_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            seasonId,
            event.day_index,
            event.phase,
            event.order_index,
            event.text,
            JSON.stringify(event.involved_user_ids || []),
            JSON.stringify(event.outcome || {}),
            event.created_at,
          ]
        );
        event.id = result.lastID;
      }

      await dbRunAsync(
        `UPDATE survival_seasons SET status=?, day_index=?, phase=?, updated_at=? WHERE id=?`,
        [season.status, season.day_index, season.phase, season.updated_at, seasonId]
      );
      await dbRunAsync("COMMIT");
    }
  } catch (e) {
    try { await dbRunAsync("ROLLBACK"); } catch {}
    try { if (await pgUsersEnabled()) await pgPool.query("ROLLBACK"); } catch {}
    console.warn("[survival] advance failed", e?.message || e);
    return res.status(500).json({ message: "Failed to advance." });
  }

  const payload = await buildSurvivalPayload(await fetchSurvivalSeasonById(seasonId));
  io.to(SURVIVAL_ROOM_ID).emit("survival:update", payload);
  io.to(SURVIVAL_ROOM_ID).emit("survival:events", { seasonId, events });

  // Mirror every simulator event into room system messages so spectators see the full story.
  try {
    for (const ev of events || []) {
      if (!ev || !ev.text) continue;
      emitRoomSystem(SURVIVAL_ROOM_ID, `⚔️ ${ev.text}`, { kind: "survival" });
    }
  } catch {}

  return res.json(payload);
});

app.post("/api/survival/seasons/:id/end", survivalLimiter, requireCoOwner, express.json({ limit: "8kb" }), async (req, res) => {
  const seasonId = Number(req.params.id);
  if (!seasonId) return res.status(400).json({ message: "Invalid season." });
  const season = await fetchSurvivalSeasonById(seasonId);
  if (!season) return res.status(404).json({ message: "Season not found." });
  if (season.status === "finished") {
    const payload = await buildSurvivalPayload(season);
    return res.json(payload);
  }
  const now = Date.now();
  try {
    if (await pgUsersEnabled()) {
      await pgPool.query(`UPDATE survival_seasons SET status='finished', updated_at=$1 WHERE id=$2`, [now, seasonId]);
    } else {
      await dbRunAsync(`UPDATE survival_seasons SET status='finished', updated_at=? WHERE id=?`, [now, seasonId]);
    }
  } catch (e) {
    console.warn("[survival] end failed", e?.message || e);
    return res.status(500).json({ message: "Failed to end season." });
  }
  const payload = await buildSurvivalPayload(await fetchSurvivalSeasonById(seasonId));
  io.to(SURVIVAL_ROOM_ID).emit("survival:update", payload);
  return res.json(payload);
});

// ---- Room structure management (Owner-only)
app.post("/api/room-masters", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const name = sanitizeRoomGroupName(req.body?.name || "");
  if (!name) return res.status(400).send("Invalid name");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    let sortOrder = 0;
    let insertedId = null;
    const now = Date.now();
    if (await pgUsersEnabled()) {
      const { rows: exists } = await pgPool.query(
        `SELECT id FROM room_master_categories WHERE lower(name) = lower($1)`,
        [name]
      );
      if (exists?.[0]) return res.status(409).send("Master exists");
      const { rows: maxRows } = await pgPool.query(`SELECT COALESCE(MAX(sort_order), 0) as maxsort FROM room_master_categories`);
      sortOrder = Number(maxRows?.[0]?.maxsort || 0) + 1;
      const { rows } = await pgPool.query(
        `INSERT INTO room_master_categories (name, sort_order, created_at) VALUES ($1, $2, $3) RETURNING id`,
        [name, sortOrder, now]
      );
      insertedId = rows?.[0]?.id ?? null;
    } else {
      const existing = await dbGetAsync(`SELECT id FROM room_master_categories WHERE lower(name) = lower(?)`, [name]);
      if (existing) return res.status(409).send("Master exists");
      const maxRow = await dbGetAsync(`SELECT COALESCE(MAX(sort_order), 0) as maxSort FROM room_master_categories`);
      sortOrder = Number(maxRow?.maxSort || 0) + 1;
      const ins = await dbRunAsync(
        `INSERT INTO room_master_categories (name, sort_order, created_at) VALUES (?, ?, ?)`,
        [name, sortOrder, now]
      );
      insertedId = ins?.lastID || null;
    }
    await applyRoomStructureChange({
      action: "room_master.create",
      actorUserId: req.session?.user?.id,
      auditPayload: { id: insertedId, name, sort_order: sortOrder },
    });
    return res.json({ ok: true, id: insertedId, name, sort_order: sortOrder });
  } catch (e) {
    console.warn("[room-masters] create failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/room-masters/reorder", strictLimiter, requireAdminPlus, express.json({ limit: "32kb" }), async (req, res) => {
  const orderedIds = Array.isArray(req.body?.orderedIds) ? req.body.orderedIds : null;
  if (!orderedIds?.length) return res.status(400).send("Missing order");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    if (await pgUsersEnabled()) {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const id = Number(orderedIds[i]);
        if (!id) continue;
        await pgPool.query(`UPDATE room_master_categories SET sort_order = $1 WHERE id = $2`, [i, id]);
      }
    } else {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const id = Number(orderedIds[i]);
        if (!id) continue;
        await dbRunAsync(`UPDATE room_master_categories SET sort_order = ? WHERE id = ?`, [i, id]);
      }
    }
    await applyRoomStructureChange({
      action: "room_master.reorder",
      actorUserId: req.session?.user?.id,
      auditPayload: { orderedIds },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-masters] reorder failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/room-masters/:id", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).send("Invalid master");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT id, name FROM room_master_categories WHERE id = $1`, [id]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT id, name FROM room_master_categories WHERE id = ?`, [id]);
    if (!row) return res.status(404).send("Not found");
    const updates = [];
    const params = [];
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "name")) {
      const name = sanitizeRoomGroupName(req.body?.name || "");
      if (!name) return res.status(400).send("Invalid name");
      if (DEFAULT_ROOM_MASTERS.includes(row.name) && name !== row.name) {
        return res.status(400).send("Cannot rename default master");
      }
      const existing = await (await pgUsersEnabled())
        ? (async () => {
          const { rows } = await pgPool.query(
            `SELECT id FROM room_master_categories WHERE lower(name) = lower($1) AND id != $2`,
            [name, id]
          );
          return rows?.[0] || null;
        })()
        : await dbGetAsync(
          `SELECT id FROM room_master_categories WHERE lower(name) = lower(?) AND id != ?`,
          [name, id]
        );
      if (existing) return res.status(409).send("Name exists");
      updates.push("name = ?");
      params.push(name);
    }
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "sort_order")) {
      const sortOrder = Number(req.body?.sort_order);
      if (Number.isFinite(sortOrder)) {
        updates.push("sort_order = ?");
        params.push(sortOrder);
      }
    }
    if (!updates.length) return res.json({ ok: true });
    if (await pgUsersEnabled()) {
      const pgUpdates = updates.map((item, idx) => item.replace("?", `$${idx + 1}`));
      const pgParams = [...params, id];
      await pgPool.query(`UPDATE room_master_categories SET ${pgUpdates.join(", ")} WHERE id = $${pgParams.length}`, pgParams);
    } else {
      params.push(id);
      await dbRunAsync(`UPDATE room_master_categories SET ${updates.join(", ")} WHERE id = ?`, params);
    }
    await applyRoomStructureChange({
      action: "room_master.update",
      actorUserId: req.session?.user?.id,
      auditPayload: { id, updates: req.body || {} },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-masters] patch failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.delete("/api/room-masters/:id", strictLimiter, requireOwner, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).send("Invalid master");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT id, name FROM room_master_categories WHERE id = $1`, [id]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT id, name FROM room_master_categories WHERE id = ?`, [id]);
    if (!row) return res.status(404).send("Not found");
    if (DEFAULT_ROOM_MASTERS.includes(row.name)) {
      return res.status(400).send("Cannot delete default master");
    }
    const defaults = await getDefaultMasterIds();
    const fallbackCategoryId = await getUncategorizedCategoryId(defaults.site);
    if (await pgUsersEnabled()) {
      const { rows: categories } = await pgPool.query(`SELECT id FROM room_categories WHERE master_id = $1`, [id]);
      const categoryIds = (categories || []).map((c) => c.id).filter(Boolean);
      if (categoryIds.length && fallbackCategoryId) {
        await pgPool.query(
          `UPDATE rooms SET category_id = $1 WHERE category_id = ANY($2::int[])`,
          [fallbackCategoryId, categoryIds]
        );
      }
      await pgPool.query(`DELETE FROM room_categories WHERE master_id = $1`, [id]);
      await pgPool.query(`DELETE FROM room_master_categories WHERE id = $1`, [id]);
    } else {
      const categories = await dbAllAsync(`SELECT id FROM room_categories WHERE master_id = ?`, [id]);
      const categoryIds = categories.map((c) => c.id).filter(Boolean);
      if (categoryIds.length && fallbackCategoryId) {
        const placeholders = categoryIds.map(() => "?").join(",");
        await dbRunAsync(
          `UPDATE rooms SET category_id = ? WHERE category_id IN (${placeholders})`,
          [fallbackCategoryId, ...categoryIds]
        );
      }
      await dbRunAsync(`DELETE FROM room_categories WHERE master_id = ?`, [id]);
      await dbRunAsync(`DELETE FROM room_master_categories WHERE id = ?`, [id]);
    }
    await applyRoomStructureChange({
      action: "room_master.delete",
      actorUserId: req.session?.user?.id,
      auditPayload: { id, name: row.name },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-masters] delete failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.post("/api/room-categories", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const masterId = Number(req.body?.master_id);
  const name = sanitizeRoomGroupName(req.body?.name || "");
  if (!masterId) return res.status(400).send("Invalid master");
  if (!name) return res.status(400).send("Invalid name");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    let sortOrder = 0;
    let insertedId = null;
    const now = Date.now();
    if (await pgUsersEnabled()) {
      const { rows: masterRows } = await pgPool.query(
        `SELECT id FROM room_master_categories WHERE id = $1`,
        [masterId]
      );
      if (!masterRows?.[0]) return res.status(404).send("Master not found");
      const { rows: existingRows } = await pgPool.query(
        `SELECT id FROM room_categories WHERE master_id = $1 AND lower(name) = lower($2)`,
        [masterId, name]
      );
      if (existingRows?.[0]) return res.status(409).send("Category exists");
      const { rows: maxRows } = await pgPool.query(
        `SELECT COALESCE(MAX(sort_order), 0) as maxsort FROM room_categories WHERE master_id = $1`,
        [masterId]
      );
      sortOrder = Number(maxRows?.[0]?.maxsort || 0) + 1;
      const { rows } = await pgPool.query(
        `INSERT INTO room_categories (master_id, name, sort_order, created_at) VALUES ($1, $2, $3, $4) RETURNING id`,
        [masterId, name, sortOrder, now]
      );
      insertedId = rows?.[0]?.id ?? null;
    } else {
      const master = await dbGetAsync(`SELECT id FROM room_master_categories WHERE id = ?`, [masterId]);
      if (!master) return res.status(404).send("Master not found");
      const existing = await dbGetAsync(
        `SELECT id FROM room_categories WHERE master_id = ? AND lower(name) = lower(?)`,
        [masterId, name]
      );
      if (existing) return res.status(409).send("Category exists");
      const maxRow = await dbGetAsync(
        `SELECT COALESCE(MAX(sort_order), 0) as maxSort FROM room_categories WHERE master_id = ?`,
        [masterId]
      );
      sortOrder = Number(maxRow?.maxSort || 0) + 1;
      const ins = await dbRunAsync(
        `INSERT INTO room_categories (master_id, name, sort_order, created_at) VALUES (?, ?, ?, ?)`,
        [masterId, name, sortOrder, now]
      );
      insertedId = ins?.lastID || null;
    }
    await applyRoomStructureChange({
      action: "room_category.create",
      actorUserId: req.session?.user?.id,
      auditPayload: { id: insertedId, master_id: masterId, name, sort_order: sortOrder },
    });
    return res.json({ ok: true, id: insertedId, master_id: masterId, name });
  } catch (e) {
    console.warn("[room-categories] create failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/room-categories/reorder", strictLimiter, requireAdminPlus, express.json({ limit: "32kb" }), async (req, res) => {
  const masterId = Number(req.body?.master_id);
  const orderedIds = Array.isArray(req.body?.orderedIds) ? req.body.orderedIds : null;
  if (!masterId || !orderedIds?.length) return res.status(400).send("Invalid order");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    if (await pgUsersEnabled()) {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const id = Number(orderedIds[i]);
        if (!id) continue;
        await pgPool.query(
          `UPDATE room_categories SET sort_order = $1 WHERE id = $2 AND master_id = $3`,
          [i, id, masterId]
        );
      }
    } else {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const id = Number(orderedIds[i]);
        if (!id) continue;
        await dbRunAsync(
          `UPDATE room_categories SET sort_order = ? WHERE id = ? AND master_id = ?`,
          [i, id, masterId]
        );
      }
    }
    await applyRoomStructureChange({
      action: "room_category.reorder",
      actorUserId: req.session?.user?.id,
      auditPayload: { master_id: masterId, orderedIds },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-categories] reorder failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/room-categories/:id", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).send("Invalid category");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT id, name, master_id FROM room_categories WHERE id = $1`, [id]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT id, name, master_id FROM room_categories WHERE id = ?`, [id]);
    if (!row) return res.status(404).send("Not found");
    const updates = [];
    const params = [];

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "name")) {
      const name = sanitizeRoomGroupName(req.body?.name || "");
      if (!name) return res.status(400).send("Invalid name");
      if (normalizeRoomGroupName(row.name) === normalizeRoomGroupName(DEFAULT_ROOM_CATEGORY) && name !== row.name) {
        return res.status(400).send("Cannot rename Uncategorized");
      }
      const targetMaster = Number(req.body?.master_id) || row.master_id;
      const existing = await (await pgUsersEnabled())
        ? (async () => {
          const { rows } = await pgPool.query(
            `SELECT id FROM room_categories WHERE master_id = $1 AND lower(name) = lower($2) AND id != $3`,
            [targetMaster, name, id]
          );
          return rows?.[0] || null;
        })()
        : await dbGetAsync(
          `SELECT id FROM room_categories WHERE master_id = ? AND lower(name) = lower(?) AND id != ?`,
          [targetMaster, name, id]
        );
      if (existing) return res.status(409).send("Name exists");
      updates.push("name = ?");
      params.push(name);
    }

    let nextMasterId = row.master_id;
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "master_id")) {
      const masterId = Number(req.body?.master_id);
      if (!masterId) return res.status(400).send("Invalid master");
      if (normalizeRoomGroupName(row.name) === normalizeRoomGroupName(DEFAULT_ROOM_CATEGORY) && masterId !== row.master_id) {
        return res.status(400).send("Cannot move Uncategorized");
      }
      const masterRow = await (await pgUsersEnabled())
        ? (async () => {
          const { rows } = await pgPool.query(`SELECT id FROM room_master_categories WHERE id = $1`, [masterId]);
          return rows?.[0] || null;
        })()
        : await dbGetAsync(`SELECT id FROM room_master_categories WHERE id = ?`, [masterId]);
      if (!masterRow) return res.status(404).send("Master not found");
      nextMasterId = masterId;
      updates.push("master_id = ?");
      params.push(masterId);
    }

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "sort_order")) {
      const sortOrder = Number(req.body?.sort_order);
      if (Number.isFinite(sortOrder)) {
        updates.push("sort_order = ?");
        params.push(sortOrder);
      }
    }

    if (!updates.length) return res.json({ ok: true });

    if (nextMasterId !== row.master_id && !Object.prototype.hasOwnProperty.call(req.body || {}, "sort_order")) {
      const maxRow = await (await pgUsersEnabled())
        ? (async () => {
          const { rows } = await pgPool.query(
            `SELECT COALESCE(MAX(sort_order), 0) as maxsort FROM room_categories WHERE master_id = $1`,
            [nextMasterId]
          );
          return rows?.[0] || null;
        })()
        : await dbGetAsync(
          `SELECT COALESCE(MAX(sort_order), 0) as maxSort FROM room_categories WHERE master_id = ?`,
          [nextMasterId]
        );
      const sortOrder = Number(maxRow?.maxsort || maxRow?.maxSort || 0) + 1;
      updates.push("sort_order = ?");
      params.push(sortOrder);
    }

    if (await pgUsersEnabled()) {
      const pgUpdates = updates.map((item, idx) => item.replace("?", `$${idx + 1}`));
      const pgParams = [...params, id];
      await pgPool.query(`UPDATE room_categories SET ${pgUpdates.join(", ")} WHERE id = $${pgParams.length}`, pgParams);
    } else {
      params.push(id);
      await dbRunAsync(`UPDATE room_categories SET ${updates.join(", ")} WHERE id = ?`, params);
    }
    await applyRoomStructureChange({
      action: "room_category.update",
      actorUserId: req.session?.user?.id,
      auditPayload: { id, updates: req.body || {} },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-categories] patch failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.delete("/api/room-categories/:id", strictLimiter, requireAdminPlus, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).send("Invalid category");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT id, name, master_id FROM room_categories WHERE id = $1`, [id]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT id, name, master_id FROM room_categories WHERE id = ?`, [id]);
    if (!row) return res.status(404).send("Not found");
    if (normalizeRoomGroupName(row.name) === normalizeRoomGroupName(DEFAULT_ROOM_CATEGORY)) {
      return res.status(400).send("Cannot delete Uncategorized");
    }
    const rooms = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE category_id = $1`, [id]);
        return rows || [];
      })()
      : await dbAllAsync(`SELECT name FROM rooms WHERE category_id = ?`, [id]);
    if (rooms?.length) return res.status(409).send("Category must be empty to delete");
    if (await pgUsersEnabled()) {
      await pgPool.query(`DELETE FROM room_categories WHERE id = $1`, [id]);
    } else {
      await dbRunAsync(`DELETE FROM room_categories WHERE id = ?`, [id]);
    }
    await applyRoomStructureChange({
      action: "room_category.delete",
      actorUserId: req.session?.user?.id,
      auditPayload: { id, name: row.name },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[room-categories] delete failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/rooms/:id/move", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const roomRow = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [roomName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [roomName]);
    if (!roomRow) return res.status(404).send("Not found");
    const requestedCategoryId = Number(req.body?.category_id) || null;
    const resolved = await resolveRoomCategoryId({ categoryId: requestedCategoryId, isUserRoom: false });
    const categoryId = resolved?.categoryId ?? null;
    let categoryRow = null;
    if (categoryId) {
      if (await pgUsersEnabled()) {
        const { rows } = await pgPool.query(
          `SELECT c.id, m.name as master_name
             FROM room_categories c
             JOIN room_master_categories m ON m.id = c.master_id
            WHERE c.id = $1 LIMIT 1`,
          [categoryId]
        );
        categoryRow = rows?.[0] || null;
      } else {
        categoryRow = await dbGetAsync(
          `SELECT c.id, m.name as master_name
             FROM room_categories c
             JOIN room_master_categories m ON m.id = c.master_id
            WHERE c.id = ? LIMIT 1`,
          [categoryId]
        );
      }
    }
    const isUserRoom = categoryRow?.master_name === "User Rooms" ? 1 : 0;
    let sortOrder = Number(req.body?.room_sort_order);
    if (!Number.isFinite(sortOrder)) {
      let maxRow = { maxSort: 0, maxsort: 0 };
      if (categoryId) {
        if (await pgUsersEnabled()) {
          const { rows } = await pgPool.query(
            `SELECT COALESCE(MAX(room_sort_order), 0) as maxsort FROM rooms WHERE category_id = $1`,
            [categoryId]
          );
          maxRow = rows?.[0] || maxRow;
        } else {
          maxRow = await dbGetAsync(
            `SELECT COALESCE(MAX(room_sort_order), 0) as maxSort FROM rooms WHERE category_id = ?`,
            [categoryId]
          );
        }
      }
      sortOrder = Number(maxRow?.maxsort || maxRow?.maxSort || 0) + 1;
    }
    if (await pgUsersEnabled()) {
      await pgPool.query(
        `UPDATE rooms SET category_id = $1, room_sort_order = $2, is_user_room = $3 WHERE name = $4`,
        [categoryId, sortOrder, isUserRoom, roomName]
      );
    } else {
      await dbRunAsync(
        `UPDATE rooms SET category_id = ?, room_sort_order = ?, is_user_room = ? WHERE name = ?`,
        [categoryId, sortOrder, isUserRoom, roomName]
      );
    }
    await applyRoomStructureChange({
      action: "room.move",
      actorUserId: req.session?.user?.id,
      auditPayload: { name: roomName, category_id: categoryId, room_sort_order: sortOrder },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms] move failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/rooms/:id/settings", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  const slowmode = Number(req.body?.slowmode_seconds ?? req.body?.slowmode ?? 0);
  const isLocked = Number(req.body?.is_locked ?? 0) ? 1 : 0;
  const maintenance = Number(req.body?.maintenance_mode ?? 0) ? 1 : 0;
  const vipOnly = Number(req.body?.vip_only ?? 0) ? 1 : 0;
  const staffOnly = Number(req.body?.staff_only ?? 0) ? 1 : 0;
  const minLevel = Math.max(0, Math.min(999, Number(req.body?.min_level ?? 0) || 0));
  const eventsEnabled = Number(req.body?.events_enabled ?? 1) ? 1 : 0;

  if (!Number.isFinite(slowmode) || slowmode < 0 || slowmode > 3600) {
    return res.status(400).send("Invalid slowmode");
  }
  try {
    const roomRow = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [roomName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [roomName]);
    if (!roomRow) return res.status(404).send("Not found");
    if (await pgUsersEnabled()) {
      await pgPool.query(
        `UPDATE rooms
            SET slowmode_seconds = $1,
                is_locked = $2,
                maintenance_mode = $3,
                vip_only = $4,
                staff_only = $5,
                min_level = $6,
                events_enabled = $7
          WHERE name = $8`,
        [slowmode, isLocked, maintenance, vipOnly, staffOnly, minLevel, eventsEnabled, roomName]
      );
    } else {
      await dbRunAsync(
        `UPDATE rooms
            SET slowmode_seconds = ?,
                is_locked = ?,
                maintenance_mode = ?,
                vip_only = ?,
                staff_only = ?,
                min_level = ?,
                events_enabled = ?
          WHERE name = ?`,
        [slowmode, isLocked, maintenance, vipOnly, staffOnly, minLevel, eventsEnabled, roomName]
      );
    }
    await emitRoomStructureUpdate();
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms][settings]", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/rooms/:id/archive", strictLimiter, requireAdminPlus, async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  const actor = req.session?.user;
  if (isCoreRoomName(roomName) && !requireMinRole(actor?.role, "Owner")) {
    return res.status(403).send("Core rooms can only be archived by the Owner");
  }
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [roomName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [roomName]);
    if (!row) return res.status(404).send("Not found");
    if (await pgUsersEnabled()) {
      await pgPool.query(`UPDATE rooms SET archived = 1 WHERE name = $1`, [roomName]);
    } else {
      await dbRunAsync(`UPDATE rooms SET archived = 1 WHERE name = ?`, [roomName]);
    }
    await applyRoomStructureChange({
      action: "room.archive",
      actorUserId: req.session?.user?.id,
      auditPayload: { name: roomName },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms] archive failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/rooms/:id/restore", strictLimiter, requireAdminPlus, async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const row = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [roomName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [roomName]);
    if (!row) return res.status(404).send("Not found");
    if (await pgUsersEnabled()) {
      await pgPool.query(`UPDATE rooms SET archived = 0 WHERE name = $1`, [roomName]);
    } else {
      await dbRunAsync(`UPDATE rooms SET archived = 0 WHERE name = ?`, [roomName]);
    }
    await applyRoomStructureChange({
      action: "room.restore",
      actorUserId: req.session?.user?.id,
      auditPayload: { name: roomName },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms] restore failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.get("/api/rooms/:id/events", strictLimiter, requireAdminPlus, async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  return res.json({ ok: true, events: getActiveEventsForRoom(roomName) });
});

app.post("/api/rooms/:id/events", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const roomName = sanitizeRoomName(req.params.id || "");
  if (!roomName) return res.status(400).send("Invalid room");
  const type = String(req.body?.type || "").trim();
  const allowedTypes = new Set(["announcement", "prompt", "flair"]);
  if (!allowedTypes.has(type)) return res.status(400).send("Invalid event type");
  const roomRow = await dbGetAsync(`SELECT events_enabled, archived FROM rooms WHERE name = ?`, [roomName]);
  if (!roomRow) return res.status(404).send("Not found");
  if (Number(roomRow.archived || 0) === 1) return res.status(400).send("Room is archived");
  if (Number(roomRow.events_enabled ?? 1) === 0) return res.status(400).send("Events are disabled for this room");
  const durationSec = Math.max(0, Math.min(24 * 60 * 60, Number(req.body?.duration_seconds ?? 0) || 0));
  const payload = req.body?.payload && typeof req.body.payload === "object" ? req.body.payload : {};
  const id = ROOM_EVENT_SEQ++;
  const startedAt = Date.now();
  const endsAt = durationSec ? startedAt + durationSec * 1000 : null;
  const rawText = String(payload?.text || "").trim();
  if (type === "announcement" && !rawText) return res.status(400).send("Text required");
  const resolvedText = type === "prompt" ? (rawText || selectPromptText()) : rawText;
  const title = resolvedText ? resolvedText.slice(0, 80) : type === "flair" ? "Visual Flair" : "Room Event";
  const ev = { id, type, title, payload: { ...payload, text: resolvedText }, startedAt, endsAt, createdBy: req.session?.user?.username || null };
  await addRoomEvent(roomName, ev);
  io.to(roomName).emit("room:event", { room: roomName, active: ev, at: Date.now() });

  if (type === "announcement" || type === "prompt") {
    const text = resolvedText ? String(resolvedText).slice(0, 500) : "💬 Prompt event started.";
    emitRoomSystem(roomName, text);
  }

  return res.json({ ok: true, event: ev });
});

app.post("/api/room-events/:id/stop", strictLimiter, requireAdminPlus, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) return res.status(400).send("Invalid event");
  const stopped = await stopRoomEventById(id);
  if (!stopped) return res.status(404).send("Not found");
  emitRoomSystem(stopped.room, "⛔ Room event ended.");
  io.to(stopped.room).emit("room:event", { room: stopped.room, active: null, at: Date.now() });
  return res.json({ ok: true });
});


app.patch("/api/rooms/:id", strictLimiter, requireAdminPlus, express.json({ limit: "16kb" }), async (req, res) => {
  const oldName = sanitizeRoomName(req.params.id || "");
  const nextName = sanitizeRoomName(req.body?.name || "");
  if (!oldName || !nextName) return res.status(400).send("Invalid room");
  if (oldName === nextName) return res.json({ ok: true, name: nextName });
  const actor = req.session?.user;
  if (isCoreRoomName(oldName) && !requireMinRole(actor?.role, "Owner")) {
    return res.status(403).send("Core rooms can only be renamed by the Owner");
  }
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    const roomRow = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [oldName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [oldName]);
    if (!roomRow) return res.status(404).send("Not found");
    const exists = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(`SELECT name FROM rooms WHERE name = $1`, [nextName]);
        return rows?.[0] || null;
      })()
      : await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [nextName]);
    if (exists) return res.status(409).send("Room already exists");

    // Update rooms primary key name + all references that store room name
    if (await pgUsersEnabled()) {
      await pgPool.query(`UPDATE rooms SET name = $1 WHERE name = $2`, [nextName, oldName]);
    } else {
      await dbRunAsync(`UPDATE rooms SET name = ? WHERE name = ?`, [nextName, oldName]);
    }

    // Best-effort updates for related tables (some installs may not have all tables)
    const safeUpdate = async (sql, params) => {
      try { await dbRunAsync(sql, params); } catch (_) {}
    };
    await safeUpdate(`UPDATE messages SET room = ? WHERE room = ?`, [nextName, oldName]);
    await safeUpdate(`UPDATE mod_logs SET room = ? WHERE room = ?`, [nextName, oldName]);
    await safeUpdate(`UPDATE command_audit SET room = ? WHERE room = ?`, [nextName, oldName]);

    if (await pgUsersEnabled()) {
      const safeUpdatePg = async (sql, params) => {
        try { await pgPool.query(sql, params); } catch (_) {}
      };
      await safeUpdatePg(`UPDATE messages SET room = $1 WHERE room = $2`, [nextName, oldName]);
      await safeUpdatePg(`UPDATE mod_logs SET room = $1 WHERE room = $2`, [nextName, oldName]);
      await safeUpdatePg(`UPDATE command_audit SET room = $1 WHERE room = $2`, [nextName, oldName]);
    }

    // Move live sockets currently in the old room to the new room to prevent "ghost" rooms.
    try {
      const sockets = await io.in(oldName).fetchSockets();
      for (const sock of sockets) {
        try { sock.leave(oldName); } catch (_) {}
        try { sock.join(nextName); } catch (_) {}
        if (sock.currentRoom === oldName) sock.currentRoom = nextName;
        if (sock.data?.currentRoom === oldName) sock.data.currentRoom = nextName;
      }
    } catch (_) {}

    await applyRoomStructureChange({
      action: "room.rename",
      actorUserId: actor?.id,
      auditPayload: { from: oldName, to: nextName },
    });
    return res.json({ ok: true, name: nextName });
  } catch (e) {
    console.warn("[rooms] rename failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.patch("/api/rooms/reorder", strictLimiter, requireAdminPlus, express.json({ limit: "32kb" }), async (req, res) => {
  const categoryId = Number(req.body?.category_id);
  const orderedIds = Array.isArray(req.body?.orderedIds) ? req.body.orderedIds : null;
  if (!categoryId || !orderedIds?.length) return res.status(400).send("Invalid order");
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    if (await pgUsersEnabled()) {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const roomName = sanitizeRoomName(orderedIds[i] || "");
        if (!roomName) continue;
        await pgPool.query(
          `UPDATE rooms SET room_sort_order = $1 WHERE name = $2 AND category_id = $3`,
          [i, roomName, categoryId]
        );
      }
    } else {
      for (let i = 0; i < orderedIds.length; i += 1) {
        const roomName = sanitizeRoomName(orderedIds[i] || "");
        if (!roomName) continue;
        await dbRunAsync(
          `UPDATE rooms SET room_sort_order = ? WHERE name = ? AND category_id = ?`,
          [i, roomName, categoryId]
        );
      }
    }
    await applyRoomStructureChange({
      action: "room.reorder",
      actorUserId: req.session?.user?.id,
      auditPayload: { category_id: categoryId, orderedIds },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms] reorder failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

app.post("/api/rooms/reset_defaults", strictLimiter, requireAdminPlus, async (req, res) => {
  try {
    const versionCheck = await ensureRoomStructureVersionMatch(extractExpectedRoomVersion(req));
    if (!versionCheck.ok) return res.status(409).json({ ok: false, version: versionCheck.version });
    await ensureCoreRoomsExist();
    await applyRoomStructureChange({
      action: "room.reset_defaults",
      actorUserId: req.session?.user?.id,
      auditPayload: { restored: "missing_system_rooms" },
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[rooms] reset defaults failed", e?.message || e);
    return res.status(500).send("Failed");
  }
});

// ---- Moderation Cases API
app.get("/api/mod/cases", strictLimiter, requireLogin, async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");

  const status = String(req.query?.status || "").trim();
  const type = String(req.query?.type || "").trim();
  const assigned = String(req.query?.assigned || "").trim();
  const isAdmin = canViewAllCases(actor.role);
  const limit = Math.min(200, Math.max(1, Number(req.query?.limit || 200)));

  try {
    if (await pgUsersEnabled()) {
      const where = [];
      const params = [];
      if (!isAdmin) {
        where.push("(status = 'open' OR assigned_to_user_id = $1 OR created_by_user_id = $2)");
        params.push(actor.id, actor.id);
      }
      if (status) { params.push(status); where.push(`status = $${params.length}`); }
      if (type) { params.push(type); where.push(`type = $${params.length}`); }
      if (assigned === "me") { params.push(actor.id); where.push(`assigned_to_user_id = $${params.length}`); }
      if (assigned === "unassigned") { where.push("assigned_to_user_id IS NULL"); }
      if (assigned && assigned !== "me" && assigned !== "unassigned") {
        const assignedId = Number(assigned);
        if (Number.isFinite(assignedId) && assignedId > 0) {
          params.push(assignedId);
          where.push(`assigned_to_user_id = $${params.length}`);
        }
      }
      const sql = `SELECT * FROM mod_cases ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY updated_at DESC LIMIT ${limit}`;
      const { rows } = await pgPool.query(sql, params);
      return res.json({ ok: true, items: rows || [] });
    }

    const where = [];
    const params = [];
    if (!isAdmin) {
      where.push("(status = 'open' OR assigned_to_user_id = ? OR created_by_user_id = ?)");
      params.push(actor.id, actor.id);
    }
    if (status) { where.push("status = ?"); params.push(status); }
    if (type) { where.push("type = ?"); params.push(type); }
    if (assigned === "me") { where.push("assigned_to_user_id = ?"); params.push(actor.id); }
    if (assigned === "unassigned") { where.push("assigned_to_user_id IS NULL"); }
    if (assigned && assigned !== "me" && assigned !== "unassigned") {
      const assignedId = Number(assigned);
      if (Number.isFinite(assignedId) && assignedId > 0) {
        where.push("assigned_to_user_id = ?");
        params.push(assignedId);
      }
    }
    const sql = `SELECT * FROM mod_cases ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY updated_at DESC LIMIT ${limit}`;
    const items = await dbAllAsync(sql, params);
    return res.json({ ok: true, items });
  } catch (e) {
    console.warn("[mod-cases] list failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_list" });
  }
});

app.get("/api/mod/cases/:id", strictLimiter, requireLogin, async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).send("Invalid case");

  try {
    const caseRow = await fetchModCaseById(id);
    if (!caseRow) return res.status(404).send("Not found");
    const isAdmin = canViewAllCases(actor.role);
    if (!isAdmin) {
      const allowed =
        caseRow.status === "open" ||
        Number(caseRow.assigned_to_user_id || 0) === Number(actor.id) ||
        Number(caseRow.created_by_user_id || 0) === Number(actor.id);
      if (!allowed) return res.status(403).send("Forbidden");
    }

    const events = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(
          `SELECT * FROM mod_case_events WHERE case_id = $1 ORDER BY created_at ASC`,
          [id]
        );
        return rows || [];
      })()
      : await dbAllAsync(`SELECT * FROM mod_case_events WHERE case_id = ? ORDER BY created_at ASC`, [id]);
    const notes = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(
          `SELECT * FROM mod_case_notes WHERE case_id = $1 ORDER BY created_at ASC`,
          [id]
        );
        return rows || [];
      })()
      : await dbAllAsync(`SELECT * FROM mod_case_notes WHERE case_id = ? ORDER BY created_at ASC`, [id]);
    const evidence = await (await pgUsersEnabled())
      ? (async () => {
        const { rows } = await pgPool.query(
          `SELECT * FROM mod_case_evidence WHERE case_id = $1 ORDER BY created_at ASC`,
          [id]
        );
        return rows || [];
      })()
      : await dbAllAsync(`SELECT * FROM mod_case_evidence WHERE case_id = ? ORDER BY created_at ASC`, [id]);

    const parsedEvents = (events || []).map((ev) => ({
      ...ev,
      event_payload: typeof ev.event_payload === "string" ? safeJsonParse(ev.event_payload, {}) : ev.event_payload,
    }));

    return res.json({ ok: true, case: caseRow, events: parsedEvents, notes, evidence });
  } catch (e) {
    console.warn("[mod-cases] fetch failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_fetch" });
  }
});

app.post("/api/mod/cases", strictLimiter, requireLogin, express.json({ limit: "32kb" }), async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const type = String(req.body?.type || "").trim();
  const allowedTypes = new Set(["flag", "appeal", "referral", "investigation"]);
  if (!allowedTypes.has(type)) return res.status(400).send("Invalid type");

  try {
    const caseRow = await createModCase({
      type,
      status: "open",
      priority: String(req.body?.priority || "normal"),
      subjectUserId: Number(req.body?.subject_user_id) || null,
      createdByUserId: actor.id,
      assignedToUserId: Number(req.body?.assigned_to_user_id) || null,
      roomId: req.body?.room_id ? String(req.body.room_id) : null,
      title: req.body?.title ? String(req.body.title).slice(0, 160) : null,
      summary: req.body?.summary ? String(req.body.summary).slice(0, 2000) : null,
    });
    if (!caseRow?.id) return res.status(500).json({ ok: false, error: "create_failed" });
    await addModCaseEvent(caseRow.id, { actorUserId: actor.id, eventType: "created", payload: { type } });
    emitToStaff("mod:case_created", { id: caseRow.id, type: caseRow.type, status: caseRow.status });
    return res.json({ ok: true, case: caseRow });
  } catch (e) {
    console.warn("[mod-cases] create failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "create_failed" });
  }
});

app.patch("/api/mod/cases/:id", strictLimiter, requireLogin, express.json({ limit: "32kb" }), async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).send("Invalid case");

  try {
    const caseRow = await fetchModCaseById(id);
    if (!caseRow) return res.status(404).send("Not found");
    const isAdmin = canViewAllCases(actor.role);
    const isOwnerOrAssignee =
      Number(caseRow.assigned_to_user_id || 0) === Number(actor.id) ||
      Number(caseRow.created_by_user_id || 0) === Number(actor.id);
    if (!isAdmin && !isOwnerOrAssignee) return res.status(403).send("Forbidden");

    const updates = [];
    const params = [];
    const fields = [
      ["assigned_to_user_id", "assigned_to_user_id"],
      ["priority", "priority"],
      ["title", "title"],
      ["summary", "summary"],
      ["room_id", "room_id"],
      ["subject_user_id", "subject_user_id"],
    ];
    for (const [key, col] of fields) {
      if (!Object.prototype.hasOwnProperty.call(req.body || {}, key)) continue;
      updates.push(col);
      params.push(req.body[key] == null ? null : req.body[key]);
    }
    if (!updates.length) return res.json({ ok: true, case: caseRow });

    const now = Date.now();
    if (await pgUsersEnabled()) {
      const setParts = updates.map((col, idx) => `${col} = $${idx + 1}`);
      const pgParams = [...params, now, id];
      await pgPool.query(
        `UPDATE mod_cases SET ${setParts.join(", ")}, updated_at = $${pgParams.length - 1} WHERE id = $${pgParams.length}`,
        pgParams
      );
    } else {
      const setParts = updates.map(() => "?");
      await dbRunAsync(
        `UPDATE mod_cases SET ${updates.map((col, idx) => `${col} = ${setParts[idx]}`).join(", ")}, updated_at = ? WHERE id = ?`,
        [...params, now, id]
      );
    }
    await addModCaseEvent(id, { actorUserId: actor.id, eventType: "updated", payload: { updates: req.body || {} } });
    emitToStaff("mod:case_updated", { id, updates: req.body || {} });
    const updated = await fetchModCaseById(id);
    return res.json({ ok: true, case: updated });
  } catch (e) {
    console.warn("[mod-cases] update failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "update_failed" });
  }
});

app.post("/api/mod/cases/:id/status", strictLimiter, requireLogin, express.json({ limit: "16kb" }), async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const id = Number(req.params.id);
  const status = String(req.body?.status || "").trim();
  if (!Number.isFinite(id) || !status) return res.status(400).send("Invalid status");
  const allowedStatuses = new Set(["open", "closed", "resolved", "pending"]);
  if (!allowedStatuses.has(status)) return res.status(400).send("Invalid status");

  try {
    const caseRow = await fetchModCaseById(id);
    if (!caseRow) return res.status(404).send("Not found");
    const isAdmin = canViewAllCases(actor.role);
    const isOwnerOrAssignee =
      Number(caseRow.assigned_to_user_id || 0) === Number(actor.id) ||
      Number(caseRow.created_by_user_id || 0) === Number(actor.id);
    if (!isAdmin && !isOwnerOrAssignee) return res.status(403).send("Forbidden");

    const now = Date.now();
    const closedAt = status === "closed" ? now : null;
    const closedReason = req.body?.closed_reason ? String(req.body.closed_reason).slice(0, 400) : null;
    if (await pgUsersEnabled()) {
      await pgPool.query(
        `UPDATE mod_cases SET status = $1, updated_at = $2, closed_at = $3, closed_reason = $4 WHERE id = $5`,
        [status, now, closedAt, closedReason, id]
      );
    } else {
      await dbRunAsync(
        `UPDATE mod_cases SET status = ?, updated_at = ?, closed_at = ?, closed_reason = ? WHERE id = ?`,
        [status, now, closedAt, closedReason, id]
      );
    }
    await addModCaseEvent(id, { actorUserId: actor.id, eventType: "status_changed", payload: { status, closed_reason: closedReason } });
    emitToStaff("mod:case_updated", { id, status });
    const updated = await fetchModCaseById(id);
    return res.json({ ok: true, case: updated });
  } catch (e) {
    console.warn("[mod-cases] status update failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "status_failed" });
  }
});

app.post("/api/mod/cases/:id/notes", strictLimiter, requireLogin, express.json({ limit: "16kb" }), async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const id = Number(req.params.id);
  const body = String(req.body?.body || "").trim();
  if (!Number.isFinite(id) || !body) return res.status(400).send("Invalid note");
  try {
    const caseRow = await fetchModCaseById(id);
    if (!caseRow) return res.status(404).send("Not found");
    const note = await addModCaseNote(id, { authorUserId: actor.id, body: body.slice(0, 2000) });
    await addModCaseEvent(id, { actorUserId: actor.id, eventType: "note_added" });
    emitToStaff("mod:case_event", { caseId: id, eventType: "note_added" });
    return res.json({ ok: true, note });
  } catch (e) {
    console.warn("[mod-cases] note failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "note_failed" });
  }
});

app.post("/api/mod/cases/:id/evidence", strictLimiter, requireLogin, express.json({ limit: "32kb" }), async (req, res) => {
  const actor = req.session?.user;
  if (!actor || !isStaffRole(actor.role)) return res.status(403).send("Forbidden");
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).send("Invalid case");
  const evidenceType = String(req.body?.evidence_type || "").trim();
  const allowedTypes = new Set(["message", "text", "link"]);
  if (!allowedTypes.has(evidenceType)) return res.status(400).send("Invalid evidence type");

  try {
    const caseRow = await fetchModCaseById(id);
    if (!caseRow) return res.status(404).send("Not found");
    const evidence = await addModCaseEvidence(id, {
      createdByUserId: actor.id,
      evidenceType,
      roomId: req.body?.room_id ? String(req.body.room_id) : null,
      messageId: Number(req.body?.message_id) || null,
      messageExcerpt: req.body?.message_excerpt ? String(req.body.message_excerpt).slice(0, 500) : null,
      url: req.body?.url ? String(req.body.url).slice(0, 600) : null,
      text: req.body?.text ? String(req.body.text).slice(0, 2000) : null,
    });
    await addModCaseEvent(id, { actorUserId: actor.id, eventType: "evidence_added", payload: { evidence_type: evidenceType } });
    emitToStaff("mod:case_event", { caseId: id, eventType: "evidence_added" });
    return res.json({ ok: true, evidence });
  } catch (e) {
    console.warn("[mod-cases] evidence failed", e?.message || e);
    return res.status(500).json({ ok: false, error: "evidence_failed" });
  }
});

// ---- Room collapse persistence
app.patch(
  "/api/users/me/room-master-collapsed",
  strictLimiter,
  requireLogin,
  express.json({ limit: "8kb" }),
  async (req, res) => {
    const userId = req.session?.user?.id;
    const masterId = String(req.body?.master_id || "").trim();
    const collapsed = !!req.body?.collapsed;
    if (!masterId) return res.status(400).send("Invalid master");
    try {
      const current = await getUserRoomCollapseState(userId);
      const next = { ...(current.master || {}) };
      next[masterId] = collapsed;
      const serialized = JSON.stringify(next);
      await dbRunAsync(`UPDATE users SET room_master_collapsed = ? WHERE id = ?`, [serialized, userId]);
      try {
        await pgPool.query(`UPDATE users SET room_master_collapsed = $1 WHERE id = $2`, [serialized, userId]);
      } catch {}
      return res.json({ ok: true });
    } catch (e) {
      console.warn("[rooms] master collapse failed", e?.message || e);
      return res.status(500).send("Failed");
    }
  }
);

app.patch(
  "/api/users/me/room-category-collapsed",
  strictLimiter,
  requireLogin,
  express.json({ limit: "8kb" }),
  async (req, res) => {
    const userId = req.session?.user?.id;
    const categoryId = String(req.body?.category_id || "").trim();
    const collapsed = !!req.body?.collapsed;
    if (!categoryId) return res.status(400).send("Invalid category");
    try {
      const current = await getUserRoomCollapseState(userId);
      const next = { ...(current.category || {}) };
      next[categoryId] = collapsed;
      const serialized = JSON.stringify(next);
      await dbRunAsync(`UPDATE users SET room_category_collapsed = ? WHERE id = ?`, [serialized, userId]);
      try {
        await pgPool.query(`UPDATE users SET room_category_collapsed = $1 WHERE id = $2`, [serialized, userId]);
      } catch {}
      return res.json({ ok: true });
    } catch (e) {
      console.warn("[rooms] category collapse failed", e?.message || e);
      return res.status(500).send("Failed");
    }
  }
);

// ---- Changelog API
app.get("/api/changelog", requireLogin, async (req, res) => {
  const limit = clamp(req.query?.limit || 0, 0, 200);
  try {
    const rows = await fetchChangelogEntriesWithReactions({ limit, userId: req.session?.user?.id });
    return res.json(rows || []);
  } catch (e) {
    console.error("[changelog] load failed:", e?.message || e);
    return res.status(500).send("Failed to load changelog");
  }
});

app.post("/api/changelog", strictLimiter, requireOwner, async (req, res) => {
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

app.delete("/api/changelog/:id", strictLimiter, requireOwner, async (req, res) => {
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
    await dbRunAsync(`DELETE FROM changelog_reactions WHERE entry_id=?`, [id]);
    const result = await dbRunAsync(`DELETE FROM changelog_entries WHERE id=?`, [id]);
    if (!result?.changes) return res.status(404).send("Entry not found");
    io.emit("changelog updated");
    return res.json({ ok: true });
  } catch (err) {
    console.error("[changelog] delete failed:", err?.message || err);
    return res.status(500).send("Failed to delete changelog entry");
  }
});

app.post("/api/changelog/:id/reaction", strictLimiter, requireLogin, async (req, res) => {
  const entryId = Number(req.params?.id);
  const reaction = normalizeReactionKey(req.body?.reaction);
  if (!Number.isFinite(entryId) || entryId <= 0) return res.status(400).send("Invalid entry id");
  if (!reaction) return res.status(400).send("Invalid reaction");

  const userId = req.session.user.id;
  let payload = null;
  let usedPg = false;

  if (await pgChangelogEnabled()) {
    try {
      const exists = await pgChangelogEntryExists(entryId);
      if (!exists) return res.status(404).send("Entry not found");
      await pgToggleChangelogReaction(entryId, userId, reaction);
      usedPg = true;
      payload = await pgChangelogReactionPayload(entryId, userId);
    } catch (e) {
      console.warn("[changelog] PG reaction toggle fallback:", e?.message || e);
      if (usedPg) return res.status(500).send("Failed to update reaction");
    }
  }

  if (!payload && !usedPg) {
    const exists = await sqliteChangelogEntryExists(entryId);
    if (!exists) return res.status(404).send("Entry not found");
    await sqliteToggleChangelogReaction(entryId, userId, reaction);
    payload = await sqliteChangelogReactionPayload(entryId, userId);
  } else if (!payload && usedPg) {
    return res.status(500).send("Failed to update reaction");
  }

  if (!payload) return res.status(500).send("Failed to update reaction");

  io.emit("changelog reactions updated");
  return res.json(payload);
});

app.get("/api/faq", requireLogin, async (req, res) => {
  try {
    const rows = await fetchFaqQuestionsWithReactions(req.session?.user?.username);
    return res.json(rows || []);
  } catch (e) {
    console.error("[faq] load failed:", e?.message || e);
    return res.status(500).send("Failed to load FAQ");
  }
});

app.post("/api/faq", strictLimiter, requireLogin, async (req, res) => {
  const cleaned = cleanFaqInput(req.body?.title, req.body?.details);
  if(cleaned.error) return res.status(400).send(cleaned.error);

  const userId = req.session.user.id;
  const now = Date.now();
  const last = faqAskCooldown.get(userId) || 0;
  if(now - last < FAQ_RATE_LIMIT_MS) return res.status(429).send("Please wait before asking another question.");
  faqAskCooldown.set(userId, now);

  try{
    let row = null;
    if(await pgChangelogEnabled()){
      try{ row = await pgCreateFaqQuestion(cleaned); }catch(e){ console.warn("[faq] PG create fallback:", e?.message || e); }
    }
    if(!row){
      row = await sqliteCreateFaqQuestion(cleaned);
    }
    const payload = toFaqPayload(row);
    io.emit("faq:update");
    return res.json(payload);
  }catch(err){
    console.error("[faq] create failed:", err?.message || err);
    return res.status(500).send("Failed to submit question");
  }
});

app.patch("/api/faq/:id/answer", requireLogin, async (req, res) => {
  const questionId = Number(req.params?.id);
  if(!Number.isFinite(questionId) || questionId <= 0) return res.status(400).send("Invalid question id");
  if(!requireMinRole(req.session.user.role, "Admin")) return res.status(403).send("Forbidden");

  const answerBody = String(req.body?.answer || "").trimEnd();
  // Allow effectively unlimited answers (TEXT field), but keep a high ceiling
  // to protect the service from accidental paste-bombs.
  if(answerBody.length > 50000) return res.status(400).send("Answer is too long");

  try{
    let row = null;
    if(await pgChangelogEnabled()){
      try{ row = await pgUpdateFaqAnswer({ id: questionId, answerBody, answeredBy: req.session.user.id }); }catch(e){ console.warn("[faq] PG answer fallback:", e?.message || e); }
    }
    if(!row){
      row = await sqliteUpdateFaqAnswer({ id: questionId, answerBody, answeredBy: req.session.user.id });
    }
    if(!row) return res.status(404).send("Question not found");
    const payload = toFaqPayload(row);
    io.emit("faq:update");
    return res.json(payload);
  }catch(err){
    console.error("[faq] answer failed:", err?.message || err);
    return res.status(500).send("Failed to save answer");
  }
});

app.delete("/api/faq/:id", strictLimiter, requireLogin, async (req, res) => {
  const questionId = Number(req.params?.id);
  if(!Number.isFinite(questionId) || questionId <= 0) return res.status(400).send("Invalid question id");
  // Admin, Co-owner, Owner
  if(!requireMinRole(req.session.user.role, "Admin")) return res.status(403).send("Forbidden");

  try{
    let ok = false;
    if(await pgChangelogEnabled()){
      try{ ok = await pgDeleteFaqQuestion(questionId); }catch(e){ console.warn("[faq] PG delete fallback:", e?.message || e); }
    }
    if(!ok){
      ok = await sqliteDeleteFaqQuestion(questionId);
    }
    if(!ok) return res.status(404).send("Question not found");
    io.emit("faq:update");
    return res.json({ ok:true });
  }catch(err){
    console.error("[faq] delete failed:", err?.message || err);
    return res.status(500).send("Failed to delete question");
  }
});

app.post("/api/faq/:id/react", strictLimiter, requireLogin, async (req, res) => {
  const questionId = Number(req.params?.id);
  const reaction = normalizeFaqReactionKey(req.body?.reaction);
  if(!Number.isFinite(questionId) || questionId <= 0) return res.status(400).send("Invalid question id");
  if(!reaction) return res.status(400).send("Invalid reaction");

  const username = req.session.user.username;
  let usedPg = false;
  try{
    if(await pgChangelogEnabled()){
      const exists = await pgFaqQuestionExists(questionId);
      if(!exists) return res.status(404).send("Question not found");
      await pgToggleFaqReaction(questionId, username, reaction);
      usedPg = true;
      const payload = await faqReactionPayload(questionId, username);
      io.emit("faq:update");
      return res.json(payload);
    }
  }catch(e){
    console.warn("[faq] PG reaction toggle fallback:", e?.message || e);
    if(usedPg) return res.status(500).send("Failed to update reaction");
  }

  try{
    const exists = await sqliteFaqQuestionExists(questionId);
    if(!exists) return res.status(404).send("Question not found");
    await sqliteToggleFaqReaction(questionId, username, reaction);
    const payload = await faqReactionPayload(questionId, username);
    io.emit("faq:update");
    return res.json(payload);
  }catch(err){
    console.error("[faq] reaction failed:", err?.message || err);
    return res.status(500).send("Failed to update reaction");
  }
});
// ---- Profile routes
app.get("/api/profile", requireLogin, (req, res) => res.redirect(307, "/profile"));

async function fetchProfileLikeStats(targetUserId, viewerId) {
  if (await pgUsersEnabled()) {
    try {
      const { rows } = await pgPool.query(
        `SELECT COUNT(*)::int AS likes,
                EXISTS(SELECT 1 FROM profile_likes WHERE user_id = $2 AND target_user_id = $1) AS liked`,
        [targetUserId, viewerId]
      );
      return { likes: Number(rows?.[0]?.likes || 0), liked: !!rows?.[0]?.liked };
    } catch (e) {
      console.warn("[profile likes][pg] failed, falling back to sqlite:", e?.message || e);
    }
  }

  return await new Promise((resolve) => {
    db.get(
      `SELECT
        (SELECT COUNT(*) FROM profile_likes WHERE target_user_id = ?) AS likes,
        EXISTS(SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?) AS liked`,
      [targetUserId, viewerId, targetUserId],
      (_likeErr, likesRow) => {
        resolve({
          likes: Number(likesRow?.likes || 0),
          liked: !!Number(likesRow?.liked || 0),
        });
      }
    );
  });
}

async function toggleProfileLike(userId, targetUserId) {
  if (await pgUsersEnabled()) {
    try {
      const now = Date.now();
      await pgPool.query(
        `WITH deleted AS (
            DELETE FROM profile_likes
             WHERE user_id = $1 AND target_user_id = $2
             RETURNING 1
         ),
         inserted AS (
           INSERT INTO profile_likes (user_id, target_user_id, created_at)
           SELECT $1, $2, $3
            WHERE NOT EXISTS (SELECT 1 FROM deleted)
           ON CONFLICT (user_id, target_user_id) DO NOTHING
           RETURNING 1
         )
         SELECT 1`,
        [userId, targetUserId, now]
      );
      const stats = await fetchProfileLikeStats(targetUserId, userId);
      // Best-effort mirror to SQLite so legacy reads stay consistent.
      try {
        if (stats.liked) {
          await dbRunAsync(
            `INSERT OR IGNORE INTO profile_likes (user_id, target_user_id, created_at) VALUES (?, ?, ?)`,
            [userId, targetUserId, now]
          );
        } else {
          await dbRunAsync(`DELETE FROM profile_likes WHERE user_id = ? AND target_user_id = ?`, [userId, targetUserId]);
        }
      } catch (e) {
        console.warn("[profile likes][sqlite mirror]", e?.message || e);
      }
      return stats;
    } catch (e) {
      console.warn("[profile likes][pg toggle] failed, falling back to sqlite:", e?.message || e);
    }
  }

  const existing = await dbGetAsync(
    `SELECT 1 FROM profile_likes WHERE user_id = ? AND target_user_id = ?`,
    [userId, targetUserId]
  ).catch(() => null);
  if (existing) {
    await dbRunAsync(`DELETE FROM profile_likes WHERE user_id = ? AND target_user_id = ?`, [userId, targetUserId]);
  } else {
    await dbRunAsync(
      `INSERT OR IGNORE INTO profile_likes (user_id, target_user_id, created_at) VALUES (?, ?, ?)`,
      [userId, targetUserId, Date.now()]
    );
  }
  return await fetchProfileLikeStats(targetUserId, userId);
}

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

      const likeStats = await fetchProfileLikeStats(row.id, userId);
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
        likes: likeStats.likes,
        likedByMe: likeStats.liked,
        vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
        ...progressionFromRow(row, true),
      };
      return res.json(payload);
    }
  } catch (e) {
    console.warn("[/profile][pg] failed, falling back to sqlite:", e?.message || e);
  }

  // SQLite fallback (original behavior)
  const row = await dbGet(
    `SELECT id, username FROM users WHERE id = ?`,
    [userId]
  );
  if (!row) return res.status(404).send("Not found");
  const live = onlineState.get(row.id);
  const lastStatus = normalizeStatus(live?.status || row.last_status, "");
  const lastSeen = resolveLastSeen(row, live, lastStatus);
  const likeStats = await fetchProfileLikeStats(row.id, userId);
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
    likes: likeStats.likes,
    likedByMe: likeStats.liked,
    vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
    ...progressionFromRow(row, true),
  };
  return res.json(payload);
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
    let fromPg = false;
    try {
      for (const cand of candidates) {
        try {
          const r = await pgPool.query(
            `SELECT id, username FROM users WHERE username = $1 OR lower(username) = lower($1)
             LIMIT 1`,
            [cand]
          );
          row = r.rows?.[0] || null;
          if (row) break;
        } catch {}
      }
      if (row) fromPg = true;
    } catch {}

    // Fallback to SQLite
    if (!row) {
      for (const cand of candidates) {
        row = await dbGet(
          `SELECT id, username FROM users WHERE username = ? OR lower(username) = lower(?)`,
          [cand, cand]
        );
        if (row) break;
      }
    }

    if (!row) return res.status(404).send("Not found");

    // IMPORTANT: The quick lookup above only selects id/username.
    // We must fetch the full profile row, otherwise the UI will show blanks
    // and appear to "not pull" changes after edits.
    const PROFILE_COLS = [
      "id",
      "username",
      "role",
      "created_at",
      "avatar",
      "avatar_bytes",
      "avatar_mime",
      "avatar_updated",
      "bio",
      "mood",
      "age",
      "gender",
      "last_seen",
      "last_room",
      "last_status",
      "gold",
      "xp",
      "vibe_tags",
      "header_grad_a",
      "header_grad_b",
    ];

    if (fromPg) {
      try {
        const full = await pgGetUserRowById(Number(row.id) || 0, PROFILE_COLS);
        if (full) row = full;
      } catch {}
    } else {
      // SQLite full fetch
      try {
        const full = await dbGet(
          `SELECT ${PROFILE_COLS.filter((c) => c !== "avatar_bytes" && c !== "avatar_mime" && c !== "avatar_updated").join(", ")}
           FROM users WHERE id = ? LIMIT 1`,
          [Number(row.id) || 0]
        );
        if (full) row = full;
      } catch {}
    }

    const live = onlineState.get(row.id);
    const lastStatus = normalizeStatus(live?.status || row.last_status, "");
    const lastSeen = resolveLastSeen(row, live, lastStatus);
    const includePrivate = req.session.user.id === row.id;

    const likeStats = await fetchProfileLikeStats(row.id, req.session.user.id);
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
      likes: likeStats.likes,
      likedByMe: likeStats.liked,
      vibe_tags: sanitizeVibeTags(row.vibe_tags || []),
      ...progressionFromRow(row, includePrivate),
    };

    // Couple info (opt-in, privacy-friendly)
    try {
      if (PG_READY && row?.id) {
        const targetId = Number(row.id) || 0;
        const { rows: clRows } = await pgPool.query(
          `
          SELECT cl.*,
                 u1.username AS user1_name,
                 u2.username AS user2_name,
                 u1.avatar AS user1_avatar,
                 u2.avatar AS user2_avatar,
                 u1.role AS user1_role,
                 u2.role AS user2_role,
                 p1.enabled AS p1_enabled, p1.show_profile AS p1_show_profile, p1.show_members AS p1_show_members,
                 p1.group_members AS p1_group_members, p1.aura AS p1_aura, p1.badge AS p1_badge,
                 p2.enabled AS p2_enabled, p2.show_profile AS p2_show_profile, p2.show_members AS p2_show_members,
                 p2.group_members AS p2_group_members, p2.aura AS p2_aura, p2.badge AS p2_badge
            FROM couple_links cl
            JOIN users u1 ON u1.id = cl.user1_id
            JOIN users u2 ON u2.id = cl.user2_id
            LEFT JOIN couple_prefs p1 ON p1.link_id = cl.id AND p1.user_id = cl.user1_id
            LEFT JOIN couple_prefs p2 ON p2.link_id = cl.id AND p2.user_id = cl.user2_id
           WHERE cl.status='active'
             AND (cl.user1_id=$1 OR cl.user2_id=$1)
           ORDER BY cl.updated_at DESC
           LIMIT 1
          `,
          [targetId]
        );

        const cl = clRows[0];
        if (cl) {
          const isU1 = Number(cl.user1_id) === targetId;
          const partnerName = isU1 ? cl.user2_name : cl.user1_name;
          const partnerId = getCouplePartnerId(targetId, cl);
          const viewerId = Number(req.session.user?.id) || 0;
          const isMember = isCoupleMember(viewerId, cl);
          const privacy = cl.privacy || "private";

          const mePrefs = isU1 ? {
            enabled: !!cl.p1_enabled,
            showProfile: !!cl.p1_show_profile,
            showMembers: !!cl.p1_show_members,
            groupMembers: !!cl.p1_group_members,
            aura: !!cl.p1_aura,
            badge: !!cl.p1_badge
          } : {
            enabled: !!cl.p2_enabled,
            showProfile: !!cl.p2_show_profile,
            showMembers: !!cl.p2_show_members,
            groupMembers: !!cl.p2_group_members,
            aura: !!cl.p2_aura,
            badge: !!cl.p2_badge
          };

          const partnerPrefs = isU1 ? {
            enabled: !!cl.p2_enabled,
            showProfile: !!cl.p2_show_profile,
            showMembers: !!cl.p2_show_members,
            groupMembers: !!cl.p2_group_members,
            aura: !!cl.p2_aura,
            badge: !!cl.p2_badge
          } : {
            enabled: !!cl.p1_enabled,
            showProfile: !!cl.p1_show_profile,
            showMembers: !!cl.p1_show_members,
            groupMembers: !!cl.p1_group_members,
            aura: !!cl.p1_aura,
            badge: !!cl.p1_badge
          };

          let privacyAllows = privacy === "public";
          if (privacy === "private") privacyAllows = isMember;
          if (privacy === "friends" && !privacyAllows) {
            if (isMember) privacyAllows = true;
            else if (viewerId && viewerId !== targetId && partnerId) {
              try {
                if (PG_READY && FRIENDS_READY) {
                  privacyAllows = (await pgAreFriends(viewerId, targetId)) || (await pgAreFriends(viewerId, partnerId));
                } else {
                  privacyAllows = (await dbAreFriends(viewerId, targetId)) || (await dbAreFriends(viewerId, partnerId));
                }
              } catch {}
            }
          }

          if (privacyAllows && canShowCoupleFeature(mePrefs, partnerPrefs, "profile")) {
            payload.couple = {
              partner: partnerName,
              since: Number(cl.activated_at || cl.created_at) || null,
              statusEmoji: cl.status_emoji || "💜",
              statusLabel: cl.status_label || "Linked",
              badge: canShowCoupleBadge(mePrefs, partnerPrefs, cl),
              aura: canShowCoupleFeature(mePrefs, partnerPrefs, "aura"),
              showMembers: canShowCoupleFeature(mePrefs, partnerPrefs, "members"),
              groupMembers: canShowCoupleFeature(mePrefs, partnerPrefs, "group")
            };
          }

          if (privacyAllows && isCouplesV2EnabledFor(req.session.user)) {
            const members = [
              {
                id: Number(cl.user1_id) || 0,
                username: cl.user1_name,
                avatar: avatarUrlFromRow({ avatar: cl.user1_avatar }),
                role: cl.user1_role || "User"
              },
              {
                id: Number(cl.user2_id) || 0,
                username: cl.user2_name,
                avatar: avatarUrlFromRow({ avatar: cl.user2_avatar }),
                role: cl.user2_role || "User"
              }
            ];
            payload.coupleCard = {
              coupleName: cl.couple_name || "",
              coupleBio: cl.couple_bio || "",
              privacy,
              showBadge: cl.show_badge !== false,
              statusEmoji: cl.status_emoji || "💜",
              statusLabel: cl.status_label || "Linked",
              since: Number(cl.activated_at || cl.created_at) || null,
              members
            };
          }
        }
      }
    } catch {}

    // Friend relationship info (for showing accept/decline/add friend UI)
    try {
      const viewerId = Number(req.session.user?.id) || 0;
      const targetId = Number(payload.id) || 0;
      if (viewerId && targetId && viewerId !== targetId) {
        let status = null;
        let requestId = null;
        if (PG_READY && FRIENDS_READY) {
          const friends = await pgAreFriends(viewerId, targetId);
          if (friends) {
            status = 'friends';
          } else {
            const incoming = await pgGetPendingFriendRequest(targetId, viewerId);
            const outgoing = await pgGetPendingFriendRequest(viewerId, targetId);
            if (incoming?.id) { status = 'incoming'; requestId = Number(incoming.id) || null; }
            else if (outgoing?.id) { status = 'outgoing'; requestId = Number(outgoing.id) || null; }
            else status = 'none';
          }
        } else {
          const friends = await dbAreFriends(viewerId, targetId);
          if (friends) {
            status = 'friends';
          } else {
            const incoming = await dbGetPendingFriendRequest(targetId, viewerId);
            const outgoing = await dbGetPendingFriendRequest(viewerId, targetId);
            if (incoming?.id) { status = 'incoming'; requestId = Number(incoming.id) || null; }
            else if (outgoing?.id) { status = 'outgoing'; requestId = Number(outgoing.id) || null; }
            else status = 'none';
          }
        }
        payload.friend = { status, requestId };
      }
    } catch {}


    return res.json(payload);
  } catch (e) {
    return res.status(500).send("Server error");
  }
});

app.get("/api/memory-settings", requireLogin, async (req, res) => {
  try {
    const settings = await getMemorySettingsForUser(req.session.user);
    return res.json({ ok: true, ...settings });
  } catch (e) {
    console.warn("[memory] settings fetch failed:", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_load_settings" });
  }
});

app.post("/api/memory-settings", strictLimiter, requireLogin, express.json({ limit: "16kb" }), async (req, res) => {
  try {
    const user = req.session.user;
    const settings = await getMemorySettingsForUser(user);
    if (!settings.available) return res.status(403).json({ ok: false, error: "feature_disabled" });
    const enabled = !!req.body?.enabled;
    await setMemorySettingsRow(user.id, enabled);
    return res.json({ ok: true, available: true, enabled });
  } catch (e) {
    console.warn("[memory] settings update failed:", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_save_settings" });
  }
});

app.get("/api/memories", requireLogin, async (req, res) => {
  const user = req.session.user;
  try {
    const settings = await getMemorySettingsForUser(user);
    if (!settings.available || !settings.enabled) return res.status(403).json({ ok: false, error: "disabled" });

    const types = resolveMemoryTypes(req.query?.filter);
    if (await pgUserExists(user.id)) {
      const params = [user.id];
      let whereSql = "user_id = $1";
      if (types?.length) {
        params.push(types);
        whereSql += ` AND type = ANY($${params.length}::text[])`;
      }
      const { rows } = await pgPool.query(
        `SELECT * FROM memories WHERE ${whereSql} ORDER BY created_at DESC`,
        params
      );
      const memories = rows.map(normalizeMemoryRow);
      return res.json({ ok: true, memories });
    }
  } catch (e) {
    console.warn("[memory] pg list failed, falling back to sqlite:", e?.message || e);
  }

  try {
    const params = [user.id];
    let whereSql = "user_id = ?";
    if (types?.length) {
      whereSql += ` AND type IN (${types.map(() => "?").join(", ")})`;
      params.push(...types);
    }
    const rows = await dbAllAsync(
      `SELECT * FROM memories WHERE ${whereSql} ORDER BY created_at DESC`,
      params
    );
    const memories = rows.map(normalizeMemoryRow);
    return res.json({ ok: true, memories });
  } catch (e) {
    console.warn("[memory] sqlite list failed:", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_load_memories" });
  }
});

app.post("/api/memories/:id/pin", strictLimiter, requireLogin, async (req, res) => {
  const user = req.session.user;
  const memoryId = Number(req.params.id) || 0;
  if (!memoryId) return res.status(400).json({ ok: false, error: "bad_request" });

  try {
    const settings = await getMemorySettingsForUser(user);
    if (!settings.available || !settings.enabled) return res.status(403).json({ ok: false, error: "disabled" });

    if (await pgUserExists(user.id)) {
      const { rows } = await pgPool.query(
        `UPDATE memories SET pinned = NOT pinned WHERE id = $1 AND user_id = $2 RETURNING pinned`,
        [memoryId, user.id]
      );
      const row = rows[0];
      if (!row) return res.status(404).json({ ok: false, error: "not_found" });
      return res.json({ ok: true, pinned: normalizeMemoryBool(row.pinned) });
    }
  } catch (e) {
    console.warn("[memory] pg pin failed, falling back to sqlite:", e?.message || e);
  }

  try {
    await dbRunAsync(
      `UPDATE memories SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE id = ? AND user_id = ?`,
      [memoryId, user.id]
    );
    const row = await dbGetAsync(`SELECT pinned FROM memories WHERE id = ? AND user_id = ?`, [memoryId, user.id]);
    if (!row) return res.status(404).json({ ok: false, error: "not_found" });
    return res.json({ ok: true, pinned: normalizeMemoryBool(row.pinned) });
  } catch (e) {
    console.warn("[memory] sqlite pin failed:", e?.message || e);
    return res.status(500).json({ ok: false, error: "failed_to_pin" });
  }
});


// ---- Couples API (opt-in). Postgres only.
app.get("/api/couples/me", requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    const summary = await pgGetCoupleSummaryFor(req.session.user);
    if (summary?.v2Enabled && summary?.couple) {
      ensureCoupleMilestoneMemories(summary.couple).catch((e) => {
        console.warn("[couples] milestone memory failed:", e?.message || e);
      });
    }
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] /me failed:", e?.message || e);
    return res.status(500).send("Could not load couples");
  }
});

app.post("/api/couples/request", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");

    const targetRaw = String(req.body?.targetUsername || "").trim().slice(0, 64);
    const targetName = sanitizeUsername(targetRaw);
    if (!targetName) return res.status(400).send("Bad username");
    if (targetName.toLowerCase() === String(req.session.user?.username || "").toLowerCase()) {
      return res.status(400).send("You cannot link with yourself");
    }

    const { rows: trg } = await pgPool.query(`SELECT id, username FROM users WHERE lower(username)=lower($1) LIMIT 1`, [targetName]);
    const target = trg[0];
    if (!target) return res.status(404).send("User not found");

    const meId = Number(req.session.user?.id) || 0;
    if (!meId) return res.status(401).send("Not logged in");
    const otherId = Number(target.id) || 0;
    const [u1, u2] = orderPair(meId, otherId);
    const now = Date.now();

    const { rows: existing } = await pgPool.query(
      `SELECT id, status FROM couple_links WHERE user1_id=$1 AND user2_id=$2 LIMIT 1`,
      [u1, u2]
    );
    if (existing[0]) {
      if (existing[0].status === "active") return res.status(409).send("Already linked");
      return res.status(409).send("A link request already exists");
    }

    const { rows: created } = await pgPool.query(
      `
      INSERT INTO couple_links(user1_id, user2_id, requested_by_id, status, status_emoji, status_label, created_at, updated_at)
      VALUES($1,$2,$3,'pending','💜','Linked',$4,$4)
      RETURNING id
      `,
      [u1, u2, meId, now]
    );
    const linkId = created?.[0]?.id;

    await pgPool.query(
      `
      INSERT INTO couple_prefs(link_id, user_id, enabled, show_profile, show_members, group_members, aura, badge, allow_ping, updated_at)
      VALUES
        ($1,$2,true,true,true,false,true,true,true,$4),
        ($1,$3,true,true,true,false,true,true,true,$4)
      ON CONFLICT (link_id, user_id) DO NOTHING
      `,
      [linkId, u1, u2, now]
    );

    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] request failed:", e?.message || e);
    return res.status(500).send("Could not create request");
  }
});

app.post("/api/couples/respond", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    const linkId = Number(req.body?.linkId) || 0;
    const accept = !!req.body?.accept;
    if (!linkId) return res.status(400).send("Bad request");

    const meId = Number(req.session.user?.id) || 0;
    const { rows } = await pgPool.query(`SELECT * FROM couple_links WHERE id=$1 LIMIT 1`, [linkId]);
    const link = rows[0];
    if (!link) return res.status(404).send("Not found");
    if (link.status !== "pending") return res.status(409).send("Not pending");
    if (!isCoupleMember(meId, link)) return res.status(403).send("Forbidden");

    if (!accept) {
      await pgPool.query(`DELETE FROM couple_links WHERE id=$1`, [linkId]);
      emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId });
      const summary = await pgGetCoupleSummaryFor(req.session.user);
      return res.json(summary);
    }

    const now = Date.now();
    await pgPool.query(
      `UPDATE couple_links SET status='active', activated_at=$2, updated_at=$2 WHERE id=$1`,
      [linkId, now]
    );
    emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId });

    // Ensure both sides have default prefs rows (so both requestor + acceptor see options)
    try {
      await pgUpsertCouplePrefs(linkId, Number(link.user1_id) || 0, {});
      await pgUpsertCouplePrefs(linkId, Number(link.user2_id) || 0, {});
    } catch (e) {
      console.warn("[couples] ensure prefs rows failed:", e?.message || e);
    }

    try {
      await ensureCoupleLinkedMemories(link);
    } catch (e) {
      console.warn("[couples] memory create failed:", e?.message || e);
    }

    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] respond failed:", e?.message || e);
    return res.status(500).send("Could not respond");
  }
});

app.post("/api/couples/unlink", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    const linkId = Number(req.body?.linkId) || 0;
    if (!linkId) return res.status(400).send("Bad request");

    const meId = Number(req.session.user?.id) || 0;
    const { rows } = await pgPool.query(`SELECT user1_id,user2_id FROM couple_links WHERE id=$1 LIMIT 1`, [linkId]);
    const link = rows[0];
    if (!link) return res.status(404).send("Not found");
    if (!isCoupleMember(meId, link)) return res.status(403).send("Forbidden");

    await pgPool.query(`DELETE FROM couple_links WHERE id=$1`, [linkId]);
    emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId });
    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] unlink failed:", e?.message || e);
    return res.status(500).send("Could not unlink");
  }
});

app.post("/api/couples/prefs", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    const linkId = Number(req.body?.linkId) || 0;
    if (!linkId) return res.status(400).send("Bad request");
    const meId = Number(req.session.user?.id) || 0;

    const { rows } = await pgPool.query(`SELECT user1_id,user2_id FROM couple_links WHERE id=$1 LIMIT 1`, [linkId]);
    const link = rows[0];
    if (!link) return res.status(404).send("Not found");
    if (!isCoupleMember(meId, link)) return res.status(403).send("Forbidden");

    await pgUpsertCouplePrefs(linkId, meId, req.body?.prefs || {});
    emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId });
    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] prefs failed:", e?.message || e);
    return res.status(500).send("Could not update prefs");
  }
});

app.post("/api/couples/status", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    const linkId = Number(req.body?.linkId) || 0;
    if (!linkId) return res.status(400).send("Bad request");

    const meId = Number(req.session.user?.id) || 0;
    const { rows } = await pgPool.query(`SELECT user1_id,user2_id,status FROM couple_links WHERE id=$1 LIMIT 1`, [linkId]);
    const link = rows[0];
    if (!link) return res.status(404).send("Not found");
    if (link.status !== "active") return res.status(409).send("Not active");
    if (!isCoupleMember(meId, link)) return res.status(403).send("Forbidden");

    const emoji = String(req.body?.statusEmoji || "💜").trim().slice(0, 8) || "💜";
    const label = String(req.body?.statusLabel || "Linked").trim().slice(0, 20) || "Linked";
    const now = Date.now();

    await pgPool.query(
      `UPDATE couple_links SET status_emoji=$2, status_label=$3, updated_at=$4 WHERE id=$1`,
      [linkId, emoji, label, now]
    );
    emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId });

    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] status failed:", e?.message || e);
    return res.status(500).send("Could not update status");
  }
});

app.post("/api/couples/settings", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    if (!isCouplesV2EnabledFor(req.session.user)) return res.status(403).send("Forbidden");

    const link = await pgGetActiveCoupleLinkForUser(req.session.user.id);
    if (!link) return res.status(404).send("Not linked");
    if (!isCoupleMember(req.session.user.id, link)) return res.status(403).send("Forbidden");

    const privacyRaw = String(req.body?.privacy || "").trim().toLowerCase();
    const privacy = ["private", "friends", "public"].includes(privacyRaw) ? privacyRaw : undefined;
    const coupleName = typeof req.body?.couple_name === "string" ? String(req.body.couple_name).trim().slice(0, 48) : undefined;
    const coupleBio = typeof req.body?.couple_bio === "string" ? String(req.body.couple_bio).trim().slice(0, 220) : undefined;
    const showBadge = typeof req.body?.show_badge === "boolean" ? req.body.show_badge : undefined;
    const bonusesEnabled = typeof req.body?.bonuses_enabled === "boolean" ? req.body.bonuses_enabled : undefined;
    const now = Date.now();

    const sets = [];
    const vals = [];
    if (privacy) { sets.push(`privacy=$${vals.length + 1}`); vals.push(privacy); }
    if (coupleName !== undefined) { sets.push(`couple_name=$${vals.length + 1}`); vals.push(coupleName || null); }
    if (coupleBio !== undefined) { sets.push(`couple_bio=$${vals.length + 1}`); vals.push(coupleBio || null); }
    if (showBadge !== undefined) { sets.push(`show_badge=$${vals.length + 1}`); vals.push(showBadge); }
    if (bonusesEnabled !== undefined) { sets.push(`bonuses_enabled=$${vals.length + 1}`); vals.push(bonusesEnabled); }
    sets.push(`updated_at=$${vals.length + 1}`); vals.push(now);

    if (sets.length) {
      vals.push(link.id);
      await pgPool.query(`UPDATE couple_links SET ${sets.join(", ")} WHERE id=$${vals.length}`, vals);
    }

    emitToUserIds([link.user1_id, link.user2_id], "couples:update", { linkId: link.id });
    const summary = await pgGetCoupleSummaryFor(req.session.user);
    return res.json(summary);
  } catch (e) {
    console.warn("[couples] settings failed:", e?.message || e);
    return res.status(500).send("Could not update settings");
  }
});

const coupleNudgeCooldownMs = 60_000;
const coupleNudgeLastByUser = new Map(); // key: `${linkId}:${userId}` -> ts

app.post("/api/couples/nudge", strictLimiter, requireLogin, async (req, res) => {
  try {
    if (!PG_READY) return res.status(503).send("DB not ready");
    if (!COUPLES_READY) return res.status(503).send("Couples not ready");
    if (!isCouplesV2EnabledFor(req.session.user)) return res.status(403).send("Forbidden");

    const link = await pgGetActiveCoupleLinkForUser(req.session.user.id);
    if (!link) return res.status(404).send("Not linked");
    if (!isCoupleMember(req.session.user.id, link)) return res.status(403).send("Forbidden");

    const partnerId = getCouplePartnerId(req.session.user.id, link);
    if (!partnerId) return res.status(404).send("Partner not found");
    const prefsPartner = await pgGetCouplePrefs(link.id, partnerId);
    if (prefsPartner && prefsPartner.allow_ping === false) return res.status(403).send("Partner muted nudges");

    const key = `${link.id}:${req.session.user.id}`;
    const last = coupleNudgeLastByUser.get(key) || 0;
    if (Date.now() - last < coupleNudgeCooldownMs) return res.status(429).send("Slow down");
    coupleNudgeLastByUser.set(key, Date.now());

    emitToUserIds([partnerId], "couples:nudge", {
      fromId: req.session.user.id,
      fromName: req.session.user.username,
      linkId: link.id
    });
    return res.json({ ok: true });
  } catch (e) {
    console.warn("[couples] nudge failed:", e?.message || e);
    return res.status(500).send("Could not send nudge");
  }
});


// --- Friends API
app.get("/api/friends/requests", requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    if (!meId) return res.status(401).send("Not logged in");
    const rows = (PG_READY && FRIENDS_READY)
      ? await pgListIncomingFriendRequests(meId)
      : await dbListIncomingFriendRequests(meId);

    const payload = rows.map((r) => ({
      id: Number(r.id) || 0,
      createdAt: Number(r.created_at) || Date.now(),
      from: {
        id: Number(r.from_id) || null,
        username: r.from_username || r.username || null,
        avatar: (PG_READY && FRIENDS_READY) ? avatarUrlFromRow(r) : (r.avatar || null)
      }
    })).filter((x) => x.id && x.from?.username);

    return res.json({ incoming: payload });
  } catch (e) {
    console.warn('[friends] requests list failed:', e?.message || e);
    return res.status(500).send('Could not load requests');
  }
});

app.get("/api/friends/list", requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    if (!meId) return res.status(401).send("Not logged in");
    const rows = (PG_READY && FRIENDS_READY)
      ? await pgListFriendsForUser(meId)
      : await dbListFriendsForUser(meId);

    const friends = rows.map((r) => {
      const uid = Number(r.id) || Number(r.friend_user_id) || 0;
      const live = onlineState.get(uid);
      const online = !!socketIdByUserId.get(uid);
      return {
        id: uid,
        username: r.username,
        role: r.role,
        avatar: (PG_READY && FRIENDS_READY) ? avatarUrlFromRow(r) : (r.avatar || null),
        isFavorite: !!r.is_favorite,
        online,
        currentRoom: live?.room || null,
        lastSeen: r.last_seen || null,
        lastRoom: r.last_room || null,
        lastStatus: live?.status || r.last_status || null,
      };
    }).filter((f) => f.id && f.username);

    return res.json({ friends });
  } catch (e) {
    console.warn('[friends] list failed:', e?.message || e);
    return res.status(500).send('Could not load friends');
  }
});

app.post("/api/friends/request", strictLimiter, requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    const toName = String(req.body?.to || '').trim().slice(0, 64);
    const toUser = await findUserByUsername(toName);
    if (!toUser) return res.status(404).send('User not found');
    if (Number(toUser.id) === meId) return res.status(400).send('You cannot friend yourself');

    // Already friends?
    const already = (PG_READY && FRIENDS_READY)
      ? await pgAreFriends(meId, toUser.id)
      : await dbAreFriends(meId, toUser.id);
    if (already) return res.json({ ok: true, status: 'friends', autoAccepted: true });

    // If they already requested you, auto-accept
    const incoming = (PG_READY && FRIENDS_READY)
      ? await pgGetPendingFriendRequest(toUser.id, meId)
      : await dbGetPendingFriendRequest(toUser.id, meId);

    const now = Date.now();

    if (incoming?.id) {
      if (PG_READY && FRIENDS_READY) {
        await pgPool.query(`UPDATE friend_requests SET status='accepted', updated_at=$2 WHERE id=$1`, [incoming.id, now]);
        await pgCreateFriendsPair(meId, toUser.id);
      } else {
        await dbRunAsync(`UPDATE friend_requests SET status='accepted', updated_at=? WHERE id=?`, [now, incoming.id]);
        await dbCreateFriendsPair(meId, toUser.id);
      }

      // notify both
      const sOther = socketIdByUserId.get(Number(toUser.id));
      if (sOther) io.to(sOther).emit('friend:accepted', { username: req.session.user.username, by: req.session.user.username });
      const sMe = socketIdByUserId.get(meId);
      if (sMe) io.to(sMe).emit('friend:accepted', { username: toUser.username, by: req.session.user.username });

      return res.json({ ok: true, status: 'friends', autoAccepted: true });
    }

    // Existing outgoing pending?
    const outgoing = (PG_READY && FRIENDS_READY)
      ? await pgGetPendingFriendRequest(meId, toUser.id)
      : await dbGetPendingFriendRequest(meId, toUser.id);
    if (outgoing?.id) return res.json({ ok: true, status: 'pending', requestId: Number(outgoing.id) });

    let requestId = 0;
    if (PG_READY && FRIENDS_READY) {
      const { rows } = await pgPool.query(
        `INSERT INTO friend_requests(from_user_id, to_user_id, status, created_at, updated_at)
         VALUES ($1,$2,'pending',$3,$3)
         RETURNING id`,
        [meId, toUser.id, now]
      );
      requestId = Number(rows?.[0]?.id) || 0;
    } else {
      const r = await dbRunAsync(
        `INSERT INTO friend_requests(from_user_id, to_user_id, status, created_at, updated_at)
         VALUES (?,?, 'pending', ?, ?)`,
        [meId, toUser.id, now, now]
      );
      requestId = Number(r?.lastID) || 0;
    }

    // notify receiver (personalized flair via client notification)
    const sOther = socketIdByUserId.get(Number(toUser.id));
    if (sOther) {
      io.to(sOther).emit('friend:request', {
        requestId,
        from: {
          id: meId,
          username: req.session.user.username,
          avatar: await getAvatarUrlForUserId(meId),
        },
        createdAt: now,
      });
    }

    return res.json({ ok: true, status: 'pending', requestId });
  } catch (e) {
    console.warn('[friends] request failed:', e?.message || e);
    return res.status(500).send('Could not send request');
  }
});

app.post("/api/friends/respond", strictLimiter, requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    const requestId = Number(req.body?.requestId) || 0;
    const action = String(req.body?.action || '').toLowerCase();
    if (!requestId || !['accept','decline'].includes(action)) return res.status(400).send('Bad request');

    const now = Date.now();

    if (PG_READY && FRIENDS_READY) {
      const { rows } = await pgPool.query(`SELECT * FROM friend_requests WHERE id=$1 LIMIT 1`, [requestId]);
      const fr = rows[0];
      if (!fr) return res.status(404).send('Not found');
      if (String(fr.status) !== 'pending') return res.json({ ok: true, status: fr.status });
      if (Number(fr.to_user_id) !== meId) return res.status(403).send('Forbidden');

      if (action === 'accept') {
        await pgPool.query(`UPDATE friend_requests SET status='accepted', updated_at=$2 WHERE id=$1`, [requestId, now]);
        await pgCreateFriendsPair(fr.from_user_id, fr.to_user_id);
      } else {
        await pgPool.query(`UPDATE friend_requests SET status='declined', updated_at=$2 WHERE id=$1`, [requestId, now]);
      }

      const fromId = Number(fr.from_user_id) || 0;
      const fromUser = await pgGetUserById(fromId).catch(()=>null);
      const sFrom = socketIdByUserId.get(fromId);
      const sMe = socketIdByUserId.get(meId);
      if (action === 'accept') {
        if (sFrom) io.to(sFrom).emit('friend:accepted', { username: req.session.user.username, by: req.session.user.username });
        if (sMe && fromUser?.username) io.to(sMe).emit('friend:accepted', { username: fromUser.username, by: req.session.user.username });
      } else {
        if (sFrom) io.to(sFrom).emit('friend:declined', { username: req.session.user.username });
      }

      return res.json({ ok: true, status: action === 'accept' ? 'accepted' : 'declined' });
    }

    // SQLite fallback
    const fr = await dbGetAsync(`SELECT * FROM friend_requests WHERE id=? LIMIT 1`, [requestId]).catch(()=>null);
    if (!fr) return res.status(404).send('Not found');
    if (String(fr.status) !== 'pending') return res.json({ ok: true, status: fr.status });
    if (Number(fr.to_user_id) !== meId) return res.status(403).send('Forbidden');

    if (action === 'accept') {
      await dbRunAsync(`UPDATE friend_requests SET status='accepted', updated_at=? WHERE id=?`, [now, requestId]);
      await dbCreateFriendsPair(fr.from_user_id, fr.to_user_id);
    } else {
      await dbRunAsync(`UPDATE friend_requests SET status='declined', updated_at=? WHERE id=?`, [now, requestId]);
    }

    const sFrom = socketIdByUserId.get(Number(fr.from_user_id));
    if (action === 'accept') {
      if (sFrom) io.to(sFrom).emit('friend:accepted', { username: req.session.user.username, by: req.session.user.username });
    } else {
      if (sFrom) io.to(sFrom).emit('friend:declined', { username: req.session.user.username });
    }

    return res.json({ ok: true, status: action === 'accept' ? 'accepted' : 'declined' });
  } catch (e) {
    console.warn('[friends] respond failed:', e?.message || e);
    return res.status(500).send('Could not respond');
  }
});

app.post("/api/friends/favorite", strictLimiter, requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    const uname = String(req.body?.username || '').trim().slice(0,64);
    const other = await findUserByUsername(uname);
    if (!other) return res.status(404).send('User not found');
    const isFavorite = !!req.body?.isFavorite;

    if (PG_READY && FRIENDS_READY) {
      await pgPool.query(
        `UPDATE friends SET is_favorite=$3 WHERE user_id=$1 AND friend_user_id=$2`,
        [meId, other.id, isFavorite]
      );
    } else {
      await dbRunAsync(`UPDATE friends SET is_favorite=? WHERE user_id=? AND friend_user_id=?`, [isFavorite ? 1 : 0, meId, other.id]);
    }
    return res.json({ ok: true });
  } catch (e) {
    console.warn('[friends] favorite failed:', e?.message || e);
    return res.status(500).send('Could not update favorite');
  }
});

app.post("/api/friends/remove", strictLimiter, requireLogin, async (req, res) => {
  try {
    const meId = Number(req.session.user?.id) || 0;
    const uname = String(req.body?.username || '').trim().slice(0,64);
    const other = await findUserByUsername(uname);
    if (!other) return res.status(404).send('User not found');

    if (PG_READY && FRIENDS_READY) {
      await pgPool.query(`DELETE FROM friends WHERE (user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)`, [meId, other.id]);
    } else {
      await dbRunAsync(`DELETE FROM friends WHERE (user_id=? AND friend_user_id=?) OR (user_id=? AND friend_user_id=?)`, [meId, other.id, other.id, meId]);
    }
    // notify other (optional)
    const sOther = socketIdByUserId.get(Number(other.id));
    if (sOther) io.to(sOther).emit('friend:removed', { username: req.session.user.username });
    return res.json({ ok: true });
  } catch (e) {
    console.warn('[friends] remove failed:', e?.message || e);
    return res.status(500).send('Could not remove friend');
  }
});



app.post("/profile/:username/like", strictLimiter, requireLogin, async (req, res) => {
  const u = sanitizeUsername(req.params.username);
  if (!u) return res.status(400).send("Bad username");

  const target = await findUserByUsername(u);
  if (!target) return res.status(404).send("Not found");
  if (target.id === req.session.user.id) {
    return res.status(400).json({ ok: false, message: "You cannot like yourself." });
  }

  try {
    const stats = await toggleProfileLike(req.session.user.id, target.id);
    return res.json({
      ok: true,
      likes: stats.likes,
      liked: stats.liked,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, message: "Could not update like" });
  }
});

// Avatar upload for profile edits (2MB max, in-memory only)
const AVATAR_ALLOWED_MIME = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = AVATAR_ALLOWED_MIME.has(String(file.mimetype || "").toLowerCase());
    cb(ok ? null : new Error("Invalid avatar type"), ok);
  },
});

// IMPORTANT: Most of your app now reads profiles from Postgres (when the user exists there).
// The old version of this route only updated SQLite, so uploads "worked" but never showed up.
app.post("/profile", strictLimiter, requireLogin, (req, res) => {
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
    if (file) {
      const sniffed = sniffImageMime(file.buffer);
      if (!sniffed || !AVATAR_ALLOWED_MIME.has(sniffed)) {
        return res.status(400).json({ ok: false, message: "Invalid avatar content." });
      }
    }
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
app.delete("/profile/avatar", strictLimiter, requireLogin, async (req, res) => {
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

// ---- Uploads (25MB images/gifs, 100MB videos). VIP can upload videos, everyone can upload images.
const MAX_IMAGE_GIF_BYTES = 25 * 1024 * 1024;
const MAX_AUDIO_BYTES = 15 * 1024 * 1024;
const MAX_VIDEO_BYTES = 100 * 1024 * 1024;
const IMAGE_UPLOAD_ALLOWED_MIME = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const AUDIO_UPLOAD_ALLOWED_MIME = new Set(["audio/mpeg", "audio/mp4", "audio/aac"]);
const VIDEO_UPLOAD_ALLOWED_MIME = new Set(["video/mp4", "video/webm"]);
const AUDIO_UPLOAD_ALLOWED_EXT = new Set([".mp3", ".m4a", ".aac"]);
const IMAGE_UPLOAD_ALLOWED_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif"]);
const VIDEO_UPLOAD_ALLOWED_EXT = new Set([".mp4", ".webm"]);
const SAFE_UPLOAD_EXT_BY_MIME = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "audio/mpeg": ".mp3",
  "audio/mp4": ".m4a",
  "audio/aac": ".aac",
  "video/mp4": ".mp4",
  "video/webm": ".webm",
};

function inferUploadMimeFromName(originalname){
  const name = String(originalname || "").toLowerCase();
  const ext = (name.includes(".") ? name.split(".").pop() : "").slice(0, 10);
  switch(ext){
    case "mp3": return "audio/mpeg";
    case "m4a": return "audio/mp4";
    case "aac": return "audio/aac";
    case "wav": return "audio/wav";
    case "ogg":
    case "oga": return "audio/ogg";
    case "opus": return "audio/opus";
    case "webm": return "audio/webm";
    default: return "";
  }
}

function safeUploadExt(mime, originalname) {
  const ext = path.extname(originalname || "").toLowerCase();
  if (IMAGE_UPLOAD_ALLOWED_EXT.has(ext) || AUDIO_UPLOAD_ALLOWED_EXT.has(ext) || VIDEO_UPLOAD_ALLOWED_EXT.has(ext)) {
    return ext;
  }
  return SAFE_UPLOAD_EXT_BY_MIME[mime] || "";
}

function readFileHeader(filePath, length = 32) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, 0);
    fs.closeSync(fd);
    return buffer;
  } catch {
    return null;
  }
}

function sniffImageMime(buffer) {
  if (!buffer) return "";
  if (buffer.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) {
    return "image/png";
  }
  if (buffer.slice(0, 3).equals(Buffer.from([0xFF, 0xD8, 0xFF]))) return "image/jpeg";
  if (buffer.slice(0, 6).toString("ascii") === "GIF87a" || buffer.slice(0, 6).toString("ascii") === "GIF89a") {
    return "image/gif";
  }
  if (buffer.slice(0, 4).toString("ascii") === "RIFF" && buffer.slice(8, 12).toString("ascii") === "WEBP") {
    return "image/webp";
  }
  return "";
}

function sniffMp3(buffer) {
  if (!buffer) return false;
  if (buffer.slice(0, 3).toString("ascii") === "ID3") return true;
  return buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0;
}

function sniffAac(buffer) {
  if (!buffer) return false;
  return buffer[0] === 0xff && (buffer[1] & 0xf6) === 0xf0;
}

function sniffMp4Container(buffer) {
  if (!buffer) return false;
  return buffer.slice(4, 8).toString("ascii") === "ftyp";
}

function sniffWebm(buffer) {
  if (!buffer) return false;
  return buffer.slice(0, 4).equals(Buffer.from([0x1A, 0x45, 0xDF, 0xA3]));
}
const chatUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const ext = safeUploadExt(file.mimetype, file.originalname) || "";
      cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${ext}`);
    },
  }),
  limits: { fileSize: MAX_VIDEO_BYTES },
});

app.post("/upload", uploadLimiter, uploadUserLimiter, requireLogin, (req, res) => {
  chatUpload.single("file")(req, res, (err) => {
    if (err) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ message: "File too large (max 100MB)." });
      }
      return res.status(400).json({ message: err.message || "Upload failed." });
    }
    if (!req.file) return res.status(400).send("No file");

    const uploadKind = String(req.body?.uploadKind || "").trim();
    let mime = String(req.file.mimetype || "");
    if(!mime || mime === "application/octet-stream"){
      const inferred = inferUploadMimeFromName(req.file.originalname);
      if(inferred) mime = inferred;
    }
    const role = req.session.user.role;

    const isSvg = mime === "image/svg+xml";
    const isImage = IMAGE_UPLOAD_ALLOWED_MIME.has(mime);
    const isAudio = AUDIO_UPLOAD_ALLOWED_MIME.has(mime);
    const isVideo = VIDEO_UPLOAD_ALLOWED_MIME.has(mime);

    const cleanupUpload = () => {
      try { fs.unlinkSync(path.join(UPLOADS_DIR, req.file.filename)); } catch {}
    };

    if (isSvg || (!isImage && !isAudio && !isVideo)) {
      cleanupUpload();
      return res.status(400).json({ message: "File type not allowed" });
    }

    if (isAudio && uploadKind === "audio-upload") {
      const ext = path.extname(req.file.originalname || "").toLowerCase();
      const mimeAllowed = AUDIO_UPLOAD_ALLOWED_MIME.has(mime);
      const extAllowed = AUDIO_UPLOAD_ALLOWED_EXT.has(ext);
      if (!mimeAllowed || !extAllowed) {
        cleanupUpload();
        return res.status(400).json({ message: "Audio upload supports MP3, M4A, or AAC only." });
      }
    }

    if (isImage && !IMAGE_UPLOAD_ALLOWED_EXT.has(path.extname(req.file.originalname || "").toLowerCase())) {
      cleanupUpload();
      return res.status(400).json({ message: "Image type not allowed." });
    }

    const header = readFileHeader(path.join(UPLOADS_DIR, req.file.filename), 32);
    if (isImage) {
      const sniffed = sniffImageMime(header);
      if (!sniffed || !IMAGE_UPLOAD_ALLOWED_MIME.has(sniffed)) {
        cleanupUpload();
        return res.status(400).json({ message: "Image content invalid." });
      }
      mime = sniffed;
    }

    if (isAudio) {
      const isMp3 = sniffMp3(header);
      const isAac = sniffAac(header);
      const isMp4 = sniffMp4Container(header);
      if (!(isMp3 || isAac || isMp4)) {
        cleanupUpload();
        return res.status(400).json({ message: "Audio content invalid." });
      }
    }

    if (isVideo) {
      const isMp4 = sniffMp4Container(header);
      const isW = sniffWebm(header);
      if (!(isMp4 || isW)) {
        cleanupUpload();
        return res.status(400).json({ message: "Video content invalid." });
      }
    }

    if (isImage && req.file.size > MAX_IMAGE_GIF_BYTES) {
      cleanupUpload();
      return res.status(413).json({ message: "Image/GIF too large (max 25MB)." });
    }

    if (isAudio && req.file.size > MAX_AUDIO_BYTES) {
      cleanupUpload();
      return res.status(413).json({ message: "Audio too large (max 15MB)." });
    }

    if (isVideo && req.file.size > MAX_VIDEO_BYTES) {
      cleanupUpload();
      return res.status(413).json({ message: "Video too large (max 100MB)." });
    }

    if (isVideo && !requireMinRole(role, "VIP")) {
      cleanupUpload();
      return res.status(403).json({ message: "VIP required for video uploads" });
    }

    const url = `/uploads/${req.file.filename}`;
    const type = isImage ? "image" : (isAudio ? "audio" : "video");

    if (req.session?.user?.id) {
      const userHint = req.session.user;
      if (isAudio && uploadKind === "audio-upload") {
        void ensureMemory(req.session.user.id, "first_voice_note", {
          type: "media",
          title: "First voice note",
          description: "Sent your first voice note.",
          icon: "🎙️",
          metadata: { kind: "voice_note" },
        }, userHint);
      }
      if (isImage) {
        void ensureMemory(req.session.user.id, "first_image_upload", {
          type: "media",
          title: "First image upload",
          description: "Shared your first image.",
          icon: "🖼️",
          metadata: { kind: "image" },
        }, userHint);
      }
    }

    logSecurityEvent("upload", {
      ip: getClientIp(req),
      userId: req.session?.user?.id || null,
      username: req.session?.user?.username || null,
      type,
      mime,
      size: req.file.size,
    });

    return res.json({
      url,
      mime,
      size: req.file.size,
      type,
    });
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
            COALESCE(
              (SELECT id FROM dm_messages WHERE id=t.last_message_id AND deleted=0),
              (SELECT id FROM dm_messages WHERE thread_id=t.id AND deleted=0 ORDER BY ts DESC LIMIT 1)
            ) AS last_message_id,
            (SELECT text FROM dm_messages WHERE thread_id=t.id AND deleted=0 ORDER BY ts DESC LIMIT 1) AS last_text,
            COALESCE(
              (SELECT ts FROM dm_messages WHERE id=t.last_message_id AND deleted=0),
              t.last_message_at,
              (SELECT ts FROM dm_messages WHERE thread_id=t.id AND deleted=0 ORDER BY ts DESC LIMIT 1)
            ) AS last_ts,
            (SELECT COUNT(*) FROM dm_messages m
              WHERE m.thread_id = t.id
                AND m.deleted = 0
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

    // NOTE:
    // The client may pass BOTH `participants` (names) and `participantIds` for the SAME user.
    // If we derive group/direct from the raw request counts, a normal direct DM can be
    // misclassified as a group chat (e.g. 1 name + 1 id = 2 requestedCount).
    // Instead, determine group/direct based on the *resolved unique recipients*.
    //
    // Also: if the client explicitly requests a direct DM, honor that.
    const requestedKind = kindRaw === "group" ? "group" : (kindRaw === "direct" ? "direct" : "auto");

    try {
      const usersByName = await fetchUsersByNames(cleanedNames);
      if (usersByName.length !== cleanedNames.length) {
        const found = new Set((usersByName || []).map((u) => normKey(u.username)));
        const missing = cleanedNames.filter((n) => !found.has(normKey(n))).slice(0, 3);
        return res.status(404).send(missing.length ? `User not found: ${missing.join(", ")}` : "User not found");
      }

      const myId = req.session.user.id;
      const myName = req.session.user.username;

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

      // Determine group/direct from resolved recipients.
      const isGroup = (requestedKind === "group") || (requestedKind === "auto" && (recipients.length > 1 || !!title));

      if (requestedKind === "group" && recipients.length < 2) {
        return res.status(400).send("Group chats need 2+ participants (or a title)");
      }

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

      const threadParticipants = allParticipantIds;
      return resolveOrCreateThread(
        {
          participantIds: threadParticipants,
          isGroup,
          title,
          createdBy: myId,
        },
        (err3, info) => {
          if (err3) {
            console.error("[dm:create] resolve failed", err3);
            return res.status(500).send("Failed to create thread");
          }
          notifyParticipants(info.id, !info.created, isGroup, title || null);
        }
      );
    } catch (err) {
      console.error("[dm:create] failed", err);
      return res.status(500).send("Failed to create thread");
    }
  }

app.post("/dm/thread", dmLimiter, requireLogin, handleCreateDmThread);
app.post("/api/dm/thread", dmLimiter, requireLogin, handleCreateDmThread);

app.post("/dm/thread/:id/participants", dmLimiter, requireLogin, (req, res) => {
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

app.post("/dm/thread/:id/leave", dmLimiter, requireLogin, (req, res) => {
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

app.delete("/dm/thread/:id/messages", dmLimiter, requireLogin, (req, res) => {
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
  const loop = async () => {
    const now = Date.now();
    for (const [uid, track] of onlineXpTrack.entries()) {
      if (!onlineState.has(uid)) {
        onlineXpTrack.delete(uid);
        continue;
      }
      const lastTs = track.lastTs || now;
      const elapsed = Math.max(0, now - lastTs);
      const total = (track.carryMs || 0) + elapsed;
      const fullMinutes = Math.floor(total / 60_000);
      const cappedMinutes = Math.min(fullMinutes, 60);
      const carry = total - cappedMinutes * 60_000;
      onlineXpTrack.set(uid, { lastTs: now, carryMs: carry });
      if (cappedMinutes <= 0) continue;

      try {
        const row = await getProgressionRow(uid);
        if (!row) continue;
        const role = liveRoleForUser(uid, row.role);
        const rate = xpRatesForRole(role).online;
        const delta = Math.max(0, Math.floor(cappedMinutes * rate));
        if (delta > 0) {
          await applyXpGain(uid, delta, { baseRow: row, lastOnlineXpAt: now });
          console.log(`[xp][online] +${delta} user=${uid} mins=${cappedMinutes} role=${role}`);
        }
      } catch (e) {
        console.warn("[xp][online]", e?.message || e);
      }
    }

    for (const uid of onlineState.keys()) {
      awardPassiveGold(uid);
    }
  };
  loop().catch((e) => console.warn("[xp][online loop]", e?.message || e));
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


// ---- Kick/Ban restrictions (persistent) + Appeals
const KICK_LENGTH_OPTIONS = [
  { label: "1 week", seconds: 7 * 24 * 60 * 60 },
  { label: "5 days", seconds: 5 * 24 * 60 * 60 },
  { label: "3 days", seconds: 3 * 24 * 60 * 60 },
  { label: "2 days", seconds: 2 * 24 * 60 * 60 },
  { label: "1 day", seconds: 1 * 24 * 60 * 60 },
  { label: "12 hrs", seconds: 12 * 60 * 60 },
  { label: "8 hrs", seconds: 8 * 60 * 60 },
  { label: "3 hrs", seconds: 3 * 60 * 60 },
  { label: "2 hrs", seconds: 2 * 60 * 60 },
  { label: "1 hr", seconds: 60 * 60 },
  { label: "45m", seconds: 45 * 60 },
  { label: "30m", seconds: 30 * 60 },
  { label: "15m", seconds: 15 * 60 },
  { label: "10m", seconds: 10 * 60 },
  { label: "5min", seconds: 5 * 60 },
  { label: "1min", seconds: 60 },
];

function normalizeRestrictionType(t){
  const x = String(t || "").toLowerCase();
  if (x === "kick") return "kick";
  if (x === "ban") return "ban";
  return "none";
}

async function getRestrictionByUsername(username){
  const u = String(username || "").trim();
  if(!u) return { type:"none" };

  // PG first
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query(
        "SELECT restriction_type, reason, expires_at, set_at FROM user_restrictions WHERE lower(username)=lower($1) LIMIT 1",
        [u]
      );
      const r = rows?.[0];
      if (r) {
        const type = normalizeRestrictionType(r.restriction_type);
        const expiresAt = r.expires_at != null ? Number(r.expires_at) : null;
        if (type === "kick" && expiresAt && expiresAt <= Date.now()) {
          await clearRestrictionEverywhere(u, "system", "kick expired");
          return { type: "none" };
        }
        return { type, reason: r.reason || "", expiresAt: expiresAt || null, setAt: r.set_at ? Number(r.set_at) : null };
      }
      return { type: "none" };
    }
  } catch (e) {
    console.warn("[restriction][pg] get failed", e?.message || e);
  }

  // SQLite fallback
  try {
    const row = await dbGetAsync(
      "SELECT restriction_type, reason, expires_at, set_at FROM user_restrictions WHERE lower(username)=lower(?) LIMIT 1",
      [u]
    );
    if (!row) return { type:"none" };
    const type = normalizeRestrictionType(row.restriction_type);
    const expiresAt = row.expires_at != null ? Number(row.expires_at) : null;
    if (type === "kick" && expiresAt && expiresAt <= Date.now()) {
      await clearRestrictionEverywhere(u, "system", "kick expired");
      return { type:"none" };
    }
    return { type, reason: row.reason || "", expiresAt: expiresAt || null, setAt: row.set_at ? Number(row.set_at) : null };
  } catch (e) {
    console.warn("[restriction][sqlite] get failed", e?.message || e);
    return { type:"none" };
  }
}

async function logModerationAction({ targetUsername, actorUsername, actionType, reason, durationSeconds = null, expiresAt = null }){
  const now = Date.now();
  const tUser = String(targetUsername || "").trim();
  const aUser = actorUsername ? String(actorUsername) : null;
  const act = String(actionType || "").trim();
  const why = reason ? String(reason).slice(0, 600) : "";
  try {
    await dbRunAsync(
      `INSERT INTO moderation_actions (target_username, actor_username, action_type, reason, duration_seconds, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [tUser, aUser, act, why, durationSeconds, expiresAt, now]
    );
  } catch {}
  try {
    if (PG_READY) {
      await pgPool.query(
        `INSERT INTO moderation_actions (target_username, actor_username, action_type, reason, duration_seconds, expires_at, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [tUser, aUser, act, why, durationSeconds, expiresAt, now]
      );
    }
  } catch {}
}

async function upsertRestrictionEverywhere(username, { type, reason = "", setBy = "", expiresAt = null }){
  const u = String(username || "").trim();
  const now = Date.now();
  const t = normalizeRestrictionType(type);
  const exp = expiresAt != null ? Number(expiresAt) : null;

  // SQLite
  try {
    await dbRunAsync(
      `INSERT INTO user_restrictions (username, restriction_type, reason, set_by, set_at, expires_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(username) DO UPDATE SET
         restriction_type=excluded.restriction_type,
         reason=excluded.reason,
         set_by=excluded.set_by,
         set_at=excluded.set_at,
         expires_at=excluded.expires_at,
         updated_at=excluded.updated_at`,
      [u, t, String(reason || "").slice(0, 800), String(setBy || "").slice(0, 120), now, exp, now]
    );
  } catch (e) {
    console.warn("[restriction][sqlite] upsert failed", e?.message || e);
  }

  // PG
  try {
    if (PG_READY) {
      await pgPool.query(
        `INSERT INTO user_restrictions (username, restriction_type, reason, set_by, set_at, expires_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (username) DO UPDATE SET
           restriction_type=EXCLUDED.restriction_type,
           reason=EXCLUDED.reason,
           set_by=EXCLUDED.set_by,
           set_at=EXCLUDED.set_at,
           expires_at=EXCLUDED.expires_at,
           updated_at=EXCLUDED.updated_at`,
        [u, t, String(reason || "").slice(0, 800), String(setBy || "").slice(0, 120), now, exp, now]
      );
    }
  } catch (e) {
    console.warn("[restriction][pg] upsert failed", e?.message || e);
  }
}

async function clearRestrictionEverywhere(username, actorUsername = "system", reason = ""){
  await upsertRestrictionEverywhere(username, { type:"none", reason:"", setBy: actorUsername, expiresAt: null });
  await logModerationAction({ targetUsername: username, actorUsername, actionType: "unlock", reason });
}

async function setKickEverywhere(username, actorUsername, reason, durationSeconds){
  const dur = Math.max(60, Math.min(Number(durationSeconds) || 60, 7*24*60*60));
  const expiresAt = Date.now() + dur*1000;
  await upsertRestrictionEverywhere(username, { type:"kick", reason, setBy: actorUsername, expiresAt });
  await logModerationAction({ targetUsername: username, actorUsername, actionType: "kick", reason, durationSeconds: dur, expiresAt });
  return { expiresAt };
}

async function setBanEverywhere(username, actorUsername, reason){
  await upsertRestrictionEverywhere(username, { type:"ban", reason, setBy: actorUsername, expiresAt: null });
  await logModerationAction({ targetUsername: username, actorUsername, actionType: "ban", reason });
}

// Appeals
async function findOpenAppeal(username){
  const u = String(username || "").trim();
  if(!u) return null;
  // PG first
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query(
        "SELECT * FROM appeals WHERE lower(username)=lower($1) AND status='open' ORDER BY created_at DESC LIMIT 1",
        [u]
      );
      return rows?.[0] || null;
    }
  } catch {}
  try {
    const row = await dbGetAsync(
      "SELECT * FROM appeals WHERE lower(username)=lower(?) AND status='open' ORDER BY created_at DESC LIMIT 1",
      [u]
    );
    return row || null;
  } catch {
    return null;
  }
}

async function createAppeal(username, restrictionType, reasonAtTime){
  const now = Date.now();
  const u = String(username || "").trim();
  const t = normalizeRestrictionType(restrictionType);
  const r = String(reasonAtTime || "").slice(0, 800);
  // SQLite
  try {
    const res = await dbRunAsync(
      `INSERT INTO appeals (username, restriction_type, reason_at_time, status, created_at, updated_at, last_admin_reply_at, last_user_reply_at)
       VALUES (?, ?, ?, 'open', ?, ?, NULL, ?)`,
      [u, t === "ban" ? "ban" : "kick", r, now, now, now]
    );
    const appeal = { id: res.lastID, username: u, restriction_type: t, reason_at_time: r, status:"open", created_at: now, updated_at: now };
    try {
      const subjectUserId = await findUserIdByUsername(u);
      const caseRow = await createModCase({
        type: "appeal",
        subjectUserId,
        createdByUserId: subjectUserId,
        title: `Appeal #${appeal.id}`,
        summary: r,
      });
      if (caseRow?.id) {
        await addModCaseEvent(caseRow.id, { actorUserId: subjectUserId, eventType: "appeal_created", payload: { appealId: appeal.id } });
        emitToStaff("mod:case_created", { id: caseRow.id, type: caseRow.type, status: caseRow.status });
      }
    } catch {}
    return appeal;
  } catch (e) {
    // If it failed (maybe due to partial unique index in PG only), just fall back to find open
  }
  // PG
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query(
        `INSERT INTO appeals (username, restriction_type, reason_at_time, status, created_at, updated_at, last_admin_reply_at, last_user_reply_at)
         VALUES ($1,$2,$3,'open',$4,$5,NULL,$6)
         RETURNING *`,
        [u, t === "ban" ? "ban" : "kick", r, now, now, now]
      );
      const appeal = rows?.[0] || null;
      if (appeal?.id) {
        try {
          const subjectUserId = await findUserIdByUsername(u);
          const caseRow = await createModCase({
            type: "appeal",
            subjectUserId,
            createdByUserId: subjectUserId,
            title: `Appeal #${appeal.id}`,
            summary: r,
          });
          if (caseRow?.id) {
            await addModCaseEvent(caseRow.id, { actorUserId: subjectUserId, eventType: "appeal_created", payload: { appealId: appeal.id } });
            emitToStaff("mod:case_created", { id: caseRow.id, type: caseRow.type, status: caseRow.status });
          }
        } catch {}
      }
      return appeal;
    }
  } catch {}
  return await findOpenAppeal(u);
}

async function addAppealMessage(appealId, { authorRole, authorName, message }){
  const now = Date.now();
  const msg = String(message || "").trim().slice(0, 2000);
  if (!msg) return;
  const role = authorRole === "admin" ? "admin" : "user";
  const name = authorName ? String(authorName).slice(0, 120) : null;

  // SQLite
  try {
    await dbRunAsync(
      `INSERT INTO appeal_messages (appeal_id, author_role, author_name, message, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [appealId, role, name, msg, now]
    );
    await dbRunAsync(
      `UPDATE appeals SET updated_at=?, ${role === "admin" ? "last_admin_reply_at" : "last_user_reply_at"}=? WHERE id=?`,
      [now, now, appealId]
    );
  } catch {}

  // PG
  try {
    if (PG_READY) {
      await pgPool.query(
        `INSERT INTO appeal_messages (appeal_id, author_role, author_name, message, created_at)
         VALUES ($1,$2,$3,$4,$5)`,
        [appealId, role, name, msg, now]
      );
      const col = role === "admin" ? "last_admin_reply_at" : "last_user_reply_at";
      await pgPool.query(`UPDATE appeals SET updated_at=$1, ${col}=$2 WHERE id=$3`, [now, now, appealId]);
    }
  } catch {}
}

async function getAppealThread(appealId){
  // PG first
  try {
    if (PG_READY) {
      const { rows: msgs } = await pgPool.query(
        "SELECT * FROM appeal_messages WHERE appeal_id=$1 ORDER BY created_at ASC",
        [appealId]
      );
      return msgs || [];
    }
  } catch {}
  try {
    return await dbAllAsync(
      "SELECT * FROM appeal_messages WHERE appeal_id=? ORDER BY created_at ASC",
      [appealId]
    );
  } catch {
    return [];
  }
}

async function listOpenAppeals(){
  // PG first
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query(
        "SELECT * FROM appeals WHERE status='open' ORDER BY updated_at DESC LIMIT 200"
      );
      return rows || [];
    }
  } catch {}
  try {
    return await dbAllAsync("SELECT * FROM appeals WHERE status='open' ORDER BY updated_at DESC LIMIT 200");
  } catch {
    return [];
  }
}

async function getModerationLogsForUser(username, limit=200){
  const u = String(username || "").trim();
  const lim = Math.max(10, Math.min(Number(limit)||200, 500));
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query(
        "SELECT * FROM moderation_actions WHERE lower(target_username)=lower($1) ORDER BY created_at DESC LIMIT $2",
        [u, lim]
      );
      return rows || [];
    }
  } catch {}
  try {
    return await dbAllAsync(
      "SELECT * FROM moderation_actions WHERE lower(target_username)=lower(?) ORDER BY created_at DESC LIMIT ?",
      [u, lim]
    );
  } catch {
    return [];
  }
}

function getSocketIp(socket) {
  const xfwd = String(socket.handshake.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xfwd || socket.handshake.address || "";
}

function allowSocketEvent(socket, key, limit, windowMs) {
  const now = Date.now();
  let perSocket = socketEventRate.get(socket.id);
  if (!perSocket) {
    perSocket = new Map();
    socketEventRate.set(socket.id, perSocket);
  }
  const state = perSocket.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + windowMs;
  }
  state.count += 1;
  perSocket.set(key, state);
  return state.count <= limit;
}

function trackSocketConnection(ip) {
  const now = Date.now();
  const state = socketConnByIp.get(ip) || { count: 0, lastSeen: now };
  if (now - state.lastSeen > SOCKET_CONN_TTL_MS) {
    state.count = 0;
  }
  state.count += 1;
  state.lastSeen = now;
  socketConnByIp.set(ip, state);
  return state.count;
}

function releaseSocketConnection(ip) {
  const state = socketConnByIp.get(ip);
  if (!state) return;
  state.count = Math.max(0, state.count - 1);
  state.lastSeen = Date.now();
  if (!state.count) socketConnByIp.delete(ip);
}

// ---- Socket auth middleware (session)
io.use((socket, next) => {
  const origin = String(socket.handshake.headers.origin || "");
  const hostHeader = String(socket.handshake.headers.host || "");
  if (!origin) {
    if (IS_PROD) return next(new Error("Origin required"));
  } else if (!isAllowedOrigin(origin, hostHeader)) {
    return next(new Error("Origin not allowed"));
  }
  return next();
});

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

function broadcastDmTyping(threadId) {
  const tid = Number(threadId);
  if (!Number.isInteger(tid)) return;
  const set = dmTypingByThread.get(tid);
  const names = set ? Array.from(set) : [];
  io.to(`dm:${tid}`).emit("dm typing update", { threadId: tid, names });
}

function emitOnlineUsers() {
  try {
    io.emit("onlineUsers", Array.from(ONLINE_USERS));
  } catch {}
}


function roleRank(role) {
  // Keep consistent with requireMinRole ordering
  const order = ["Guest", "User", "VIP", "Moderator", "Admin", "Co-owner", "Owner"];
  const idx = order.indexOf(String(role || "User"));
  return idx === -1 ? 1 : idx;
}

function parseSmartMentionKinds(text) {
  const t = String(text || "").toLowerCase();
  const kinds = new Set();
  if (t.includes("@here")) kinds.add("here");
  if (t.includes("@mods")) kinds.add("mods");
  if (t.includes("@admins")) kinds.add("admins");
  if (t.includes("@staff")) kinds.add("staff");
  if (t.includes("@owner")) kinds.add("owner");
  return Array.from(kinds);
}

function emitSmartMentionPings({ room, fromUser, messageId, text }) {
  const kinds = parseSmartMentionKinds(text);
  if (!kinds.length) return;

  const now = Date.now();
  const uid = fromUser?.id;
  const last = lastMentionByUserId.get(uid) || 0;
  if (now - last < 5000) {
    bumpHeat(uid, 1); // spammy mentions
    return; // cooldown
  }
  lastMentionByUserId.set(uid, now);

  // @here only pings users currently in the same room
  const sockets = Array.from(io.sockets.sockets.values());
  for (const s of sockets) {
    try {
      if (!s?.user?.id) continue;
      if (s.id === fromUser?.socketId) continue;
      const inRoom = room && s.rooms?.has(room);
      if (!inRoom) continue;

      const r = String(s.user.role || "User");
      const rr = roleRank(r);

      for (const kind of kinds) {
        let ok = false;
        if (kind === "here") ok = true;
        else if (kind === "mods") ok = rr >= roleRank("Moderator");
        else if (kind === "admins") ok = rr >= roleRank("Admin");
        else if (kind === "staff") ok = rr >= roleRank("Moderator");
        else if (kind === "owner") ok = rr >= roleRank("Owner");
        if (!ok) continue;

        s.emit("mention:ping", {
          kind,
          room,
          messageId: messageId || null,
          from: { id: fromUser?.id, username: fromUser?.username || "" },
          at: now,
        });
      }
    } catch {}
  }
}


function updateLiveUsername(userId, newUsername) {
  const sid = socketIdByUserId.get(userId);
  const s = sid ? io.sockets.sockets.get(sid) : null;
  if (!s?.user) return;

  const oldUsername = s.user.username;
  if (oldUsername && oldUsername !== newUsername) {
    ONLINE_USERS.delete(oldUsername);
  }
  s.user.username = newUsername;
  if (s.request?.session?.user) {
    s.request.session.user.username = newUsername;
    s.request.session.save?.(() => {});
  }
  if (newUsername) ONLINE_USERS.add(newUsername);

  // Replace any live typing indicators so the UI updates immediately.
  for (const set of typingByRoom.values()) {
    if (oldUsername && set.has(oldUsername)) {
      set.delete(oldUsername);
      set.add(newUsername);
    }
  }

  for (const set of dmTypingByThread.values()) {
    if (oldUsername && set.has(oldUsername)) {
      set.delete(oldUsername);
      set.add(newUsername);
    }
  }

  emitOnlineUsers();
  if (s.currentRoom) emitUserList(s.currentRoom);
  io.to(sid).emit("profile:update", { username: newUsername });
}

async function emitUserList(room) {
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
        chatFx: mergeChatFxWithCustomization(s.user.chatFx, s.user.customization, s.user.textStyle),
        customization: sanitizeCustomization(s.user.customization, s.user.textStyle),
      });
    }
  }

  // Sort by role then name
  const lurkWeight = (status) => normalizeStatus(status, "Online") === "Lurking" ? 1 : 0;
  // Attach couple display info (opt-in) for users in this room
  try {
    if (PG_READY && users.length) {
      const ids = users.map(u => Number(u.id) || 0).filter(Boolean);
      if (ids.length) {
        const { rows: couples } = await pgPool.query(
          `
          SELECT cl.id AS link_id,
                 cl.user1_id, cl.user2_id,
                 cl.status_emoji, cl.status_label,
                 cl.show_badge,
                 cl.activated_at, cl.created_at,
                 u1.username AS user1_name,
                 u2.username AS user2_name,
                 p1.enabled AS p1_enabled, p1.show_members AS p1_show_members, p1.group_members AS p1_group_members, p1.aura AS p1_aura, p1.badge AS p1_badge,
                 p2.enabled AS p2_enabled, p2.show_members AS p2_show_members, p2.group_members AS p2_group_members, p2.aura AS p2_aura, p2.badge AS p2_badge
            FROM couple_links cl
            JOIN users u1 ON u1.id = cl.user1_id
            JOIN users u2 ON u2.id = cl.user2_id
            LEFT JOIN couple_prefs p1 ON p1.link_id = cl.id AND p1.user_id = cl.user1_id
            LEFT JOIN couple_prefs p2 ON p2.link_id = cl.id AND p2.user_id = cl.user2_id
           WHERE cl.status='active'
             AND (cl.user1_id = ANY($1::int[]) OR cl.user2_id = ANY($1::int[]))
          `,
          [ids]
        );

        const byId = new Map(users.map(u => [Number(u.id) || 0, u]));
        for (const c of couples) {
          const a = Number(c.user1_id) || 0;
          const b = Number(c.user2_id) || 0;
          if (!byId.has(a) || !byId.has(b)) continue; // only if both are in this room list

          const prefsA = { enabled: !!c.p1_enabled, showMembers: !!c.p1_show_members, groupMembers: !!c.p1_group_members, aura: !!c.p1_aura, badge: !!c.p1_badge };
          const prefsB = { enabled: !!c.p2_enabled, showMembers: !!c.p2_show_members, groupMembers: !!c.p2_group_members, aura: !!c.p2_aura, badge: !!c.p2_badge };
          if (!canShowCoupleFeature(prefsA, prefsB, "members")) continue;

          const base = {
            linkId: Number(c.link_id) || null,
            since: Number(c.activated_at || c.created_at) || null,
            statusEmoji: c.status_emoji || "💜",
            statusLabel: c.status_label || "Linked",
          };

          const uA = byId.get(a);
          const uB = byId.get(b);

          uA.couple = {
            ...base,
            partner: c.user2_name,
            badge: canShowCoupleBadge(prefsA, prefsB, c),
            aura: canShowCoupleFeature(prefsA, prefsB, "aura"),
            group: canShowCoupleFeature(prefsA, prefsB, "group"),
          };
          uB.couple = {
            ...base,
            partner: c.user1_name,
            badge: canShowCoupleBadge(prefsA, prefsB, c),
            aura: canShowCoupleFeature(prefsA, prefsB, "aura"),
            group: canShowCoupleFeature(prefsA, prefsB, "group"),
          };
        }
      }
    }
  } catch {}


  users.sort((a, b) => {
    const lb = lurkWeight(a.status) - lurkWeight(b.status);
    if (lb !== 0) return lb;
    const ra = roleRank(a.role);
    const rb = roleRank(b.role);
    if (ra !== rb) return rb - ra;
    return a.name.localeCompare(b.name);
  });
  // If both opted-in, pull couples together in the list (keeps existing sort priority otherwise)
  try {
    const seen = new Set();
    const byName = new Map(users.map(u => [u.name, u]));
    const out = [];
    for (const u of users) {
      if (seen.has(u.name)) continue;
      out.push(u);
      seen.add(u.name);
      const c = u.couple;
      if (c && c.group && c.partner && byName.has(c.partner) && !seen.has(c.partner)) {
        const partnerUser = byName.get(c.partner);
        if (partnerUser && roleRank(partnerUser.role) === roleRank(u.role)) {
          out.push(partnerUser);
          seen.add(c.partner);
        }
      }
    }
    if (out.length === users.length) users.splice(0, users.length, ...out);
  } catch {}


  io.to(room).emit("user list", users);
}

// ---- Luck system: qualifying message handling (server-authoritative)
async function applyLuckForQualifyingMessage({ userId, room, text }) {
  if (!userId || room === "diceroom") return;
  const trimmed = String(text || "").trim();
  if (trimmed.length < LUCK_MESSAGE_MIN_LEN) return;

  const normalized = normalizeLuckMessage(trimmed);
  if (!normalized) return;

  const now = Date.now();
  const msgHash = hashLuckMessage(normalized);

  try {
    if (await pgUserExists(userId)) {
      const row = await pgGetUserRowById(userId, [
        "luck",
        "roll_streak",
        "last_qual_msg_hash",
        "last_qual_msg_at",
      ]);
      if (!row) return;
      const lastHash = row.last_qual_msg_hash || null;
      const lastAt = Number(row.last_qual_msg_at || 0);
      if (lastHash && lastHash === msgHash && now - lastAt < LUCK_REPEAT_WINDOW_MS) return;

      const count = getQualifyingMessageCount(userId, now);
      const gain = computeQualifyingLuckGain(count);
      recordQualifyingMessage(userId, now);

      const nextLuck = clampLuck(Number(row.luck || 0) + gain);
      const nextStreak = 0;
      await pgPool.query(
        `UPDATE users
           SET luck = $1,
               roll_streak = $2,
               last_qual_msg_hash = $3,
               last_qual_msg_at = $4
         WHERE id = $5`,
        [nextLuck, nextStreak, msgHash, now, userId]
      );
      emitLuckUpdate(userId, nextLuck, nextStreak);
      return;
    }
  } catch (e) {
    console.warn("[luck][pg] qualifying message failed:", e?.message || e);
  }

  try {
    const row = await dbGetAsync(
      "SELECT luck, roll_streak, last_qual_msg_hash, last_qual_msg_at FROM users WHERE id = ?",
      [userId]
    );
    if (!row) return;
    const lastHash = row.last_qual_msg_hash || null;
    const lastAt = Number(row.last_qual_msg_at || 0);
    if (lastHash && lastHash === msgHash && now - lastAt < LUCK_REPEAT_WINDOW_MS) return;

    const count = getQualifyingMessageCount(userId, now);
    const gain = computeQualifyingLuckGain(count);
    recordQualifyingMessage(userId, now);

    const nextLuck = clampLuck(Number(row.luck || 0) + gain);
    const nextStreak = 0;
    await dbRunAsync(
      "UPDATE users SET luck = ?, roll_streak = ?, last_qual_msg_hash = ?, last_qual_msg_at = ? WHERE id = ?",
      [nextLuck, nextStreak, msgHash, now, userId]
    );
    emitLuckUpdate(userId, nextLuck, nextStreak);
  } catch (e) {
    console.warn("[luck][sqlite] qualifying message failed:", e?.message || e);
  }
}

async function emitLuckStateToSocket(socket) {
  const uid = Number(socket?.user?.id || 0);
  if (!uid) return;
  try {
    if (await pgUserExists(uid)) {
      const row = await pgGetUserRowById(uid, ["luck", "roll_streak"]);
      if (!row) return;
      socket.emit("luck:update", {
        luck: Number(row.luck || 0),
        rollStreak: Number(row.roll_streak || 0),
        ts: Date.now(),
      });
      return;
    }
  } catch (e) {
    console.warn("[luck][pg] state fetch failed:", e?.message || e);
  }
  try {
    const row = await dbGetAsync("SELECT luck, roll_streak FROM users WHERE id = ?", [uid]);
    if (!row) return;
    socket.emit("luck:update", {
      luck: Number(row.luck || 0),
      rollStreak: Number(row.roll_streak || 0),
      ts: Date.now(),
    });
  } catch (e) {
    console.warn("[luck][sqlite] state fetch failed:", e?.message || e);
  }
}

function applyLuckForRoll({ luck, rollStreak, lastQualMsgAt, userId, now }) {
  const nextStreak = Number(rollStreak || 0) + 1;
  let nextLuck = Number(luck || 0);

  const streakPenalty = computeRollStreakPenalty(nextStreak);
  if (streakPenalty) nextLuck -= streakPenalty;

  if (isCadenceFlagged(userId, now, nextStreak, lastQualMsgAt)) {
    nextLuck -= LUCK_CADENCE_PENALTY;
  }

  nextLuck = clampLuck(nextLuck);
  return { nextLuck, nextStreak };
}

// ---- Socket handlers
io.on("connection", async (socket) => {
  const sessUser = socket.request.session?.user;
  if (!sessUser?.id) {
    socket.disconnect(true);
    return;
  }

  const socketIp = getSocketIp(socket);
  if (socketIp) {
    const count = trackSocketConnection(socketIp);
    if (count > MAX_SOCKET_CONN_PER_IP) {
      socket.emit("system", buildSystemPayload("__global__", "Too many active connections. Try again shortly.", { kind: "global" }));
      socket.disconnect(true);
      return;
    }
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
    chatFx: sanitizeChatFx(sessUser.chatFx),
    textStyle: sanitizeTextStyle(sessUser.textStyle),
    customization: sanitizeCustomization(sessUser.customization, sessUser.textStyle),
  };

  // --- Owner session map: register basic meta
  try {
    const uid = socket.user?.id;
    const set = sessionByUserId.get(uid) || new Set();
    set.add(socket.id);
    sessionByUserId.set(uid, set);

    sessionMetaBySocketId.set(socket.id, {
      userId: uid,
      username: socket.user?.username || "",
      role: socket.user?.role || "",
      room: null,
      connectedAt: Date.now(),
      userAgent: String(socket.request?.headers?.["user-agent"] || ""),
      ip: socketIp || "",
      tz: null,
      locale: null,
      platform: null,
    });
  } catch {}

  socket.on("client:hello", (info = {}) => {
    try {
      const meta = sessionMetaBySocketId.get(socket.id) || {};
      meta.tz = info.tz ? String(info.tz).slice(0, 64) : meta.tz;
      meta.locale = info.locale ? String(info.locale).slice(0, 32) : meta.locale;
      meta.platform = info.platform ? String(info.platform).slice(0, 64) : meta.platform;
      meta.lastSeenAt = Date.now();
      sessionMetaBySocketId.set(socket.id, meta);
    } catch {}
  });

  socket.on("luck:get", () => {
    void emitLuckStateToSocket(socket);
  });

  socket.on("disconnect", () => {
    try {
      sessionMetaBySocketId.delete(socket.id);
      const uid = socket.user?.id;
      const set = sessionByUserId.get(uid);
      if (set) {
        set.delete(socket.id);
        if (!set.size) sessionByUserId.delete(uid);
      }
    } catch {}
  });





  // --- Enforce kick/ban restrictions immediately on connect (before presence/auto-join)
  socket.restriction = { type: "none" };
  try {
    const r = await getRestrictionByUsername(socket.user.username);
    socket.restriction = r || { type: "none" };
    if (r?.type && r.type !== "none") {
      io.to(socket.id).emit("restriction:status", {
        type: r.type,
        reason: r.reason || "",
        expiresAt: r.expiresAt || null,
        now: Date.now(),
      });
    }
  } catch {}

  // Track global online usernames (for private theme "together online" effects)
  if (socket.user?.username && (socket.restriction?.type === "none" || !socket.restriction?.type)) {
    ONLINE_USERS.add(socket.user.username);
  }
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
  primeOnlineXpTracker(socket.user.id);
  initGoldTick(socket.user.id);

// Load profile bits for presence (PG-first, SQLite fallback) + refresh member list when ready
(async () => {
  try {
    if (await pgUserExists(socket.user.id)) {
      const { rows } = await pgPool.query(
        "SELECT avatar, avatar_updated, mood, vibe_tags, prefs_json FROM users WHERE id=$1 LIMIT 1",
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
        const prefs = safeJsonParse(r?.prefs_json, {});
        socket.user.chatFx = sanitizeChatFx(prefs?.chatFx);
        socket.user.textStyle = sanitizeTextStyle(prefs?.textStyle);
        socket.user.customization = sanitizeCustomization(prefs?.customization, prefs?.textStyle);
        if (socket.currentRoom) emitUserList(socket.currentRoom);
      }
      return;
    }
  } catch (e) {
    console.warn("[presence][pg] failed:", e?.message || e);
  }

  db.get(
    "SELECT avatar, mood, vibe_tags, prefs_json FROM users WHERE id = ?",
    [socket.user.id],
    (_e, row) => {
      if (row) {
        const computedAvatar = avatarUrlFromRow(row);
        if (computedAvatar) socket.user.avatar = computedAvatar;
        if (typeof row.mood === "string") socket.user.mood = row.mood;
        socket.user.vibe_tags = sanitizeVibeTags(row.vibe_tags || []);
        const prefs = safeJsonParse(row?.prefs_json, {});
        socket.user.chatFx = sanitizeChatFx(prefs?.chatFx);
        socket.user.textStyle = sanitizeTextStyle(prefs?.textStyle);
        socket.user.customization = sanitizeCustomization(prefs?.customization, prefs?.textStyle);
        if (socket.currentRoom) emitUserList(socket.currentRoom);
      }
    }
  );
})();

  socket.currentRoom = null;
  socket.data.currentRoom = null;
    // --- SAFETY: ensure user is always in a room so messages can appear
  // If client fails to emit "join room" (mobile / reconnect / race), auto-join main.
  // IMPORTANT: never auto-join if the user is kicked/banned.
  setTimeout(() => {
    if (!socket.currentRoom && (socket.restriction?.type === "none" || !socket.restriction?.type)) {
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
  if (socket.restriction?.type && socket.restriction.type !== "none") {
    io.to(socket.id).emit("restriction:status", {
      type: socket.restriction.type,
      reason: socket.restriction.reason || "",
      expiresAt: socket.restriction.expiresAt || null,
      now: Date.now(),
    });
    return;
  }
const desired = sanitizeRoomName(room) || "main";

// VIP rooms: names prefixed with vip_ or vip- are only visible/accessible to VIP+ with level >= 25
const desiredIsVip = /^vip[_-]/i.test(desired);
const enforceVipGate = (roomName, cb) => {
  if(!desiredIsVip) return cb(true);
  const roleOk = isVipPlus(sessUser.role);
  if(!roleOk) return cb(false);
  db.get(`SELECT level FROM users WHERE id=? LIMIT 1`, [sessUser.id], (_e, urow) => {
    const lvl = Number(urow?.level || 0);
    cb(lvl >= 25);
  });
};

enforceVipGate(desired, (allowed) => {
  if(!allowed){
    try {
      socket.emit("system", buildSystemPayload("__global__", "That VIP room is locked (VIP + level 25 required).", { kind: "global" }));
    } catch(_){}
    return db.get(`SELECT name FROM rooms WHERE name=?`, ["main"], (_err2, row2) => doJoin(row2 ? "main" : "main", status));
  }

  db.get(
  `SELECT name, vip_only, staff_only, min_level, is_locked, maintenance_mode, archived FROM rooms WHERE name=?`,
  [desired],
  (_err, row) => {
    if (!row) return doJoin("main", status);

    // Enforce room visibility gates
    if (!canAccessRoomBySettings(sessUser, row)) {
      try { socket.emit("system", buildSystemPayload("__global__", "You don't have access to that room.", { kind: "global" })); } catch (_) {}
      return doJoin("main", status);
    }

    // Maintenance gate: Admin+ only
    if (Number(row.maintenance_mode || 0) === 1 && roleRankServer(sessUser.role) < roleRankServer("Admin")) {
      try { socket.emit("system", buildSystemPayload("__global__", "That room is in maintenance.", { kind: "global" })); } catch (_) {}
      return doJoin("main", status);
    }

    if (Number(row.archived || 0) === 1) {
      try { socket.emit("system", buildSystemPayload("__global__", "That room is archived.", { kind: "global" })); } catch (_) {}
      return doJoin("main", status);
    }

    // Locked gate: Mod+ only
    if (Number(row.is_locked || 0) === 1 && roleRankServer(sessUser.role) < roleRankServer("Moderator")) {
      try { socket.emit("system", buildSystemPayload("__global__", "That room is locked.", { kind: "global" })); } catch (_) {}
      return doJoin("main", status);
    }

    doJoin(desired, status);
  }
);
});

      });

  // Dice Room mini-game
  socket.on("dice:roll", (payload = {}) => {
    const room = socket.currentRoom;
    const requestedRoom = typeof payload.room === "string" ? sanitizeRoomName(payload.room) : null;
    if (requestedRoom && requestedRoom !== room) {
      socket.emit("dice:error", "Invalid room for dice roll.");
      return;


    }
    if (room !== "diceroom") {
      socket.emit("dice:error", "You can only roll dice in Dice Room.");
      return;
    }

    const variant = normalizeDiceVariant(payload.variant);
    if (!variant || !DICE_VARIANTS.includes(variant)) {
      socket.emit("dice:error", "Invalid dice variant.");
      return;
    }

    const now = Date.now();
    const uid = socket.user.id;
    const lastLocal = diceRollRateByUserId.get(uid) || 0;
    if (now - lastLocal < DICE_ROLL_MIN_INTERVAL_MS) {
      socket.emit(
        "dice:error",
        `Roll available in ${Math.ceil((DICE_ROLL_MIN_INTERVAL_MS - (now - lastLocal)) / 1000)}s.`
      );
      return;
    }
    diceRollRateByUserId.set(uid, now);

    const formatDiceSystemMessage = ({ result, breakdown, deltaGold, outcome } = {}) => {
      const faceMap = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
      let display = String(result);
      if (variant === "d6") {
        display = faceMap[Number(result) - 1] || result;
      } else if (variant === "2d6" && Array.isArray(breakdown)) {
        display = `${result} (2d6: ${breakdown.join("+")})`;
      } else {
        display = `${result} (${DICE_VARIANT_LABELS[variant] || variant})`;
      }
      const dg = Number(deltaGold || 0);
      const sign = dg >= 0 ? "+" : "";
      const emoji = outcome === "jackpot" ? "💥" : outcome === "bigwin" ? "🎉" : outcome === "win" ? "✨" : outcome === "nice" ? "😏" : "🎲";
      return `${socket.user.username} rolled ${display} ${emoji} (${sign}${dg} Gold)`;
    };

    (async () => {
      try {
        if (await pgUserExists(uid)) {
          const row = await pgGetUserRowById(uid, [
            "gold",
            "lastDiceRollAt",
            "luck",
            "roll_streak",
            "last_qual_msg_at",
          ]);
          if (!row) {
            socket.emit("dice:error", "Could not roll dice right now.");
            return;
          }

          const last = Number(row.lastDiceRollAt || 0);
          if (now - last < DICE_ROLL_MIN_INTERVAL_MS) {
            socket.emit(
              "dice:error",
              `Roll available in ${Math.ceil((DICE_ROLL_MIN_INTERVAL_MS - (now - last)) / 1000)}s.`
            );
            return;
          }

          const gold = Number(row.gold || 0);
          const luckState = applyLuckForRoll({
            luck: row.luck,
            rollStreak: row.roll_streak,
            lastQualMsgAt: row.last_qual_msg_at,
            userId: uid,
            now,
          });
          const roll = rollDiceVariantWithLuck(variant, luckState.nextLuck);
          const reward = computeDiceReward(variant, roll.result, roll.breakdown);
          if (gold < (reward.minBalanceRequired || 0)) {
            socket.emit(
              "dice:error",
              `You need at least ${reward.minBalanceRequired || 0} Gold to roll ${DICE_VARIANT_LABELS[variant] || variant}.`
            );
            return;
          }

          const deltaGold = Number(reward.deltaGold || 0);
          const breakdownArr = Array.isArray(roll.breakdown) ? roll.breakdown : [];
          const sixGain =
            variant === "d6" ? (roll.result === 6 ? 1 : 0) : variant === "2d6" ? breakdownArr.filter((n) => n === 6).length : 0;
          const didWinForLuck = isLuckWin(variant, roll.result, roll.breakdown);
          const finalLuck = clampLuck(applyWinCut(luckState.nextLuck, didWinForLuck));

          await pgPool.query(
            `UPDATE users
               SET gold = GREATEST(0, gold + $1),
                   lastDiceRollAt = $2,
                   dice_sixes = dice_sixes + $3,
                   luck = $4,
                   roll_streak = $5
             WHERE id = $6`,
            [deltaGold, now, sixGain, finalLuck, luckState.nextStreak, uid]
          );

          const payloadBase = {
            userId: uid,
            username: socket.user.username,
            variant,
            result: roll.result,
            value: roll.result,
            breakdown: roll.breakdown,
            won: reward.isJackpot || deltaGold > 0,
            outcome: reward.outcome,
            isJackpot: !!reward.isJackpot,
            serverTs: now,
          };

          socket.emit("dice:result", { ...payloadBase, deltaGold });
          socket.to(room).emit("dice:result", { ...payloadBase, deltaGold });
          emitProgressionUpdate(uid);
          emitLuckUpdate(uid, finalLuck, luckState.nextStreak);

          emitRoomSystem(
            room,
            formatDiceSystemMessage({ result: roll.result, breakdown: roll.breakdown, deltaGold, outcome: reward.outcome }),
            { kind: "dice" }
          );

          if (reward.isJackpot) {
            void ensureMemory(
              uid,
              "dice_jackpot",
              {
                type: "rare",
                title: "Dice jackpot!",
                description: "Landed the jackpot roll in Dice Room.",
                icon: "🎲",
                room_id: room,
                metadata: { value: roll.result, deltaGold, variant, outcome: reward.outcome },
              },
              socket.user
            );
          }
          return;
        }
      } catch (e) {
        console.warn("[dice][pg] failed, falling back to sqlite:", e?.message || e);
      }

      // SQLite fallback (original behavior)
      db.get(
        `SELECT gold, lastDiceRollAt, luck, roll_streak, last_qual_msg_at FROM users WHERE id=?`,
        [uid],
        (err, row) => {
        if (err || !row) {
          socket.emit("dice:error", "Could not roll dice right now.");
          return;
        }

        const last = Number(row.lastDiceRollAt || 0);
        if (now - last < DICE_ROLL_MIN_INTERVAL_MS) {
          socket.emit(
            "dice:error",
            `Roll available in ${Math.ceil((DICE_ROLL_MIN_INTERVAL_MS - (now - last)) / 1000)}s.`
          );
          return;
        }

        const gold = Number(row.gold || 0);
        const luckState = applyLuckForRoll({
          luck: row.luck,
          rollStreak: row.roll_streak,
          lastQualMsgAt: row.last_qual_msg_at,
          userId: uid,
          now,
        });
        const roll = rollDiceVariantWithLuck(variant, luckState.nextLuck);
        const reward = computeDiceReward(variant, roll.result, roll.breakdown);
        if (gold < (reward.minBalanceRequired || 0)) {
          socket.emit(
            "dice:error",
            `You need at least ${reward.minBalanceRequired || 0} Gold to roll ${DICE_VARIANT_LABELS[variant] || variant}.`
          );
          return;
        }

        const deltaGold = Number(reward.deltaGold || 0);
        const breakdownArr = Array.isArray(roll.breakdown) ? roll.breakdown : [];
        const sixGain =
          variant === "d6" ? (roll.result === 6 ? 1 : 0) : variant === "2d6" ? breakdownArr.filter((n) => n === 6).length : 0;
        const didWinForLuck = isLuckWin(variant, roll.result, roll.breakdown);
        const finalLuck = clampLuck(applyWinCut(luckState.nextLuck, didWinForLuck));

        db.run(
          `UPDATE users
             SET gold = MAX(0, gold + ?),
                 lastDiceRollAt = ?,
                 dice_sixes = dice_sixes + ?,
                 luck = ?,
                 roll_streak = ?
           WHERE id = ?`,
          [deltaGold, now, sixGain, finalLuck, luckState.nextStreak, uid],
          (uerr) => {
            if (uerr) {
              socket.emit("dice:error", "Could not apply dice result.");
              return;
            }

            const payloadBase = {
              userId: uid,
              username: socket.user.username,
              variant,
              result: roll.result,
              value: roll.result,
              breakdown: roll.breakdown,
              won: reward.isJackpot || deltaGold > 0,
              outcome: reward.outcome,
              isJackpot: !!reward.isJackpot,
              serverTs: now,
            };

            socket.emit("dice:result", { ...payloadBase, deltaGold });
            socket.to(room).emit("dice:result", { ...payloadBase, deltaGold });
            emitProgressionUpdate(uid);
            emitLuckUpdate(uid, finalLuck, luckState.nextStreak);

            emitRoomSystem(
              room,
              formatDiceSystemMessage({ result: roll.result, breakdown: roll.breakdown, deltaGold, outcome: reward.outcome }),
              { kind: "dice" }
            );

            if (reward.isJackpot) {
              void ensureMemory(
                uid,
                "dice_jackpot",
                {
                  type: "rare",
                  title: "Dice jackpot!",
                  description: "Landed the jackpot roll in Dice Room.",
                  icon: "🎲",
                  room_id: room,
                  metadata: { value: roll.result, deltaGold, variant, outcome: reward.outcome },
                },
                socket.user
              );
            }
          }
        );
      }
      );
    })();
  });

function doJoin(room, status) {
  // Block joining rooms if the user is kicked/banned (prevents showing as online).
  if (socket.restriction?.type && socket.restriction.type !== "none") {
    io.to(socket.id).emit("restriction:status", {
      type: socket.restriction.type,
      reason: socket.restriction.reason || "",
      expiresAt: socket.restriction.expiresAt || null,
      now: Date.now(),
    });
    return;
  }
  const previousRoom = socket.data.currentRoom || socket.currentRoom || null;
  const targetRoom = room;
  if (previousRoom && previousRoom !== targetRoom) {
    if (DEBUG_ROOMS) {
      console.log("[rooms] leave", { sid: socket.id, room: previousRoom, next: targetRoom });
    }
    socket.leave(previousRoom);

    const set = typingByRoom.get(previousRoom);
    if (set) {
      set.delete(socket.user.username);
      broadcastTyping(previousRoom);
    }

    emitUserList(previousRoom);
  }

  if (previousRoom !== targetRoom) {
    if (DEBUG_ROOMS) {
      console.log("[rooms] join", { sid: socket.id, room: targetRoom, prev: previousRoom });
    }
    socket.join(targetRoom);
  }
  socket.currentRoom = targetRoom;
  socket.data.currentRoom = targetRoom;

  // session map + heat + daily unique rooms
  try {
    const meta = sessionMetaBySocketId.get(socket.id) || {};
    meta.room = room;
    meta.lastSeenAt = Date.now();
    sessionMetaBySocketId.set(socket.id, meta);
  } catch {}

  try {
    const uid = socket.user?.id;
    const prev = lastRoomHopByUserId.get(uid);
    const now = Date.now();
    if (prev && prev.room && prev.room !== room && now - (prev.ts || 0) < 15_000) bumpHeat(uid, 2);
    lastRoomHopByUserId.set(uid, { room, ts: now });
    // daily challenge: unique rooms
    bumpDailyUniqueRoom(uid, dayKeyNow(), String(room));
  } catch {}


  // send active room event (if any) to joining socket
  try {
    const ev = ACTIVE_ROOM_EVENTS.get(room);
    if (ev) socket.emit("room:event", { room, active: ev, at: Date.now() });
  } catch {}

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
    `SELECT id, room, username, role, avatar, text, tone, ts, attachment_url, attachment_type, attachment_mime, attachment_size,
            reply_to_id, reply_to_user, reply_to_text
     FROM messages
     WHERE (room=? OR room=?) AND deleted=0
     ORDER BY ts DESC LIMIT 200`,
    [room, legacyRoom],
    (_e, rows) => {
      // Query newest-first, then reverse so clients render oldest -> newest.
      const baseHistory = (rows || []).reverse().map((r) => ({
        messageId: r.id,
        room: r.room,
        user: r.username,
        role: r.role,
        avatar: r.avatar || "",
        text: (r.text || ""),
        tone: r.tone || "",
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

      const usernames = baseHistory.map((m) => m.user).filter(Boolean);
      buildAuthorsFxMap(usernames, (authorsFx) => {
        const history = baseHistory.map((m) => ({
          ...m,
          chatFx: authorsFx[m.user] || mergeChatFxWithCustomization(null, null, null),
        }));
        socket.emit("history", history, { authorsFx });

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
      });
    }
  );

  socket.emit("system", buildSystemPayload(room, "Joined " + room));
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

  socket.on("dm join", (payload = {}) => {
    const tid = Number(payload.threadId);
    if (!Number.isInteger(tid)) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err) return;
      socket.dmThreads.add(tid);
      socket.join(`dm:${tid}`);

      db.all(
        `SELECT id, thread_id, user_id, username, text, tone, ts, edited_at, reply_to_id, reply_to_user, reply_to_text, attachment_url, attachment_mime, attachment_type, attachment_size FROM dm_messages WHERE thread_id=? AND deleted=0 ORDER BY ts DESC LIMIT 50`,
        [tid],
        (_e, rows) => {
          const msgs = (rows || []).reverse().map((r) => ({
            messageId: r.id,
            id: r.id,
            threadId: r.thread_id,
            userId: r.user_id,
            user: r.username,
            text: r.text,
            tone: r.tone || "",
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
          const usernames = msgs.map((m) => m.user).filter(Boolean);
          buildAuthorsFxMap(usernames, async (authorsFx) => {
            socket.emit("dm history", {
              threadId: tid,
              title: thread.title || "",
              isGroup: !!thread.is_group,
              participants: thread.participants || [],
              messages: msgs,
              authorsFx,
            });

            // Prime read-receipt state for the joining client.
            // The socket-side in-memory map (dmReadState) is best-effort and can be empty after
            // reloads. We persist last_read_at per user in dm_participants; on join, translate
            // that into a message id so the client can reliably render the "☑" tick.
            try {
              db.all(
                `SELECT user_id, COALESCE(last_read_at,0) AS last_read_at
                   FROM dm_participants
                  WHERE thread_id = ?`,
                [tid],
                (_re0, readRows) => {
                  const rows = readRows || [];
                  for (const rr of rows) {
                    const uid = Number(rr.user_id);
                    const lastReadAt = Number(rr.last_read_at || 0);
                    if (!Number.isInteger(uid) || uid <= 0) continue;
                    if (!lastReadAt) continue;

                    // Prefer the in-memory state if it's newer.
                    try {
                      const perThread = dmReadState.get(tid);
                      const mem = perThread?.get(uid);
                      if (mem?.ts && Number(mem.ts) > lastReadAt && Number.isInteger(Number(mem.messageId))) {
                        socket.emit("dm read", {
                          threadId: tid,
                          userId: uid,
                          messageId: Number(mem.messageId),
                          ts: Number(mem.ts)
                        });
                        continue;
                      }
                    } catch {}

                    // Translate timestamp -> message id in this thread.
                    db.get(
                      `SELECT id, ts
                         FROM dm_messages
                        WHERE thread_id = ? AND deleted=0 AND ts <= ?
                        ORDER BY ts DESC, id DESC
                        LIMIT 1`,
                      [tid, lastReadAt],
                      (_re1, hit) => {
                        const mid = Number(hit?.id);
                        const mts = Number(hit?.ts || lastReadAt);
                        if (!Number.isInteger(mid) || mid <= 0) return;
                        socket.emit("dm read", {
                          threadId: tid,
                          userId: uid,
                          messageId: mid,
                          ts: mts
                        });
                      }
                    );
                  }
                }
              );
            } catch {}

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

            try {
              const latestChallenge = await chessGetLatestChallengeForThread(tid);
              if (latestChallenge) {
                await emitChessChallengeStateToSocket(socket, latestChallenge);
              }
            } catch (e) {
              console.warn("[chess] dm join challenge state failed:", e?.message || e);
            }
          });

        }
      );
    });
  });

  
  socket.on("dm mark read", (payload = {}) => {
    const tid = Number(payload.threadId);
    const mid = Number(payload.messageId);
    const tms = safeNumber(payload.ts, Date.now());
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


  socket.on("dm leave", (payload = {}) => {
    const tid = Number(payload.threadId);
    if (!Number.isInteger(tid)) return;
    try { socket.leave(`dm:${tid}`); } catch {}
    try { socket.dmThreads?.delete(tid); } catch {}

    // Clear any lingering DM typing state for this user in that thread.
    try {
      const set = dmTypingByThread.get(tid);
      if (set && socket.user?.username) {
        set.delete(socket.user.username);
        if (set.size === 0) dmTypingByThread.delete(tid);
        broadcastDmTyping(tid);
      }
    } catch {}
  });

  // DM typing indicators (per thread)
  socket.on("dm typing", (payload = {}) => {
    const tid = Number(payload.threadId);
    if (!Number.isInteger(tid)) return;
    if (!socket.dmThreads?.has(tid)) return; // must have joined
    let set = dmTypingByThread.get(tid);
    if (!set) dmTypingByThread.set(tid, (set = new Set()));
    if (socket.user?.username) set.add(socket.user.username);
    broadcastDmTyping(tid);
  });

  socket.on("dm stop typing", (payload = {}) => {
    const tid = Number(payload.threadId);
    if (!Number.isInteger(tid)) return;
    const set = dmTypingByThread.get(tid);
    if (set && socket.user?.username) {
      set.delete(socket.user.username);
      if (set.size === 0) dmTypingByThread.delete(tid);
      broadcastDmTyping(tid);
    }
  });

  socket.on("dm message", (payload = {}) => {
    const { threadId, text, replyToId, attachment, tone } = payload || {};
    const tid = Number(threadId);
    if (!allowSocketEvent(socket, "dm_message", 12, 4000)) return;
    const rawBody = safeString(text, "").trim();
    if (rawBody.length > MAX_DM_MESSAGE_CHARS) return;
    const body = rawBody.slice(0, MAX_DM_MESSAGE_CHARS);
    const att = attachment && typeof attachment === "object" ? attachment : null;
    const toneKey = sanitizeTone(tone);

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

      const replyId = safeNumber(replyToId, NaN);
      const doInsert = (replyMeta = {}) => {
        const replyUser = replyMeta.user || null;
        const replyText = replyMeta.text || null;
        const replyPk = Number.isInteger(replyMeta.id) ? replyMeta.id : null;

        db.run(
          `INSERT INTO dm_messages (thread_id, user_id, username, text, tone, ts, reply_to_id, reply_to_user, reply_to_text, attachment_url, attachment_mime, attachment_type, attachment_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            tid,
            socket.user.id,
            socket.user.username,
            body,
            toneKey,
            ts,
            replyPk,
            replyUser,
            replyText,
            attUrl,
            attMime,
            attType,
            attSize,
          ],
          function (insertErr) {
            if (insertErr) return;
            const payload = {
              threadId: tid,
              messageId: this.lastID,
              userId: socket.user.id,
              user: socket.user.username,
              text: body,
              tone: toneKey || "",
              ts,
              attachmentUrl: attUrl,
              attachmentMime: attMime,
              attachmentType: attType,
              attachmentSize: attSize,
              chatFx: mergeChatFxWithCustomization(socket.user.chatFx, socket.user.customization, socket.user.textStyle),
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
          `SELECT id, username, text FROM dm_messages WHERE id = ? AND thread_id = ? AND deleted=0`,
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
  socket.on("dm edit message", (payload = {}) => {
    const tid = Number(payload.threadId);
    const mid = Number(payload.messageId);
    if (!allowSocketEvent(socket, "dm_edit", 8, 5000)) return;
    const body = safeString(payload.text, "").trim().slice(0, MAX_DM_MESSAGE_CHARS);
    if (!socket.user) return;
    if (!Number.isInteger(tid) || !Number.isInteger(mid) || !body) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err || !thread) return;

      db.get(
        `SELECT id, thread_id, user_id, ts FROM dm_messages WHERE id = ? AND thread_id = ? AND deleted=0`,
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
  socket.on("dm reaction", (payload = {}) => {
    const tid = Number(payload.threadId);
    const mid = Number(payload.messageId);
    const em = safeString(payload.emoji, "").slice(0, 8);
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


  socket.on("chess:challenge:create", async ({ dmThreadId, challengedUserId } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    const tid = Number(dmThreadId);
    const challengedId = Number(challengedUserId);
    if (!Number.isInteger(tid) || !Number.isInteger(challengedId)) {
      return respond({ ok: false, error: "Invalid challenge request" });
    }
    if (challengedId === Number(socket.user.id)) {
      return respond({ ok: false, error: "Cannot challenge yourself" });
    }

    loadThreadForUser(tid, socket.user.id, async (err, thread) => {
      if (err || !thread) return respond({ ok: false, error: "Thread not found" });
      if (thread.is_group) return respond({ ok: false, error: "Chess challenges are direct DMs only" });
      if (!thread.participantIds?.includes?.(challengedId)) {
        return respond({ ok: false, error: "User not in this DM" });
      }

      try {
        const latest = await chessGetLatestChallengeForThread(tid);
        if (latest && latest.status === "pending") {
          await emitChessChallengeStateToSocket(socket, latest);
          return respond({ ok: false, error: "Challenge already pending", challengeId: latest.challenge_id });
        }
        const activeGame = await chessGetActiveGameForContext("dm", String(tid));
        if (activeGame) {
          await emitChessStateToSocket(socket, activeGame);
          return respond({ ok: false, error: "Game already active", gameId: activeGame.game_id });
        }
        const challenge = await chessCreateChallenge(tid, socket.user.id, challengedId);
        await insertDmChessMessage({
          threadId: tid,
          authorId: socket.user.id,
          authorName: socket.user.username,
          text: `[chess:challenge:${challenge.challenge_id}]`,
        });
        await emitChessChallengeStateToRoom(tid, challenge);
        respond({ ok: true, challengeId: challenge.challenge_id });
      } catch (e) {
        console.warn("[chess] challenge create failed:", e?.message || e);
        respond({ ok: false, error: "Failed to create challenge" });
      }
    });
  });

  socket.on("chess:challenge:respond", async ({ challengeId, accept } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (!challengeId) return respond({ ok: false, error: "Missing challenge" });
    try {
      const challenge = await chessGetChallengeById(String(challengeId));
      if (!challenge || challenge.status !== "pending") {
        return respond({ ok: false, error: "Challenge not available" });
      }
      if (Number(challenge.challenged_user_id) !== Number(socket.user.id)) {
        return respond({ ok: false, error: "Not allowed" });
      }
      const nextStatus = accept ? "accepted" : "declined";
      const updated = await chessUpdateChallenge(challenge.challenge_id, { status: nextStatus });
      await emitChessChallengeStateToRoom(updated.dm_thread_id, updated);
      if (!accept) {
        await insertDmChessMessage({
          threadId: updated.dm_thread_id,
          authorId: socket.user.id,
          authorName: socket.user.username,
          text: `[chess:challenge:declined:${updated.challenge_id}]`,
        });
        return respond({ ok: true, status: nextStatus });
      }

      const game = await chessCreateGame("dm", String(updated.dm_thread_id), updated.challenger_user_id, updated.challenged_user_id);
      await insertDmChessMessage({
        threadId: updated.dm_thread_id,
        authorId: socket.user.id,
        authorName: socket.user.username,
        text: `[chess:challenge:accepted:${updated.challenge_id}]`,
      });
      await emitChessStateToGameRoom(game);
      respond({ ok: true, status: nextStatus, gameId: game.game_id });
    } catch (e) {
      console.warn("[chess] challenge respond failed:", e?.message || e);
      respond({ ok: false, error: "Failed to respond" });
    }
  });

  socket.on("chess:game:create", async ({ contextType, contextId } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (contextType !== "room") return respond({ ok: false, error: "Invalid context" });
    const roomId = String(contextId || "");
    if (!roomId) return respond({ ok: false, error: "Missing room" });
    try {
      const existing = await chessGetActiveGameForContext("room", roomId);
      if (existing) {
        await emitChessStateToSocket(socket, existing);
        return respond({ ok: true, gameId: existing.game_id });
      }
      const game = await chessCreateGame("room", roomId);
      socket.join(`chess:${game.game_id}`);
      await emitChessStateToSocket(socket, game);
      respond({ ok: true, gameId: game.game_id });
    } catch (e) {
      console.warn("[chess] game create failed:", e?.message || e);
      respond({ ok: false, error: "Failed to create game" });
    }
  });

  socket.on("chess:game:join", async ({ gameId, contextType, contextId } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    try {
      let game = null;
      if (gameId) {
        game = await chessGetGameById(String(gameId));
      } else if (contextType && contextId) {
        game = await chessGetActiveGameForContext(String(contextType), String(contextId));
        if (!game && String(contextType) === "dm") {
          game = await chessGetLatestGameForContext(String(contextType), String(contextId));
        }
      }
      if (!game) {
        await emitChessStateToSocket(socket, null);
        return respond({ ok: false, error: "Game not found" });
      }
      if (game.context_type === "dm") {
        const threadOk = await new Promise((resolve) => {
          loadThreadForUser(Number(game.context_id), socket.user.id, (err, thread) => resolve(!err && !!thread));
        });
        if (!threadOk) return respond({ ok: false, error: "Not allowed" });
      }
      socket.join(`chess:${game.game_id}`);
      await emitChessStateToSocket(socket, game);
      respond({ ok: true, gameId: game.game_id });
    } catch (e) {
      console.warn("[chess] game join failed:", e?.message || e);
      respond({ ok: false, error: "Failed to join game" });
    }
  });

  socket.on("chess:game:seat", async ({ gameId, color } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    const seatColor = color === "white" ? "white" : (color === "black" ? "black" : "");
    if (!seatColor || !gameId) return respond({ ok: false, error: "Invalid seat" });
    try {
      let game = await chessGetGameById(String(gameId));
      if (!game) return respond({ ok: false, error: "Game not found" });
      if (game.context_type !== "room") return respond({ ok: false, error: "Seats only for rooms" });
      const seatKey = seatColor === "white" ? "white_user_id" : "black_user_id";
      const seatUserId = Number(game[seatKey] || 0);
      if (seatUserId && seatUserId !== Number(socket.user.id)) {
        const seatUser = await getUserIdentityForMemory(seatUserId);
        if (!seatClaimable(game, seatUser)) {
          return respond({ ok: false, error: "Seat occupied" });
        }
      }
      const updates = { [seatKey]: socket.user.id };
      if (game.status === "pending") {
        const nextWhite = seatColor === "white" ? socket.user.id : game.white_user_id;
        const nextBlack = seatColor === "black" ? socket.user.id : game.black_user_id;
        if (nextWhite && nextBlack) updates.status = "active";
      }
      game = await chessUpdateGame(game.game_id, updates);
      await emitChessStateToGameRoom(game);
      respond({ ok: true });
    } catch (e) {
      console.warn("[chess] seat failed:", e?.message || e);
      respond({ ok: false, error: "Failed to seat" });
    }
  });

  socket.on("chess:game:move", async ({ gameId, from, to, promotion } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (!allowSocketEvent(socket, "chess_move", 12, 4000)) return respond({ ok: false, error: "Rate limited" });
    if (!gameId || !from || !to) return respond({ ok: false, error: "Invalid move" });
    try {
      let game = await chessGetGameById(String(gameId));
      if (!game) return respond({ ok: false, error: "Game not found" });
      if (game.status !== "active") return respond({ ok: false, error: "Game not active" });
      const isWhite = Number(game.white_user_id || 0) === Number(socket.user.id);
      const isBlack = Number(game.black_user_id || 0) === Number(socket.user.id);
      if (!isWhite && !isBlack) return respond({ ok: false, error: "Spectators cannot move" });
      if ((game.turn === "w" && !isWhite) || (game.turn === "b" && !isBlack)) {
        return respond({ ok: false, error: "Not your turn" });
      }
      const chess = createChessInstance(game.fen);
      const move = chess.move({ from, to, promotion: promotion || undefined });
      if (!move) return respond({ ok: false, error: "Illegal move" });

      const now = Date.now();
      const nextStatus = chess.isCheckmate() ? "mate" : (chess.isStalemate() || chess.isDraw() ? "draw" : "active");
      const result =
        chess.isCheckmate()
          ? (chess.turn() === "w" ? "black" : "white")
          : (chess.isStalemate() || chess.isDraw()) ? "draw" : null;
      const updates = {
        fen: chess.fen(),
        pgn: chess.pgn(),
        turn: chess.turn(),
        plies_count: Number(game.plies_count || 0) + 1,
        last_move_at: now,
        updated_at: now,
        draw_offer_by_user_id: null,
        draw_offer_at: null,
      };
      if (nextStatus !== "active") {
        const updatedGame = await chessUpdateGame(game.game_id, updates);
        const finalResult = await chessFinalizeGame(
          updatedGame,
          { result: result || "draw", status: nextStatus, reason: nextStatus }
        );
        game = finalResult.game;
      } else {
        game = await chessUpdateGame(game.game_id, updates);
      }

      await emitChessStateToGameRoom(game);
      respond({ ok: true });

      if (game.context_type === "room" && move?.san) {
        const actorName = socket.user.username;
        emitRoomSystem(game.context_id, `${actorName} played ${move.san}`);
      }

      if (game.status !== "active" && game.context_type === "dm") {
        const summary = game.result === "draw"
          ? "Draw"
          : game.result === "white"
            ? "White wins"
            : "Black wins";
        await insertDmChessMessage({
          threadId: Number(game.context_id),
          authorId: socket.user.id,
          authorName: socket.user.username,
          text: `[chess:result:${game.game_id}:${summary}]`,
        });
      }
    } catch (e) {
      console.warn("[chess] move failed:", e?.message || e);
      respond({ ok: false, error: "Move failed" });
    }
  });

  socket.on("chess:game:resign", async ({ gameId } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (!gameId) return respond({ ok: false, error: "Missing game" });
    try {
      const game = await chessGetGameById(String(gameId));
      if (!game || game.status !== "active") return respond({ ok: false, error: "Game not active" });
      const isWhite = Number(game.white_user_id || 0) === Number(socket.user.id);
      const isBlack = Number(game.black_user_id || 0) === Number(socket.user.id);
      if (!isWhite && !isBlack) return respond({ ok: false, error: "Not a player" });
      const result = isWhite ? "black" : "white";
      const finalResult = await chessFinalizeGame(game, { result, status: "resigned", reason: "resign" });
      await emitChessStateToGameRoom(finalResult.game);
      if (finalResult.game.context_type === "dm") {
        const summary = result === "white" ? "White wins" : "Black wins";
        await insertDmChessMessage({
          threadId: Number(finalResult.game.context_id),
          authorId: socket.user.id,
          authorName: socket.user.username,
          text: `[chess:result:${finalResult.game.game_id}:${summary}]`,
        });
      }
      respond({ ok: true });
    } catch (e) {
      console.warn("[chess] resign failed:", e?.message || e);
      respond({ ok: false, error: "Failed to resign" });
    }
  });

  socket.on("chess:game:drawOffer", async ({ gameId } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (!gameId) return respond({ ok: false, error: "Missing game" });
    try {
      const game = await chessGetGameById(String(gameId));
      if (!game || game.status !== "active") return respond({ ok: false, error: "Game not active" });
      const isWhite = Number(game.white_user_id || 0) === Number(socket.user.id);
      const isBlack = Number(game.black_user_id || 0) === Number(socket.user.id);
      if (!isWhite && !isBlack) return respond({ ok: false, error: "Not a player" });
      const updated = await chessUpdateGame(game.game_id, {
        draw_offer_by_user_id: socket.user.id,
        draw_offer_at: Date.now(),
      });
      await emitChessStateToGameRoom(updated);
      respond({ ok: true });
    } catch (e) {
      console.warn("[chess] draw offer failed:", e?.message || e);
      respond({ ok: false, error: "Failed to offer draw" });
    }
  });

  socket.on("chess:game:drawRespond", async ({ gameId, accept } = {}, ack) => {
    const respond = (payload) => {
      if (typeof ack === "function") ack(payload);
    };
    if (!socket.user) return respond({ ok: false, error: "Unauthorized" });
    if (!gameId) return respond({ ok: false, error: "Missing game" });
    try {
      const game = await chessGetGameById(String(gameId));
      if (!game || game.status !== "active") return respond({ ok: false, error: "Game not active" });
      if (!game.draw_offer_by_user_id) return respond({ ok: false, error: "No draw offer" });
      if (Number(game.draw_offer_by_user_id) === Number(socket.user.id)) {
        return respond({ ok: false, error: "Cannot respond to your own offer" });
      }
      if (!accept) {
        const updated = await chessUpdateGame(game.game_id, { draw_offer_by_user_id: null, draw_offer_at: null });
        await emitChessStateToGameRoom(updated);
        return respond({ ok: true, status: "declined" });
      }
      const finalResult = await chessFinalizeGame(game, { result: "draw", status: "draw", reason: "draw" });
      await emitChessStateToGameRoom(finalResult.game);
      if (finalResult.game.context_type === "dm") {
        await insertDmChessMessage({
          threadId: Number(finalResult.game.context_id),
          authorId: socket.user.id,
          authorName: socket.user.username,
          text: `[chess:result:${finalResult.game.game_id}:Draw]`,
        });
      }
      respond({ ok: true, status: "accepted" });
    } catch (e) {
      console.warn("[chess] draw respond failed:", e?.message || e);
      respond({ ok: false, error: "Failed to respond" });
    }
  });

  socket.on("chess:leaderboard:get", async ({ limit, offset } = {}, ack) => {
    try {
      const rows = await fetchChessLeaderboard(limit, offset);
      const payload = rows.map((row) => {
        const games = Number(row.chess_games_played || 0);
        const wins = Number(row.chess_wins || 0);
        const losses = Number(row.chess_losses || 0);
        const draws = Number(row.chess_draws || 0);
        const winrate = games > 0 ? Math.round((wins / games) * 1000) / 10 : 0;
        return {
          userId: Number(row.user_id),
          username: row.username,
          elo: Number(row.chess_elo || CHESS_DEFAULT_ELO),
          gamesPlayed: games,
          wins,
          losses,
          draws,
          winrate,
          peakElo: Number(row.chess_peak_elo || row.chess_elo || CHESS_DEFAULT_ELO),
        };
      });
      if (typeof ack === "function") {
        ack({ rows: payload, limit: Number(limit || 50), offset: Number(offset || 0) });
      }
      socket.emit("chess:leaderboard:data", { rows: payload, limit: Number(limit || 50), offset: Number(offset || 0) });
    } catch (e) {
      console.warn("[chess] leaderboard socket failed:", e?.message || e);
      if (typeof ack === "function") ack({ ok: false });
    }
  });


  socket.on("status change", ({ status }) => {
    status = normalizeStatus(status, "Online");
    socket.user.status = status;

    const st = onlineState.get(socket.user.id);
    if (st) st.status = status;

    db.run("UPDATE users SET last_status=? WHERE id=?", [status, socket.user.id]);

    if (socket.currentRoom) emitUserList(socket.currentRoom);
  });

  socket.on("chat message", (payload = {}) => {
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

    if (!allowSocketEvent(socket, "chat_message", 16, 4000)) {
      socket.emit("system", buildSystemPayload(socket.currentRoom || "main", "You are sending messages too quickly."));
      return;
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

        const rawText = safeString(payload.text, "");
        if (rawText.length > MAX_CHAT_MESSAGE_CHARS) {
      socket.emit("system", buildSystemPayload(socket.currentRoom || "main", "Message too long (max " + MAX_CHAT_MESSAGE_CHARS + " characters)."));
          return;
        }
        const text = rawText.slice(0, MAX_CHAT_MESSAGE_CHARS);
        if (text.trim().startsWith("/")) {
          executeCommand(socket, text, room);
          return;
        }
        const attachmentUrl = safeString(payload.attachmentUrl, "").slice(0, 400);
        const attachmentType = safeString(payload.attachmentType, "").slice(0, 20);
        const attachmentMime = safeString(payload.attachmentMime, "").slice(0, 60);
        const attachmentSize = safeNumber(payload.attachmentSize, 0);
        const tone = sanitizeTone(payload.tone);

        awardPassiveGold(socket.user.id);

        // maintenance / lock / slowmode enforcement
        if (maintenanceState.enabled && !requireMinRole(socket.user.role, "Moderator")) {
          socket.emit("command response", { ok: false, message: "Site is in maintenance mode" });
          return;
        }

        db.get(
          `SELECT slowmode_seconds, is_locked, archived FROM rooms WHERE name=?`,
          [room],
          (_err, settings) => {
            const slowSeconds = Number(settings?.slowmode_seconds || 0);
            const locked = Number(settings?.is_locked || 0) === 1;
            const archived = Number(settings?.archived || 0) === 1;
            if (archived) {
              socket.emit("command response", { ok: false, message: "Room is archived" });
              return;
            }
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

            const replyId = safeNumber(payload.replyToId, NaN);
            const insertWithReply = (replyMeta = {}) => {
              const replyPk = Number.isInteger(replyMeta.id) ? replyMeta.id : null;
              const replyUser = replyMeta.username || replyMeta.user || null;
              const replyText = replyMeta.text || null;
              const tsNow = Date.now();

              db.run(
                `INSERT INTO messages (room, user_id, username, role, avatar, text, tone, ts, attachment_url, attachment_type, attachment_mime, attachment_size, reply_to_id, reply_to_user, reply_to_text)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  room,
                  socket.user.id,
                  socket.user.username,
                  socket.user.role,
                  socket.user.avatar || "",
                  text,
                  tone,
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
                  awardMessageXp(socket.user.id, socket.user.role, room).catch((e) => console.warn("[xp][msg]", e?.message || e));
                  awardMessageGold(socket.user.id);
                  const msg = {
                    messageId: this.lastID,
                    room,
                    user: socket.user.username,
                    role: socket.user.role,
                    avatar: socket.user.avatar || "",
                    text,
                    tone: tone || "",
                    ts: tsNow,
                    attachmentUrl: attachmentUrl || "",
                    attachmentType: attachmentType || "",
                    attachmentMime: attachmentMime || "",
                    attachmentSize: attachmentSize || 0,
                    replyToId: replyPk,
                    replyToUser: replyUser || "",
                    replyToText: replyText || "",
                    chatFx: mergeChatFxWithCustomization(socket.user.chatFx, socket.user.customization, socket.user.textStyle),
                  };
                  // Daily challenges + smart mentions
                  try { bumpDailyProgress(socket.user.id, dayKeyNow(), "room_msgs_5", 1); } catch {}
                  try {
                    emitSmartMentionPings({
                      room,
                      fromUser: { id: socket.user.id, username: socket.user.username, socketId: socket.id },
                      messageId: msg.id || msg.messageId || null,
                      text: msg.text || "",
                    });
                  } catch {}
                  void applyLuckForQualifyingMessage({
                    userId: socket.user.id,
                    room,
                    text,
                  });
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
  socket.on("edit message", (payload = {}) => {
    const mid = Number(payload.messageId);
    const body = safeString(payload.text, "").trim().slice(0, 2000);
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

    try {
      const uid = socket.user?.id;
      const now = Date.now();
      const last = lastReactionByUserId.get(uid) || 0;
      if (now - last < 800) bumpHeat(uid, 1);
      if (now - last >= 800) {
        bumpDailyProgress(uid, dayKeyNow(), "react_3", 1);
        lastReactionByUserId.set(uid, now);
      }
    } catch {}

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

  const logDeleteFailure = ({ scope, messageId, actorId, actorRole, reason, roomId, threadId }) => {
    console.warn(`[delete:${scope}]`, { messageId, actorId, actorRole, roomId, threadId, reason });
  };

  const respondDelete = (ack, payload) => {
    if (typeof ack === "function") ack(payload);
  };

  const emitMainMessageDeleted = (messageId, roomId) => {
    const rawRoom = String(roomId || "").trim();
    if (!rawRoom) return;
    const emitRoom = rawRoom.startsWith("#") ? rawRoom.slice(1) : rawRoom;
    io.to(emitRoom).emit("messageDeleted", { messageId, roomId: emitRoom });
    io.to(emitRoom).emit("message deleted", { messageId });
  };

  const handleMainDeleteMessage = ({ messageId } = {}, ack) => {
    const actor = socket.user;
    if (!actor) {
      respondDelete(ack, { ok: false, message: "Not authenticated." });
      return;
    }

    const actorRole = actor.role || socket.request?.session?.user?.role || "User";
    const mid = Number(messageId);
    if (!Number.isInteger(mid)) {
      respondDelete(ack, { ok: false, message: "Invalid message id." });
      logDeleteFailure({ scope: "main", messageId, actorId: actor.id, actorRole, reason: "invalid_id" });
      return;
    }

    db.get(
      "SELECT id, room, user_id, username, role, deleted FROM messages WHERE id=?",
      [mid],
      (err, msg) => {
        if (err) {
          respondDelete(ack, { ok: false, message: "Failed to load message." });
          logDeleteFailure({ scope: "main", messageId: mid, actorId: actor.id, actorRole, reason: "load_failed" });
          return;
        }
        if (!msg) {
          respondDelete(ack, { ok: false, message: "Message not found." });
          logDeleteFailure({ scope: "main", messageId: mid, actorId: actor.id, actorRole, reason: "not_found" });
          return;
        }

        const isModerator = requireMinRole(actorRole, "Moderator");
        const isVip = requireMinRole(actorRole, "VIP");
        const isOwner = Number(msg.user_id) === Number(actor.id);
        if (!isModerator && !(isVip && isOwner)) {
          respondDelete(ack, { ok: false, message: "Not allowed to delete this message." });
          logDeleteFailure({ scope: "main", messageId: mid, actorId: actor.id, actorRole, roomId: msg.room, reason: "forbidden" });
          return;
        }

        const wasDeleted = Number(msg.deleted || 0) === 1;
        if (wasDeleted) {
          respondDelete(ack, { ok: true, alreadyDeleted: true });
          emitMainMessageDeleted(mid, msg.room);
          return;
        }

        db.run("UPDATE messages SET deleted=1 WHERE id=?", [mid], (updateErr) => {
          if (updateErr) {
            respondDelete(ack, { ok: false, message: "Failed to delete message." });
            logDeleteFailure({ scope: "main", messageId: mid, actorId: actor.id, actorRole, roomId: msg.room, reason: "update_failed" });
            return;
          }

          db.run("DELETE FROM reactions WHERE message_id=?", [mid], (reactErr) => {
            if (reactErr) {
              console.warn("[delete:main] reaction cleanup failed", { messageId: mid, error: reactErr?.message || reactErr });
            }
            if (requireMinRole(actorRole, "Moderator")) {
              logModAction({
                actor,
                action: "DELETE_MESSAGE",
                targetUserId: msg.user_id,
                targetUsername: msg.username,
                room: msg.room,
                details: `messageId=${mid}`,
              });
            }
            respondDelete(ack, { ok: true });
            emitMainMessageDeleted(mid, msg.room);
          });
        });
      }
    );
  };

  socket.on("delete message", handleMainDeleteMessage);
  // Backward compatibility for older clients
  socket.on("mod delete message", handleMainDeleteMessage);

  socket.on("dm delete message", ({ threadId, messageId } = {}, ack) => {
    const actor = socket.user;
    if (!actor) {
      respondDelete(ack, { ok: false, message: "Not authenticated." });
      return;
    }

    const tid = Number(threadId);
    const mid = Number(messageId);
    if (!Number.isInteger(tid) || !Number.isInteger(mid)) {
      respondDelete(ack, { ok: false, message: "Invalid message id." });
      logDeleteFailure({ scope: "dm", messageId, actorId: actor.id, actorRole: actor.role, threadId, reason: "invalid_id" });
      return;
    }

    loadThreadForUser(tid, actor.id, (err, thread) => {
      if (err || !thread) {
        respondDelete(ack, { ok: false, message: "Not allowed in this thread." });
        logDeleteFailure({ scope: "dm", messageId: mid, actorId: actor.id, actorRole: actor.role, threadId: tid, reason: "thread_access" });
        return;
      }

      const actorRole = actor.role || socket.request?.session?.user?.role || "User";
      db.get(
        "SELECT id, thread_id, user_id, deleted FROM dm_messages WHERE id=? AND thread_id=?",
        [mid, tid],
        (msgErr, msg) => {
          if (msgErr) {
            respondDelete(ack, { ok: false, message: "Failed to load message." });
            logDeleteFailure({ scope: "dm", messageId: mid, actorId: actor.id, actorRole, threadId: tid, reason: "load_failed" });
            return;
          }
          if (!msg) {
            respondDelete(ack, { ok: false, message: "Message not found." });
            logDeleteFailure({ scope: "dm", messageId: mid, actorId: actor.id, actorRole, threadId: tid, reason: "not_found" });
            return;
          }

          const isModerator = requireMinRole(actorRole, "Moderator");
          const isVip = requireMinRole(actorRole, "VIP");
          const isOwner = Number(msg.user_id) === Number(actor.id);
          if (!isModerator && !(isVip && isOwner)) {
            respondDelete(ack, { ok: false, message: "Not allowed to delete this message." });
            logDeleteFailure({ scope: "dm", messageId: mid, actorId: actor.id, actorRole, threadId: tid, reason: "forbidden" });
            return;
          }

          const wasDeleted = Number(msg.deleted || 0) === 1;
          if (wasDeleted) {
            respondDelete(ack, { ok: true, alreadyDeleted: true });
            io.to(`dm:${tid}`).emit("dm message deleted", { threadId: tid, messageId: mid });
            return;
          }

          db.run("UPDATE dm_messages SET deleted=1 WHERE id=? AND thread_id=?", [mid, tid], (delErr) => {
            if (delErr) {
              respondDelete(ack, { ok: false, message: "Failed to delete message." });
              logDeleteFailure({ scope: "dm", messageId: mid, actorId: actor.id, actorRole, threadId: tid, reason: "update_failed" });
              return;
            }

            db.run("DELETE FROM dm_reactions WHERE thread_id=? AND message_id=?", [tid, mid], (reactErr) => {
              if (reactErr) {
                console.warn("[delete:dm] reaction cleanup failed", { messageId: mid, threadId: tid, error: reactErr?.message || reactErr });
              }
              respondDelete(ack, { ok: true });
              io.to(`dm:${tid}`).emit("dm message deleted", { threadId: tid, messageId: mid });
            });
          });
        }
      );
    });
  });

  // ---- Kick / Mute / Ban + Unmute/Unban/Warn + Set role
  
socket.on("mod kick", async ({ username, reason = "", durationSeconds = 300, caseId = null } = {}, ack) => {
  const respond = (payload) => { if (typeof ack === "function") ack(payload); };
  if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
  const room = socket.currentRoom;
  if (!room) return respond({ ok: false, error: "No active room." });

  const actorRole = socket.request.session.user.role;
  if (!requireMinRole(actorRole, "Moderator")) return respond({ ok: false, error: "Not permitted." });

  username = sanitizeUsername(username);
  if (!username) return respond({ ok: false, error: "Invalid username." });

  db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], async (_e, target) => {
    if (!target) return respond({ ok: false, error: "User not found." });
    if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

    // Persist restriction + log
    const actorName = socket.user?.username || socket.request?.session?.user?.username || "system";
    const why = String(reason || "").slice(0, 180) || "Kicked by staff";
    const dur = clamp(Number(durationSeconds) || 300, 30, 7 * 24 * 60 * 60);
    let expiresAt = null;
    try {
      ({ expiresAt } = await setKickEverywhere(target.username, actorName, why, dur));
    } catch {
      return respond({ ok: false, error: "Kick failed." });
    }

    // Notify + disconnect
    const sid = socketIdByUserId.get(target.id);
    if (sid) {
      io.to(sid).emit("restriction:status", { type: "kick", reason: why, expiresAt, now: Date.now() });
      io.sockets.sockets.get(sid)?.disconnect(true);
    }
    invalidateSessionsForUserId(target.id);

    emitRoomSystem(room, `${username} was kicked.`, { kind: "mod" });
    logModAction({ actor: socket.user, action: "KICK", targetUserId: target.id, targetUsername: target.username, room, details: `duration=${dur}s reason=${why}` });
    if (caseId) {
      addModCaseEvent(Number(caseId), {
        actorUserId: socket.user?.id || null,
        eventType: "kick",
        payload: { targetUserId: target.id, durationSeconds: dur, reason: why },
      }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "kick" })).catch(() => {});
    }
    respond({ ok: true, username: target.username, durationSeconds: dur });
  });
});

socket.on("mod unkick", async ({ username, caseId = null } = {}, ack) => {
  const respond = (payload) => { if (typeof ack === "function") ack(payload); };
  if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
  const room = socket.currentRoom;
  if (!room) return respond({ ok: false, error: "No active room." });

  const actorRole = socket.request.session.user.role;
  if (!requireMinRole(actorRole, "Moderator")) return respond({ ok: false, error: "Not permitted." });

  username = sanitizeUsername(username);
  if (!username) return respond({ ok: false, error: "Invalid username." });

  db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], async (_e, target) => {
    if (!target) return respond({ ok: false, error: "User not found." });
    if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

    const actorName = socket.user?.username || socket.request?.session?.user?.username || "system";
    try{
      await clearRestrictionEverywhere(target.username, actorName, "unkick");
    }catch{
      return respond({ ok: false, error: "Unkick failed." });
    }

    // Notify target (if online)
    const sid = socketIdByUserId.get(target.id);
    if (sid) {
      io.to(sid).emit("restriction:status", { type: "none", reason: "", expiresAt: null, now: Date.now() });
    }

    emitOnlineUsers();
    emitRoomSystem(room, "User " + (target && target.username ? target.username : "") + " has been un-kicked by " + actorName + ".", { kind: "mod" });
    if (caseId) {
      addModCaseEvent(Number(caseId), {
        actorUserId: socket.user?.id || null,
        eventType: "unkick",
        payload: { targetUserId: target.id },
      }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "unkick" })).catch(() => {});
    }
    respond({ ok: true, username: target.username });
  });
});


  socket.on("mod mute", ({ username, minutes = 10, reason = "", caseId = null } = {}, ack) => {
    const respond = (payload) => { if (typeof ack === "function") ack(payload); };
    if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
    const room = socket.currentRoom;
    if (!room) return respond({ ok: false, error: "No active room." });

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return respond({ ok: false, error: "Not permitted." });

    username = sanitizeUsername(username);
    const mins = clamp(minutes, 1, 1440);
    const expiresAt = Date.now() + mins * 60 * 1000;

    db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return respond({ ok: false, error: "User not found." });
      if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

      db.run(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at)
         VALUES (?, 'mute', ?, ?, ?, ?)`,
        [target.id, expiresAt, String(reason || "").slice(0, 180), socket.user.id, Date.now()],
        () => {
          emitRoomSystem(room, `${username} was muted for ${mins} minutes.`, { kind: "mod" });
          logModAction({
            actor: socket.user,
            action: "MUTE",
            targetUserId: target.id,
            targetUsername: target.username,
            room,
            details: `minutes=${mins} reason=${String(reason || "").slice(0, 180)}`,
          });
          if (caseId) {
            addModCaseEvent(Number(caseId), {
              actorUserId: socket.user?.id || null,
              eventType: "mute",
              payload: { targetUserId: target.id, minutes: mins, reason: String(reason || "").slice(0, 180) },
            }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "mute" })).catch(() => {});
          }
          respond({ ok: true, username: target.username, minutes: mins });
        }
      );
    });
  });

  socket.on("mod ban", ({ username, minutes = 0, reason = "", caseId = null } = {}, ack) => {
    const respond = (payload) => { if (typeof ack === "function") ack(payload); };
    if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
    const room = socket.currentRoom;
    if (!room) return respond({ ok: false, error: "No active room." });

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return respond({ ok: false, error: "Not permitted." });

    username = sanitizeUsername(username);
    const mins = Number(minutes);
    const expiresAt = Number.isFinite(mins) && mins > 0 ? Date.now() + mins * 60 * 1000 : null;

    db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return respond({ ok: false, error: "User not found." });
      if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

      db.run(
        `INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id, created_at)
         VALUES (?, 'ban', ?, ?, ?, ?)`,
        [target.id, expiresAt, String(reason || "").slice(0, 180), socket.user.id, Date.now()],
        () => {
          emitRoomSystem(
            room,
            `${username} was banned${expiresAt ? ` for ${mins} minutes` : " permanently"}.`,
            { kind: "mod" }
          );
const actorName = socket.user?.username || socket.request?.session?.user?.username || "system";
const why = String(reason || "").slice(0, 180) || "Banned by staff";
// Persist ban restriction for the restriction/appeals system (in addition to legacy punishments table)
setBanEverywhere(username, actorName, why).catch(()=>{});
const sid = socketIdByUserId.get(target.id);
if (sid) {
  io.to(sid).emit("restriction:status", { type: "ban", reason: why, expiresAt: null, now: Date.now() });
  io.sockets.sockets.get(sid)?.disconnect(true);
}
invalidateSessionsForUserId(target.id);

          logModAction({
            actor: socket.user,
            action: "BAN",
            targetUserId: target.id,
            targetUsername: target.username,
            room,
            details: expiresAt ? `minutes=${mins}` : `permanent reason=${String(reason || "").slice(0, 180)}`,
          });
          if (caseId) {
            addModCaseEvent(Number(caseId), {
              actorUserId: socket.user?.id || null,
              eventType: "ban",
              payload: { targetUserId: target.id, minutes: mins, reason: String(reason || "").slice(0, 180) },
            }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "ban" })).catch(() => {});
          }
          respond({ ok: true, username, minutes: mins });
        }
      );
    });
  });

  socket.on("mod unmute", ({ username, reason = "", caseId = null } = {}, ack) => {
    const respond = (payload) => { if (typeof ack === "function") ack(payload); };
    if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
    const room = socket.currentRoom;
    if (!room) return respond({ ok: false, error: "No active room." });
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return respond({ ok: false, error: "Not permitted." });

    username = sanitizeUsername(username);
    db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return respond({ ok: false, error: "User not found." });
      if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

      db.run("DELETE FROM punishments WHERE user_id=? AND type='mute'", [target.id], () => {
        emitRoomSystem(room, `${username} was unmuted.`, { kind: "mod" });
        logModAction({
          actor: socket.user,
          action: "UNMUTE",
          targetUserId: target.id,
          targetUsername: target.username,
          room,
          details: String(reason || "").slice(0, 180),
        });
        if (caseId) {
          addModCaseEvent(Number(caseId), {
            actorUserId: socket.user?.id || null,
            eventType: "unmute",
            payload: { targetUserId: target.id, reason: String(reason || "").slice(0, 180) },
          }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "unmute" })).catch(() => {});
        }
        respond({ ok: true, username: target.username });
      });
    });
  });

  socket.on("mod unban", ({ username, reason = "", caseId = null } = {}, ack) => {
    const respond = (payload) => { if (typeof ack === "function") ack(payload); };
    if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return respond({ ok: false, error: "Rate limited." });
    const room = socket.currentRoom;
    if (!room) return respond({ ok: false, error: "No active room." });
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return respond({ ok: false, error: "Not permitted." });

    username = sanitizeUsername(username);
    db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return respond({ ok: false, error: "User not found." });
      if (!canModerate(actorRole, target.role)) return respond({ ok: false, error: "Not permitted." });

      db.run("DELETE FROM punishments WHERE user_id=? AND type='ban'", [target.id], () => {
        emitRoomSystem(room, `${username} was unbanned.`, { kind: "mod" });
// Clear persistent restriction as well
const actorName = socket.user?.username || socket.request?.session?.user?.username || "system";
clearRestrictionEverywhere(username, actorName, String(reason || "").slice(0, 180) || "unban").catch(()=>{});
const sid = socketIdByUserId.get(target.id);
if (sid) {
  io.to(sid).emit("restriction:status", { type: "none", reason: "", expiresAt: null, now: Date.now() });
}
        logModAction({
          actor: socket.user,
          action: "UNBAN",
          targetUserId: target.id,
          targetUsername: target.username,
          room,
          details: String(reason || "").slice(0, 180),
        });
        if (caseId) {
          addModCaseEvent(Number(caseId), {
            actorUserId: socket.user?.id || null,
            eventType: "unban",
            payload: { targetUserId: target.id, reason: String(reason || "").slice(0, 180) },
          }).then(() => emitToStaff("mod:case_event", { caseId: Number(caseId), eventType: "unban" })).catch(() => {});
        }
        respond({ ok: true, username: target.username });
      });
    });
  });


// ---- Appeals (user + admin)
socket.on("restriction:check", async (_payload, ack) => {
  const username = socket.user?.username;
  const r = await getRestrictionByUsername(username);
  const payload = { type: r.type || "none", reason: r.reason || "", expiresAt: r.expiresAt || null, now: Date.now() };
  if (typeof ack === "function") ack(payload);
  else socket.emit("restriction:status", payload);
});

socket.on("appeal:fetchMine", async (_payload, ack) => {
  const username = socket.user?.username;
  const r = await getRestrictionByUsername(username);
  const open = await findOpenAppeal(username);
  let messages = [];
  if (open?.id) messages = await getAppealThread(open.id);
  const payload = { restriction: { type: r.type || "none", reason: r.reason || "", expiresAt: r.expiresAt || null, now: Date.now() }, appeal: open || null, messages };
  if (typeof ack === "function") ack(payload);
  else socket.emit("appeal:mine", payload);
});

socket.on("appeal:create", async ({ message } = {}, ack) => {
  const username = socket.user?.username;
  if (!allowSocketEvent(socket, "appeal_create", 3, 30_000)) {
    return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
  }
  const r = await getRestrictionByUsername(username);
  if (!username) return typeof ack === "function" ? ack({ ok: false, error: "Not authenticated" }) : null;
  if (!r?.type || r.type === "none") return typeof ack === "function" ? ack({ ok: false, error: "No active kick/ban." }) : null;

  let open = await findOpenAppeal(username);
  if (!open) open = await createAppeal(username, r.type, r.reason || "");
  if (!open?.id) return typeof ack === "function" ? ack({ ok: false, error: "Failed to create appeal." }) : null;

  await addAppealMessage(open.id, { authorRole: "user", authorName: username, message: String(message || "").slice(0, 2000) });
  const messages = await getAppealThread(open.id);

  // Notify staff
  io.emit("appeals:updated");

  if (typeof ack === "function") ack({ ok: true, appeal: open, messages });
});

socket.on("appeal:send", async ({ message } = {}, ack) => {
  const username = socket.user?.username;
  if (!allowSocketEvent(socket, "appeal_send", 5, 30_000)) {
    return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
  }
  if (!username) return typeof ack === "function" ? ack({ ok: false, error: "Not authenticated" }) : null;
  const open = await findOpenAppeal(username);
  if (!open?.id) return typeof ack === "function" ? ack({ ok: false, error: "No open appeal." }) : null;

  await addAppealMessage(open.id, { authorRole: "user", authorName: username, message: String(message || "").slice(0, 2000) });
  const messages = await getAppealThread(open.id);

  io.emit("appeals:updated");

  if (typeof ack === "function") ack({ ok: true, appeal: open, messages });
});

function isAppealsStaff(role){
  return requireMinRole(role, "Admin") || requireMinRole(role, "Co owner") || requireMinRole(role, "Owner");
}

// Referrals: Moderators can submit ban referrals; Admin+ can review and resolve.
function isReferralReviewer(role){
  return requireMinRole(role, "Admin") || requireMinRole(role, "Co-owner") || requireMinRole(role, "Owner");
}
function canCreateReferral(role){
  // Only Moderators submit referrals (Admins+ already have ban tools)
  return String(role || "") === "Moderator";
}

async function createReferral({ username, referredBy, referredByRole, reason }){
  const now = Date.now();
  const result = await dbRunAsync(
    `INSERT INTO referrals (username, referred_by, reason, notes, status, action_by, action_type, action_minutes, action_reason, created_at, updated_at)
     VALUES (?, ?, ?, NULL, 'open', NULL, NULL, NULL, NULL, ?, ?)`,
    [username, referredBy, reason, now, now]
  );
  try {
    const subjectUserId = await findUserIdByUsername(username);
    const actorUserId = await findUserIdByUsername(referredBy);
    const caseRow = await createModCase({
      type: "referral",
      subjectUserId,
      createdByUserId: actorUserId,
      title: `Referral #${result?.lastID || ""}`.trim(),
      summary: String(reason || "").slice(0, 800),
    });
    if (caseRow?.id) {
      await addModCaseEvent(caseRow.id, {
        actorUserId,
        eventType: "referral_created",
        payload: { referralId: result?.lastID || null, fromRole: referredByRole || null },
      });
      emitToStaff("mod:case_created", { id: caseRow.id, type: caseRow.type, status: caseRow.status });
    }
  } catch {}
}
async function listOpenReferrals(){
  return dbAllAsync(
    `SELECT id, username AS target_username, referred_by AS from_username, reason, status, created_at, updated_at
     FROM referrals
     WHERE status='open'
     ORDER BY created_at DESC
     LIMIT 200`
  );
}
async function resolveReferral({ id, actionBy }){
  const now = Date.now();
  await dbRunAsync(
    `UPDATE referrals SET status='acted', action_by=?, action_type='dismiss', updated_at=? WHERE id=?`,
    [actionBy, now, id]
  );
}

socket.on("appeals:list", async (_payload, ack) => {
  const actorRole = socket.request?.session?.user?.role || socket.user?.role || "User";
  if (!isAppealsStaff(actorRole)) return typeof ack === "function" ? ack({ ok: false, error: "Not allowed" }) : null;
  const items = await listOpenAppeals();
  if (typeof ack === "function") ack({ ok: true, items });
});

socket.on("appeals:read", async ({ appealId } = {}, ack) => {
  const actorRole = socket.request?.session?.user?.role || socket.user?.role || "User";
  if (!isAppealsStaff(actorRole)) return typeof ack === "function" ? ack({ ok: false, error: "Not allowed" }) : null;

  const id = Number(appealId);
  if (!Number.isFinite(id)) return typeof ack === "function" ? ack({ ok: false, error: "Invalid appeal" }) : null;

  let appeal = null;
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query("SELECT * FROM appeals WHERE id=$1 LIMIT 1", [id]);
      appeal = rows?.[0] || null;
    }
  } catch {}
  if (!appeal) {
    try { appeal = await dbGetAsync("SELECT * FROM appeals WHERE id=? LIMIT 1", [id]); } catch {}
  }
  if (!appeal) return typeof ack === "function" ? ack({ ok: false, error: "Not found" }) : null;

  const messages = await getAppealThread(id);
  const modlogs = await getModerationLogsForUser(appeal.username, 200);
  const restriction = await getRestrictionByUsername(appeal.username);

  if (typeof ack === "function") ack({ ok: true, appeal, messages, modlogs, restriction });
});

socket.on("appeals:reply", async ({ appealId, message } = {}, ack) => {
  const actorRole = socket.request?.session?.user?.role || socket.user?.role || "User";
  if (!allowSocketEvent(socket, "appeal_reply", 6, 30_000)) {
    return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
  }
  if (!isAppealsStaff(actorRole)) return typeof ack === "function" ? ack({ ok: false, error: "Not allowed" }) : null;

  const id = Number(appealId);
  if (!Number.isFinite(id)) return typeof ack === "function" ? ack({ ok: false, error: "Invalid appeal" }) : null;

  const actorName = socket.user?.username || "staff";
  await addAppealMessage(id, { authorRole: "admin", authorName: actorName, message: String(message || "").slice(0, 2000) });
  io.emit("appeals:updated");
  if (typeof ack === "function") ack({ ok: true });
});

socket.on("appeals:action", async ({ appealId, action, durationSeconds } = {}, ack) => {
  const actorRole = socket.request?.session?.user?.role || socket.user?.role || "User";
  if (!allowSocketEvent(socket, "appeal_action", 6, 30_000)) {
    return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
  }
  if (!isAppealsStaff(actorRole)) return typeof ack === "function" ? ack({ ok: false, error: "Not allowed" }) : null;

  const id = Number(appealId);
  if (!Number.isFinite(id)) return typeof ack === "function" ? ack({ ok: false, error: "Invalid appeal" }) : null;

  // Load appeal
  let appeal = null;
  try {
    if (PG_READY) {
      const { rows } = await pgPool.query("SELECT * FROM appeals WHERE id=$1 LIMIT 1", [id]);
      appeal = rows?.[0] || null;
    }
  } catch {}
  if (!appeal) {
    try { appeal = await dbGetAsync("SELECT * FROM appeals WHERE id=? LIMIT 1", [id]); } catch {}
  }
  if (!appeal) return typeof ack === "function" ? ack({ ok: false, error: "Not found" }) : null;

  const actorName = socket.user?.username || "staff";
  const act = String(action || "");

  if (act === "unlock" || act === "unban") {
    await clearRestrictionEverywhere(appeal.username, actorName, "staff unlock");
    // also clear legacy ban punishment if exists (best-effort)
    try {
      const urow = await dbGetAsync("SELECT id FROM users WHERE lower(username)=lower(?)", [appeal.username]);
      if (urow?.id) dbRunAsync("DELETE FROM punishments WHERE user_id=? AND type='ban'", [urow.id]).catch(()=>{});
    } catch {}
  } else if (act === "ban_to_kick") {
    const dur = Number(durationSeconds) || 3600;
    const { expiresAt } = await setKickEverywhere(appeal.username, actorName, "ban converted to kick", dur);
    // notify target if online
    const tid = await dbGetAsync("SELECT id FROM users WHERE lower(username)=lower(?)", [appeal.username]).catch(()=>null);
    const sid = tid?.id ? socketIdByUserId.get(tid.id) : null;
    if (sid) io.to(sid).emit("restriction:status", { type: "kick", reason: "Ban converted to kick", expiresAt, now: Date.now() });
  } else if (act === "update_kick") {
    const dur = Number(durationSeconds) || 3600;
    const { expiresAt } = await setKickEverywhere(appeal.username, actorName, "kick duration updated", dur);
    const tid = await dbGetAsync("SELECT id FROM users WHERE lower(username)=lower(?)", [appeal.username]).catch(()=>null);
    const sid = tid?.id ? socketIdByUserId.get(tid.id) : null;
    if (sid) io.to(sid).emit("restriction:status", { type: "kick", reason: "Kick updated", expiresAt, now: Date.now() });
  }

  // Optionally resolve appeal
  try {
    const now = Date.now();
    await dbRunAsync("UPDATE appeals SET status='resolved', updated_at=? WHERE id=?", [now, id]).catch(()=>{});
    if (PG_READY) await pgPool.query("UPDATE appeals SET status='resolved', updated_at=$1 WHERE id=$2", [now, id]).catch(()=>{});
  } catch {}

  io.emit("appeals:updated");
  if (typeof ack === "function") ack({ ok: true });
});

  // ---- Referrals ----
  socket.on("referrals:create", async ({ username, reason } = {}, ack) => {
    if (!allowSocketEvent(socket, "referral_create", 3, 30_000)) {
      return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
    }
    try{
      const actor = socket.request?.session?.user || socket.user || {};
      const actorRole = actor.role || "User";
      if(!canCreateReferral(actorRole)){
        return typeof ack === "function" ? ack({ ok:false, error:"Not allowed" }) : null;
      }
      const target = sanitizeUsername(username);
      const why = String(reason || "").trim().slice(0, 500);
      if(!target || !why){
        return typeof ack === "function" ? ack({ ok:false, error:"Missing username or reason" }) : null;
      }
      await createReferral({ username: target, referredBy: actor.username || "unknown", referredByRole: actorRole, reason: why });
      if(typeof ack === "function") ack({ ok:true });
    }catch(e){
      if(typeof ack === "function") ack({ ok:false, error:"Failed to create referral" });
    }
  });

  socket.on("referrals:list", async (_payload, ack) => {
    const actorRole = socket.request?.session?.user?.role || socket.user?.role || "User";
    if(!isReferralReviewer(actorRole)) return typeof ack === "function" ? ack({ ok:false, error:"Not allowed" }) : null;
    const items = await listOpenReferrals();
    if(typeof ack === "function") ack({ ok:true, items });
  });

  socket.on("referrals:resolve", async ({ id } = {}, ack) => {
    if (!allowSocketEvent(socket, "referral_resolve", 6, 30_000)) {
      return typeof ack === "function" ? ack({ ok: false, error: "Rate limited." }) : null;
    }
    try{
      const actor = socket.request?.session?.user || socket.user || {};
      const actorRole = actor.role || "User";
      if(!isReferralReviewer(actorRole)) return typeof ack === "function" ? ack({ ok:false, error:"Not allowed" }) : null;
      const rid = Number(id);
      if(!Number.isFinite(rid)) return typeof ack === "function" ? ack({ ok:false, error:"Invalid id" }) : null;
      await resolveReferral({ id: rid, actionBy: actor.username || "unknown" });
      if(typeof ack === "function") ack({ ok:true });
    }catch(e){
      if(typeof ack === "function") ack({ ok:false, error:"Failed to resolve" });
    }
  });

  socket.on("mod warn", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!allowSocketEvent(socket, "mod_action", 5, 5000)) return;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);
	    db.get("SELECT id, username FROM users WHERE lower(username)=lower(?)", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      emitRoomSystem(room, `${username} was warned: ${String(reason || "").slice(0, 120)}`, { kind: "mod" });
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

  socket.on("mod set role", ({ username, role, reason = "" } = {}, ack) => {
    const respond = (payload) => { if (typeof ack === "function") ack(payload); };
    if (!allowSocketEvent(socket, "mod_action", 4, 5000)) return respond({ ok: false, error: "Rate limited." });
    const room = socket.currentRoom;
    if (!room) return respond({ ok: false, error: "No active room." });

    const actor = socket.user;
    const actorRole = godmodeUsers.has(actor.id)
      ? "Owner"
      : (socket.user?.role || socket.request?.session?.user?.role || "User");

    // Admin+ can update roles via the moderation panel.
    if (!requireMinRole(actorRole, "Admin")) return respond({ ok: false, error: "Not permitted." });

    const rawName = String(username || "").trim().slice(0, 64);
    const sanitized = sanitizeUsername(rawName);
    role = String(role || "").trim();

    const normalizedRole = ROLES.find((r) => r.toLowerCase() === role.toLowerCase());
    if (!normalizedRole) return respond({ ok: false, error: "Invalid role." });
    role = normalizedRole;

    const lookupName = rawName || sanitized;
    if (!lookupName) return respond({ ok: false, error: "Invalid username." });

    findUserByMention(lookupName, (_e, found) => {
      if (!found) {
        io.to(socket.id).emit("system", buildSystemPayload(socket.currentRoom || "main", "User not found: " + lookupName));
        return respond({ ok: false, error: "User not found." });
      }

      const target = { id: found.id, username: found.username, oldRole: found.role };

      // Permission checks: you can only modify users below you.
      if (actorRole !== "Owner" && !canModerate(actorRole, target.oldRole)) return respond({ ok: false, error: "Not permitted." });

      // Prevent non-owners from assigning roles at/above themselves (or Admin+).
      if (actorRole !== "Owner") {
        if (roleRank(role) >= roleRank(actorRole)) return respond({ ok: false, error: "Not permitted." });
        if (roleRank(role) >= roleRank("Admin")) return respond({ ok: false, error: "Not permitted." });
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

        emitRoomSystem(room, `${target.username} role set to ${role}.${reason ? "" : ""}`, { kind: "mod" });
        emitUserList(room);
        respond({ ok: true, username: target.username, role });
      }).catch((e) => {
        console.error("[mod set role]", e);
        respond({ ok: false, error: "Role update failed." });
      });
    });
  });

  
  socket.on("refresh user list", () => {
    try {
      if (socket.currentRoom) emitUserList(socket.currentRoom);
    } catch {}
  });

socket.on("disconnect", () => {
    // socket.user is attached after successful auth; guard for anonymous / early disconnects
    if (socket.user?.username) ONLINE_USERS.delete(socket.user.username);
    emitOnlineUsers();

    const room = socket.currentRoom;

    // Always clear per-socket rate tracking
    msgRate.delete(socket.id);
    socketEventRate.delete(socket.id);
    releaseSocketConnection(getSocketIp(socket));

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

    // Clear DM typing indicators for any DM rooms this socket was in.
    try {
      const u = socket.user?.username;
      if (u && socket.dmThreads && socket.dmThreads.size) {
        for (const tid of socket.dmThreads) {
          const set = dmTypingByThread.get(tid);
          if (set && set.has(u)) {
            set.delete(u);
            if (set.size === 0) dmTypingByThread.delete(tid);
            broadcastDmTyping(tid);
          }
        }
      }
    } catch {}
  });

});

// ---- Start
const startupReady = Promise.allSettled([migrationsReady, pgInitPromise]);
let SERVER_STARTED = false;
async function startServer() {
  if (SERVER_STARTED) return httpServer;
  const results = await startupReady;
  const [sqliteResult, pgResult] = results;
  if (sqliteResult.status === "rejected") {
    console.error("[startup] SQLite migration failed", sqliteResult.reason);
    process.exit(1);
  }
  if (pgResult.status === "rejected") {
    console.error("[startup] Postgres init failed", pgResult.reason);
    if (IS_PROD) {
      process.exit(1);
    }
  }

  try {
    await ensureCoreRoomsExist();
  } catch (e) {
    console.warn("[startup] core room ensure failed", e?.message || e);
  }

  await ensureDevSeedUser();

  await new Promise((resolve) => {
    httpServer.listen(PORT, () => {
      SERVER_STARTED = true;
      console.log(`Server running on http://localhost:${PORT}`);
      resolve();
    });
  });
  return httpServer;
}

if (require.main === module) {
  startServer();
}

module.exports = { app, httpServer, io, startServer, startupReady };


function normalizeUserKey(value) {
  return String(value || "").trim().toLowerCase();
}
function areIrisAndLolaOnline() {
  const online = new Set(Array.from(ONLINE_USERS).map((name) => normalizeUserKey(name)));
  return online.has(normalizeUserKey("Iri")) && online.has(normalizeUserKey("Lola Henderson"));
}

function canUseTheme(user, themeName) {
  const rule = PRIVATE_THEME_ALLOWLIST[themeName];
  if (rule) {
    const userId = user?.id ?? user?.user_id ?? user?.userId;
    if (userId != null && Array.isArray(rule.userIds) && rule.userIds.length) {
      if (!rule.userIds.map(String).includes(String(userId))) return false;
    } else {
      const uname = normalizeUserKey(user?.username || "");
      const allowed = (rule.users || []).some((name) => normalizeUserKey(name) === uname);
      if (!allowed) return false;
    }
    if (rule.requireBothOnline && !areIrisAndLolaOnline()) return false;
    return true;
  }
  return true;
}
