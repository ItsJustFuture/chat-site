// server.js
"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const multer = require("multer");
const http = require("http");
const { Server } = require("socket.io");
const sqlite3 = require("sqlite3").verbose();

const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");
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
});
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

function ensureDmSchema(cb) {
  db.serialize(() => {
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

    let pending = 2;
    let done = false;
    const finish = (err) => {
      if (done) return;
      if (err) {
        done = true;
        return cb(err);
      }
      if (--pending === 0) {
        done = true;
        cb();
      }
    };

    ensureTableColumns(
      "dm_threads",
      [
        ["title", "title TEXT"],
        ["is_group", "is_group INTEGER NOT NULL DEFAULT 0"],
        ["created_by", "created_by INTEGER NOT NULL DEFAULT 0"],
        ["created_at", "created_at INTEGER NOT NULL DEFAULT 0"],
      ],
      finish
    );

    ensureTableColumns(
      "dm_participants",
      [
        ["added_by", "added_by INTEGER"],
        ["joined_at", "joined_at INTEGER NOT NULL DEFAULT 0"],
      ],
      finish
    );
  });
}

// ---- Security + parsing
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// IMPORTANT: CSP that blocks inline JS (good), but allows our external /public/app.js & /public/styles.css
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "script-src-elem 'self'",
      // we use an external stylesheet, so no unsafe-inline required
      "style-src 'self'",
      // allow avatars/uploads + blob previews on client
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      // socket.io
      "connect-src 'self' ws: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  next();
});

// ---- Sessions (works locally + Render)
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      // secure cookies in production (Render). With trust proxy set, this will work.
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);
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
function clamp(n, a, b) {
  n = Number(n);
  if (!Number.isFinite(n)) return a;
  return Math.max(a, Math.min(b, n));
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
function requireMinRole(role, minRole) {
  return roleRank(role) >= roleRank(minRole);
}
function canModerate(actorRole, targetRole) {
  // can only moderate lower roles
  return roleRank(actorRole) > roleRank(targetRole);
}
const AUTO_OWNER = new Set(["iri"]);
const AUTO_COOWNERS = new Set(["lola henderson", "amelia"]);

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

// ---- Auth routes
app.post("/register", async (req, res) => {
  try {
    const username = sanitizeUsername(req.body?.username);
    const password = String(req.body?.password || "");

    if (!username || username.length < 2) return res.status(400).send("Invalid username");
    if (!password || password.length < 6) return res.status(400).send("Password must be 6+ chars");

    db.get(
      "SELECT id FROM users WHERE lower(username) = lower(?)",
      [username],
      async (checkErr, existing) => {
        if (checkErr) return res.status(500).send("Register failed");
        if (existing) return res.status(409).send("Username already taken");

        const password_hash = await bcrypt.hash(password, 10);
        const role = AUTO_COOWNERS.has(normKey(username)) ? "Co-owner" : "User";

        db.run(
          `INSERT INTO users (username, password_hash, role, created_at, last_seen, last_status)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [username, password_hash, role, Date.now(), Date.now(), "Online"],
          function (err) {
            if (err) {
              if (String(err.message || "").includes("UNIQUE")) return res.status(409).send("Username already taken");
              return res.status(500).send("Register failed");
            }
            return res.json({ ok: true });
          }
        );
      }
    );
  } catch {
    return res.status(500).send("Register failed");
  }
});

app.post("/login", (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = String(req.body?.password || "");
  if (!username || !password) return res.status(400).send("Missing credentials");

  db.get(
    "SELECT * FROM users WHERE lower(username) = lower(?)",
    [username],
    async (err, row) => {
      if (err || !row) return res.status(401).send("Invalid username or password");
      let passwordHash = typeof row.password_hash === "string" ? row.password_hash : "";

      if (!passwordHash) {
        const legacyPassword = typeof row.password === "string" ? row.password : "";
        if (!legacyPassword) return res.status(401).send("Invalid username or password");

        const legacyMatches = legacyPassword.startsWith("$2")
          ? await bcrypt.compare(password, legacyPassword)
          : legacyPassword === password;
        if (!legacyMatches) return res.status(401).send("Invalid username or password");

        passwordHash = legacyPassword.startsWith("$2")
          ? legacyPassword
          : await bcrypt.hash(password, 10);
        db.run("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [passwordHash, row.id]);
      }

      const ok = await bcrypt.compare(password, passwordHash);
      if (!ok) return res.status(401).send("Invalid username or password");

      const norm = normKey(row.username);
      if (AUTO_OWNER.has(norm) && row.role !== "Owner") {
        db.run("UPDATE users SET role = 'Owner' WHERE id = ?", [row.id]);
        row.role = "Owner";
      } else if (AUTO_COOWNERS.has(norm) && row.role !== "Co-owner") {
        db.run("UPDATE users SET role = 'Co-owner' WHERE id = ?", [row.id]);
        row.role = "Co-owner";
      }

      req.session.user = { id: row.id, username: row.username, role: row.role };

      db.run("UPDATE users SET last_seen = ?, last_status = ? WHERE id = ?", [Date.now(), "Online", row.id]);

      // Ensure session is actually persisted before replying
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).send("Session save failed");
        return res.json({ ok: true });
      });
    }
  );
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/me", (req, res) => {
  if (!req.session?.user?.id) return res.json(null);
  return res.json(req.session.user);
});

// ---- Profile routes
app.get("/profile", requireLogin, (req, res) => {
  db.get(
    `SELECT id, username, role, avatar, bio, mood, age, gender, created_at, last_seen, last_room, last_status
     FROM users WHERE id = ?`,
    [req.session.user.id],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      const live = onlineState.get(row.id);
      return res.json({
        ...row,
        current_room: live?.room || null,
        last_status: live?.status || row.last_status || null,
      });
    }
  );
});

app.get("/profile/:username", requireLogin, (req, res) => {
  const u = sanitizeUsername(req.params.username);
  if (!u) return res.status(400).send("Bad username");

  db.get(
    `SELECT id, username, role, avatar, bio, mood, age, gender, created_at, last_seen, last_room, last_status
     FROM users WHERE lower(username) = lower(?)`,
    [u],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      const live = onlineState.get(row.id);
      return res.json({
        ...row,
        current_room: live?.room || null,
        last_status: live?.status || row.last_status || null,
      });
    }
  );
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
  limits: { fileSize: 2 * 1024 * 1024 },
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

  db.get("SELECT avatar FROM users WHERE id = ?", [req.session.user.id], (e, old) => {
    const newAvatar = avatar || old?.avatar || null;

    db.run(
      `UPDATE users SET mood=?, bio=?, age=?, gender=?, avatar=? WHERE id=?`,
      [mood, bio, age, gender, newAvatar, req.session.user.id],
      (err2) => {
        if (err2) return res.status(500).send("Save failed");
        return res.json({ ok: true });
      }
    );
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
  limits: { fileSize: 10 * 1024 * 1024 },
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
app.get("/dm/threads", requireLogin, (req, res) => {
  const userId = req.session.user.id;

  db.all(
    `SELECT t.id, t.title, t.is_group, t.created_at,
            (SELECT text FROM dm_messages WHERE thread_id=t.id ORDER BY ts DESC LIMIT 1) AS last_text,
            (SELECT ts FROM dm_messages WHERE thread_id=t.id ORDER BY ts DESC LIMIT 1) AS last_ts
     FROM dm_threads t
     INNER JOIN dm_participants p ON p.thread_id = t.id
     WHERE p.user_id = ?
     ORDER BY COALESCE(last_ts, t.created_at) DESC`,
    [userId],
    (err, threads) => {
      if (err) return res.status(500).send("Failed to load threads");
      if (!threads?.length) return res.json([]);

      const ids = threads.map((t) => t.id);
      const placeholders = ids.map(() => "?").join(",");

      db.all(
        `SELECT dp.thread_id, u.username FROM dm_participants dp JOIN users u ON u.id = dp.user_id WHERE dp.thread_id IN (${placeholders})`,
        ids,
        (_e, parts) => {
          const grouped = new Map();
          for (const p of parts || []) {
            if (!grouped.has(p.thread_id)) grouped.set(p.thread_id, []);
            grouped.get(p.thread_id).push(p.username);
          }

          const result = threads.map((t) => ({
            ...t,
            participants: grouped.get(t.id) || [],
          }));
          res.json(result);
        }
      );
    }
  );
});

app.post("/dm/thread", requireLogin, (req, res) => {
  let participants = req.body?.participants;
  if (!Array.isArray(participants)) {
    const raw = String(participants || req.body?.participant || req.body?.user || "");
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

  fetchUsersByNames(cleaned, (err, users) => {
    if (err) return res.status(500).send("Failed to create thread");
    if (users.length !== cleaned.length) return res.status(404).send("User not found");

    const now = Date.now();
    const isGroup = kindRaw === "group"
      ? true
      : (kindRaw === "direct" ? false : (users.length + 1 > 2 || !!title));

    // If it's a direct DM, reuse existing 1:1 thread (prevents duplicates)
    const myId = req.session.user.id;
    if (!isGroup && users.length === 1) {
      const otherId = users[0].id;
      db.get(
        `
        SELECT t.id AS id
        FROM dm_threads t
        WHERE t.is_group = 0
          AND (SELECT COUNT(*) FROM dm_participants dp WHERE dp.thread_id = t.id) = 2
          AND EXISTS (SELECT 1 FROM dm_participants dp WHERE dp.thread_id = t.id AND dp.user_id = ?)
          AND EXISTS (SELECT 1 FROM dm_participants dp WHERE dp.thread_id = t.id AND dp.user_id = ?)
        LIMIT 1
        `,
        [myId, otherId],
        (reuseErr, row) => {
          if (reuseErr) return res.status(500).send("Failed to create thread");
          if (row?.id) return res.json({ ok: true, threadId: row.id, reused: true });
          return createNewThread();
        }
      );
      return;
    }

    return createNewThread();

    function createNewThread() {
      db.run(
        `INSERT INTO dm_threads (title, is_group, created_by, created_at) VALUES (?, ?, ?, ?)`,
        [title || null, isGroup ? 1 : 0, myId, now],
        function (insertErr) {
          if (insertErr) return res.status(500).send("Failed to create thread");
          const threadId = this.lastID;

          const participantIds = users.map((u) => u.id);
          participantIds.push(myId);

          for (const uid of participantIds) {
            db.run(
              `INSERT OR IGNORE INTO dm_participants (thread_id, user_id, added_by, joined_at) VALUES (?, ?, ?, ?)`,
              [threadId, uid, myId, now]
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

          res.json({ ok: true, threadId });
        }
      );
    }
  });
});

// ---- Real-time presence tracking
const onlineState = new Map(); // userId -> { room, status }
const socketIdByUserId = new Map(); // userId -> socket.id
const typingByRoom = new Map(); // room -> Set(username)
const msgRate = new Map(); // socket.id -> { lastTs, count }

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
  // express-session is cookie-based; socket.io shares cookies.
  // We just trust that the client loaded the page after login.
  // If not logged in, disconnect.
  const req = socket.request;
  const res = req.res || {};
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: !!process.env.RENDER },
  })(req, res, () => {
    if (!req.session?.user?.id) return next(new Error("Not authenticated"));
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
      users.push({
        name: s.user.username,
        role: s.user.role,
        status: s.user.status || "Online",
        mood: s.user.mood || "",
        avatar: s.user.avatar || "",
      });
    }
  }

  // Sort by role then name
  users.sort((a, b) => {
    const ra = roleRank(a.role);
    const rb = roleRank(b.role);
    if (ra !== rb) return rb - ra;
    return a.name.localeCompare(b.name);
  });

  io.to(room).emit("user list", users);
}

// ---- Socket handlers
io.on("connection", (socket) => {
  const sessUser = socket.request.session.user;
  socket.user = {
    id: sessUser.id,
    username: sessUser.username,
    role: sessUser.role,
    status: "Online",
    mood: "",
    avatar: "",
  };

  socketIdByUserId.set(socket.user.id, socket.id);

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
    room = String(room || "").trim().toLowerCase();
    if (!room) room = "main";
    if (!["main", "nsfw", "music"].includes(room)) room = "main";

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

    socket.user.status = String(status || socket.user.status || "Online").slice(0, 32);

    onlineState.set(socket.user.id, { room, status: socket.user.status });

    db.run("UPDATE users SET last_room=?, last_status=? WHERE id=?", [
      room,
      socket.user.status,
      socket.user.id,
    ]);

   // Send history (exclude deleted messages entirely)
db.all(
  `SELECT id, room, username, role, avatar, text, ts, attachment_url, attachment_type, attachment_mime, attachment_size
   FROM messages
   WHERE room=? AND deleted=0
   ORDER BY ts ASC
   LIMIT 200`,
  [room],
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
    }));
    socket.emit("history", history);

    // reactions for recent messages
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
    socket.emit("system", `Joined #${room}`);
    emitUserList(room);
  });

  socket.on("typing", () => {
    const room = socket.currentRoom;
    if (!room) return;

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
        `SELECT id, thread_id, user_id, username, text, ts FROM dm_messages WHERE thread_id=? ORDER BY ts DESC LIMIT 50`,
        [tid],
        (_e, rows) => {
          const msgs = (rows || []).reverse();
          socket.emit("dm history", {
            threadId: tid,
            title: thread.title || "",
            isGroup: !!thread.is_group,
            participants: thread.participants || [],
            messages: msgs,
          });
        }
      );
    });
  });

  socket.on("dm message", ({ threadId, text }) => {
    const tid = Number(threadId);
    const body = String(text || "").trim().slice(0, 800);
    if (!Number.isInteger(tid) || !body) return;

    loadThreadForUser(tid, socket.user.id, (err, thread) => {
      if (err) return;
      const ts = Date.now();

      db.run(
        `INSERT INTO dm_messages (thread_id, user_id, username, text, ts) VALUES (?, ?, ?, ?, ?)`,
        [tid, socket.user.id, socket.user.username, body, ts],
        function (insertErr) {
          if (insertErr) return;
          const payload = {
            threadId: tid,
            messageId: this.lastID,
            userId: socket.user.id,
            user: socket.user.username,
            text: body,
            ts,
          };
          io.to(`dm:${tid}`).emit("dm message", payload);
          if (Array.isArray(thread.participants)) {
            db.all(
              `SELECT user_id FROM dm_participants WHERE thread_id = ?`,
              [tid],
              (_e2, rows) => {
                for (const r of rows || []) {
                  const sid = socketIdByUserId.get(r.user_id);
                  const s = sid ? io.sockets.sockets.get(sid) : null;
                  if (s && !s.rooms.has(`dm:${tid}`)) {
                    s.emit("dm message", payload);
                  }
                }
              }
            );
          }
        }
      );
    });
  });

  socket.on("status change", ({ status }) => {
    status = String(status || "Online").slice(0, 32);
    socket.user.status = status;

    const st = onlineState.get(socket.user.id);
    if (st) st.status = status;

    db.run("UPDATE users SET last_status=? WHERE id=?", [status, socket.user.id]);

    if (socket.currentRoom) emitUserList(socket.currentRoom);
  });

  socket.on("chat message", (payload) => {
    const room = socket.currentRoom;
    if (!room) return;

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
        const attachmentUrl = String(payload?.attachmentUrl || "").slice(0, 400);
        const attachmentType = String(payload?.attachmentType || "").slice(0, 20);
        const attachmentMime = String(payload?.attachmentMime || "").slice(0, 60);
        const attachmentSize = Number(payload?.attachmentSize || 0) || 0;

        db.run(
          `INSERT INTO messages (room, user_id, username, role, avatar, text, ts, attachment_url, attachment_type, attachment_mime, attachment_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            room,
            socket.user.id,
            socket.user.username,
            socket.user.role,
            socket.user.avatar || "",
            text,
            Date.now(),
            attachmentUrl || null,
            attachmentType || null,
            attachmentMime || null,
            attachmentSize || null,
          ],
          function () {
            const msg = {
              messageId: this.lastID,
              room,
              user: socket.user.username,
              role: socket.user.role,
              avatar: socket.user.avatar || "",
              text,
              ts: Date.now(),
              attachmentUrl: attachmentUrl || "",
              attachmentType: attachmentType || "",
              attachmentMime: attachmentMime || "",
              attachmentSize: attachmentSize || 0,
            };
            io.to(room).emit("chat message", msg);
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
});

// ---- Start
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
