// server.js (clean rebuild)
// Includes:
// - Rooms + member list + statuses + typing
// - Login/Register (sessions) + persistent users/roles/profiles (SQLite)
// - Avatars upload (2MB) + chat uploads (images 10MB; VIP+ videos mp4/mov 10MB)
// - Messages persisted (with attachments) + loads last 50 on join
// - Reactions (1 per user per message, server authoritative)
// - Moderation: delete message, kick, mute/unmute, ban/unban, warn (auto escalate), set role (Owner)
// - Moderation logs + /mod/logs endpoint
// - Security: strict upload allowlist, server-chosen extensions, rate limits, nosniff for uploads

require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { randomUUID } = require("crypto");
const onlineState = new Map(); // userId -> { room, status }
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

const PORT = process.env.PORT || 3000;
const MIN_AGE = 18;
const OWNER_USERNAME = process.env.OWNER_USERNAME || "Garrett";

// Trust proxy (Render/Reverse proxies)
app.set("trust proxy", 1);

// -------------------- Paths --------------------
const publicDir = path.join(__dirname, "public");
const avatarDir = path.join(publicDir, "avatars");
const uploadDir = path.join(publicDir, "uploads");
fs.mkdirSync(publicDir, { recursive: true });
fs.mkdirSync(avatarDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

// -------------------- Middleware --------------------
app.use(helmet({ contentSecurityPolicy: false })); // allow inline scripts in index.html
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "change-me-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false },
});
app.use(sessionMiddleware);

// Static site
app.use(express.static(publicDir));

// Hardened static serving for uploads
app.use("/uploads", express.static(uploadDir, {
  setHeaders: (res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  }
}));

// Rate limits
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
app.use("/login", authLimiter);
app.use("/register", authLimiter);

const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use("/upload", uploadLimiter);

// -------------------- DB --------------------
const db = new sqlite3.Database(path.join(__dirname, "chat.db"));

function roleRank(role) {
  return ({
    "Owner": 6,
    "Co-owner": 5,
    "Admin": 4,
    "Moderator": 3,
    "VIP": 2,
    "User": 1,
    "Guest": 0,
  }[role] ?? 1);
}

function normalizeRole(role) {
  const allowed = ["Owner", "Co-owner", "Admin", "Moderator", "VIP", "User", "Guest"];
  return allowed.includes(role) ? role : "User";
}

function canModerate(actorRole, targetRole) {
  return roleRank(actorRole) > roleRank(targetRole);
}

function requireMinRole(actorRole, minRole) {
  return roleRank(actorRole) >= roleRank(minRole);
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.sendStatus(401);
  next();
}
function normalizeUsername(u){
  return String(u || "").trim().toLowerCase();
}

const AUTO_COOWNERS = new Set([
  "lola henderson",
  "amelia"
]);

function ensureOwnerRoleIfNeeded(userRow, cb) {
  if (userRow.username === OWNER_USERNAME && userRow.role !== "Owner") {
    db.run("UPDATE users SET role = 'Owner' WHERE id = ?", [userRow.id], () => cb("Owner"));
    return;
  }
  cb(normalizeRole(userRow.role));
}

// --- Safe migrations (no req/socket here) ---
function addColumnIfMissing(table, col, ddl, done) {
  db.all(`PRAGMA table_info(${table})`, (_e, rows) => {
    rows = rows || [];
    const exists = rows.some(r => r.name === col);
    if (exists) return done?.();
    db.run(`ALTER TABLE ${table} ADD COLUMN ${ddl}`, () => done?.());
  });
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'User',
      bio TEXT DEFAULT '',
      mood TEXT DEFAULT '',
      age INTEGER,
      gender TEXT,
      avatar TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      room TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      role TEXT NOT NULL,
      text TEXT NOT NULL,
      ts INTEGER NOT NULL,
      deleted INTEGER DEFAULT 0,
      attachment_url TEXT DEFAULT '',
      attachment_type TEXT DEFAULT '',
      attachment_mime TEXT DEFAULT '',
      attachment_size INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS punishments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,        -- ban|mute
      expires_at INTEGER,        -- null => permanent
      reason TEXT DEFAULT '',
      by_user_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS warns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      reason TEXT DEFAULT '',
      by_user_id INTEGER NOT NULL,
      by_username TEXT NOT NULL,
      by_role TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS mod_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      actor_user_id INTEGER NOT NULL,
      actor_username TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      target_user_id INTEGER,
      target_username TEXT,
      room TEXT,
      details TEXT DEFAULT ''
    )
  `);

  // In case your DB existed before and is missing attachment columns:
  addColumnIfMissing("messages", "attachment_url",  "attachment_url TEXT DEFAULT ''");
  addColumnIfMissing("messages", "attachment_type", "attachment_type TEXT DEFAULT ''");
  addColumnIfMissing("messages", "attachment_mime", "attachment_mime TEXT DEFAULT ''");
  addColumnIfMissing("messages", "attachment_size", "attachment_size INTEGER DEFAULT 0");
  addColumnIfMissing("users", "last_seen", "last_seen INTEGER");
  addColumnIfMissing("users", "last_room", "last_room TEXT");
  addColumnIfMissing("users", "last_status", "last_status TEXT");
});

// -------------------- Moderation logging --------------------
function logModAction({ actor, action, targetUserId = null, targetUsername = null, room = null, details = "" }) {
  db.run(
    `INSERT INTO mod_logs
     (ts, actor_user_id, actor_username, actor_role, action, target_user_id, target_username, room, details)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      Date.now(),
      actor.id,
      actor.username,
      actor.role,
      String(action),
      targetUserId,
      targetUsername,
      room,
      String(details || "").slice(0, 1000),
    ]
  );
}

function isActivePunishment(p) {
  if (!p) return false;
  if (p.expires_at == null) return true;
  return Number(p.expires_at) > Date.now();
}

function getActiveBanMute(userId, cb) {
  db.all(
    "SELECT * FROM punishments WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC",
    [userId, Date.now()],
    (_err, rows) => {
      rows = rows || [];
      const ban = rows.find(r => r.type === "ban");
      const mute = rows.find(r => r.type === "mute");
      cb({ ban, mute });
    }
  );
}

function countWarns(userId, cb) {
  db.get("SELECT COUNT(*) AS c FROM warns WHERE user_id = ?", [userId], (_e, row) => {
    cb(row?.c ? Number(row.c) : 0);
  });
}

// -------------------- Uploads (Multer) --------------------

// Avatars (2MB, images only)
const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, avatarDir),
  filename: (req, file, cb) => {
    const userId = req.session?.user?.id;
    const mime = String(file.mimetype || "").toLowerCase();
    let ext = ".png";
    if (mime === "image/jpeg") ext = ".jpg";
    else if (mime === "image/webp") ext = ".webp";
    else if (mime === "image/gif") ext = ".gif";
    cb(null, `${userId}${ext}`);
  },
});

const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(file.mimetype);
    cb(ok ? null : new Error("Only image uploads allowed"), ok);
  },
});

// Chat uploads (10MB). Everyone: images. VIP+: videos mp4/mov.
const chatUploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const id = randomUUID();
    const mime = String(file.mimetype || "").toLowerCase();

    let ext = "";
    if (mime === "image/png") ext = ".png";
    else if (mime === "image/jpeg") ext = ".jpg";
    else if (mime === "image/webp") ext = ".webp";
    else if (mime === "image/gif") ext = ".gif";
    else if (mime === "video/mp4") ext = ".mp4";
    else if (mime === "video/quicktime") ext = ".mov";

    cb(null, `${id}${ext}`);
  }
});

const chatUpload = multer({
  storage: chatUploadStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const mime = String(file.mimetype || "").toLowerCase();
    const isImage = ["image/png","image/jpeg","image/webp","image/gif"].includes(mime);
    const isVideo = ["video/mp4","video/quicktime"].includes(mime);

    const role = req.session?.user?.role || "User";
    const vipPlus = roleRank(role) >= roleRank("VIP");

    if (isImage) return cb(null, true);
    if (vipPlus && isVideo) return cb(null, true);

    cb(new Error("File type not allowed (videos require VIP+)."), false);
  }
});

// -------------------- Routes --------------------
app.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().slice(0, 24);
    const password = String(req.body.password || "");

    if (username.length < 3) return res.status(400).send("Username must be at least 3 characters.");
    if (password.length < 6) return res.status(400).send("Password must be at least 6 characters.");

    const password_hash = await bcrypt.hash(password, 12);

    db.run(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'User')",
      [username, password_hash],
      (err) => {
        if (err) {
          if (String(err.message || "").includes("UNIQUE")) return res.status(400).send("Username already exists.");
          return res.status(500).send("Register failed.");
        }
        res.send("Registered");
      }
    );
  } catch {
    res.status(500).send("Register failed.");
  }
});

app.post("/login", (req, res) => {
  const username = String(req.body.username || "").trim().slice(0, 24);
  const password = String(req.body.password || "");

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.status(401).send("Invalid login.");

    getActiveBanMute(user.id, async ({ ban }) => {
      if (ban && isActivePunishment(ban)) return res.status(403).send("You are banned.");

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).send("Invalid login.");

      ensureOwnerRoleIfNeeded(user, (fixedRole) => {
        req.session.user = { id: user.id, username: user.username, role: fixedRole };
        res.send("Logged in");
        const uname = normalizeUsername(row.username);
if (AUTO_COOWNERS.has(uname) && row.role !== "Co-owner") {
  db.run(
    "UPDATE users SET role = 'Co-owner' WHERE id = ?",
    [row.id]
  );
  row.role = "Co-owner";
}
      });
    });
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.send("Logged out"));
});

app.get("/me", (req, res) => {
  res.json(req.session.user || null);
});

// My profile
app.get("/profile", requireLogin, (req, res) => {
  db.get(
    "SELECT id, username, role, bio, mood, age, gender, avatar, created_at FROM users WHERE id = ?",
    [req.session.user.id],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      res.json(row);
    }
  );
});

// Public profile
app.get("/profile/:username", (req, res) => {
  const u = String(req.params.username || "").trim().slice(0, 24);

  db.get(
    "SELECT id, username, role, bio, mood, age, gender, avatar, created_at, last_seen, last_room, last_status FROM users WHERE username = ?",
    [u],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");

      const live = onlineState.get(row.id); // make sure onlineState exists
      return res.json({
        ...row,
        current_room: live?.room || null,
        last_status: live?.status || row.last_status || null,
      });
    }
  );
});

// Update profile (+ avatar)
app.post("/profile", requireLogin, uploadAvatar.single("avatar"), (req, res) => {
  const bio = String(req.body.bio || "").slice(0, 400);
  const mood = String(req.body.mood || "").slice(0, 60);

  // min age enforcement
  let age = null;
  if (req.body.age !== "" && req.body.age != null) {
    const n = Number(req.body.age);
    if (!Number.isFinite(n)) return res.status(400).send("Invalid age.");
    if (n < MIN_AGE) return res.status(400).send(`Minimum age is ${MIN_AGE}.`);
    age = Math.min(120, Math.floor(n));
  }

  const gender = String(req.body.gender || "").slice(0, 24) || null;
  const avatarPath = req.file ? `/avatars/${req.file.filename}` : null;

  db.run(
    `UPDATE users
     SET bio = ?, mood = ?, age = ?, gender = ?, avatar = COALESCE(?, avatar)
     WHERE id = ?`,
    [bio, mood, age, gender, avatarPath, req.session.user.id],
    (err) => {
      if (err) return res.status(500).send("Profile update failed.");
      res.send("Profile updated");
    }
  );
});

// Upload endpoint for chat attachments
app.post("/upload", requireLogin, (req, res) => {
  chatUpload.single("file")(req, res, (err) => {
    if (err) return res.status(400).send(String(err.message || "Upload failed."));
    if (!req.file) return res.status(400).send("No file uploaded.");

    const mime = String(req.file.mimetype || "").toLowerCase();
    let type = "file";
    if (mime.startsWith("image/")) type = "image";
    if (mime === "video/mp4" || mime === "video/quicktime") type = "video";

    res.json({
      url: `/uploads/${req.file.filename}`,
      type,
      mime,
      size: req.file.size
    });
  });
});

// Mod logs API (Moderator+)
app.get("/mod/logs", requireLogin, (req, res) => {
  const role = req.session.user.role;
  if (roleRank(role) < roleRank("Moderator")) return res.sendStatus(403);

  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));
  const user = String(req.query.user || "").trim().slice(0, 24);
  const action = String(req.query.action || "").trim().slice(0, 40);

  let sql = "SELECT * FROM mod_logs";
  const where = [];
  const params = [];

  if (user) {
    where.push("(actor_username = ? OR target_username = ?)");
    params.push(user, user);
  }
  if (action) {
    where.push("action = ?");
    params.push(action);
  }
  if (where.length) sql += " WHERE " + where.join(" AND ");
  sql += " ORDER BY ts DESC LIMIT ?";
  params.push(limit);

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).send("Failed to load logs.");
    res.json(rows || []);
  });
});

// -------------------- Socket.IO session bridge --------------------
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));
io.use((socket, next) => {
  const sess = socket.request.session;
  if (!sess?.user) return next(new Error("Unauthorized"));
  socket.user = sess.user; // {id, username, role}
  next();
});

// -------------------- Realtime state --------------------
const roomsState = new Map();        // room -> Map(socket.id -> userObj)
const typingState = new Map();       // room -> Set(username)
const reactionsState = new Map();    // room -> Map(messageId -> { username: emoji })
const socketIdByUserId = new Map();  // userId -> socket.id

function getRoomMap(room) {
  if (!roomsState.has(room)) roomsState.set(room, new Map());
  return roomsState.get(room);
}
function getTypingSet(room) {
  if (!typingState.has(room)) typingState.set(room, new Set());
  return typingState.get(room);
}
function getRoomReactions(room) {
  if (!reactionsState.has(room)) reactionsState.set(room, new Map());
  return reactionsState.get(room);
}

function emitUserList(room) {
  const map = getRoomMap(room);
  const list = Array.from(map.values()).map(u => ({
    id: u.userId,
    name: u.username,
    role: u.role,
    status: u.status,
    avatar: u.avatar,
    mood: u.mood,
  }));
  io.to(room).emit("user list", list);
}

function leaveCurrentRoom(socket) {
  const prev = socket.currentRoom;
  if (!prev) return;

  socket.leave(prev);

  const map = getRoomMap(prev);
  map.delete(socket.id);

  const tset = getTypingSet(prev);
  if (tset.delete(socket.user.username)) {
    socket.to(prev).emit("typing update", Array.from(tset));
  }

  emitUserList(prev);
  socket.currentRoom = null;
}

// -------------------- Message rate limit --------------------
const msgRate = new Map(); // socket.id -> {tokens,last}
function allowMsg(socketId) {
  const now = Date.now();
  const cap = 6;
  const refillPerMs = 6 / 4000;
  const prev = msgRate.get(socketId) || { tokens: cap, last: now };
  const elapsed = now - prev.last;
  const tokens = Math.min(cap, prev.tokens + elapsed * refillPerMs);
  const ok = tokens >= 1;
  msgRate.set(socketId, { tokens: ok ? tokens - 1 : tokens, last: now });
  return ok;
}

// -------------------- Socket handlers --------------------
io.on("connection", (socket) => {
  socket.currentRoom = null;
  socketIdByUserId.set(socket.user.id, socket.id);

  socket.on("join room", ({ room, status }) => {
    room = String(room || "general").toLowerCase();
    status = String(status || "Online");

    getActiveBanMute(socket.user.id, ({ ban }) => {
      if (ban && isActivePunishment(ban)) {
        socket.emit("system", "You are banned.");
        return;
        onlineState.set(socket.user.id, { room, status });
db.run(
  "UPDATE users SET last_room = ?, last_status = ? WHERE id = ?",
  [room, status, socket.user.id]
);

      }

      leaveCurrentRoom(socket);
      socket.join(room);
      socket.currentRoom = room;

      db.get("SELECT username, role, avatar, mood FROM users WHERE id = ?", [socket.user.id], (_e, row) => {
        if (!row) return;

        ensureOwnerRoleIfNeeded({ ...row, id: socket.user.id }, (fixedRole) => {
          // update session role so UI stays correct
          socket.request.session.user.role = fixedRole;

          const map = getRoomMap(room);
          map.set(socket.id, {
            socketId: socket.id,
            userId: socket.user.id,
            username: row.username,
            role: fixedRole,
            status,
            avatar: row.avatar || "",
            mood: row.mood || "",
          });

          socket.to(room).emit("system", `${row.username} joined #${room}`);
          emitUserList(room);

          // send last 50 messages
          db.all(
            `SELECT id, room, username, role, text, ts, deleted,
                    attachment_url, attachment_type, attachment_mime, attachment_size
             FROM messages
             WHERE room = ?
             ORDER BY ts DESC
             LIMIT 50`,
            [room],
            (_e2, rows) => {
              const history = (rows || []).reverse().map(r => ({
                messageId: r.id,
                room: r.room,
                user: r.username,
                role: r.role,
                text: r.deleted ? "[message deleted]" : r.text,
                deleted: !!r.deleted,
                ts: r.ts,
                attachmentUrl: r.attachment_url || "",
                attachmentType: r.attachment_type || "",
                attachmentMime: r.attachment_mime || "",
                attachmentSize: Number(r.attachment_size || 0) || 0,
              }));
              socket.emit("history", history);
            }
          );
        });
      });
    });
  });

  socket.on("status change", ({ status }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const map = getRoomMap(room);
    const u = map.get(socket.id);
    if (!u) return;
    const st = onlineState.get(socket.user.id);
    if (st) st.status = String(status || "Online");
    db.run("UPDATE users SET last_status = ? WHERE id = ?", [String(status || "Online"), socket.user.id]);
    u.status = String(status || "Online");
    map.set(socket.id, u);
    emitUserList(room);
  });

  socket.on("typing", () => {
    const room = socket.currentRoom;
    if (!room) return;
    const tset = getTypingSet(room);
    tset.add(socket.user.username);
    socket.to(room).emit("typing update", Array.from(tset));
  });

  socket.on("stop typing", () => {
    const room = socket.currentRoom;
    if (!room) return;
    const tset = getTypingSet(room);
    if (tset.delete(socket.user.username)) {
      socket.to(room).emit("typing update", Array.from(tset));
    }
  });

  socket.on("chat message", ({ text, attachmentUrl, attachmentType, attachmentMime, attachmentSize }) => {
    const room = socket.currentRoom;
    if (!room) return;

    if (!allowMsg(socket.id)) {
      socket.emit("system", "You are sending messages too fast.");
      return;
    }

    getActiveBanMute(socket.user.id, ({ mute, ban }) => {
      if (ban && isActivePunishment(ban)) return socket.emit("system", "You are banned.");
      if (mute && isActivePunishment(mute)) return socket.emit("system", "You are muted.");

      const map = getRoomMap(room);
      const u = map.get(socket.id);
      if (!u) return;

      const cleanText = String(text || "").slice(0, 800);

      // Attachment validation (server-side)
      const hasAttachment = !!(attachmentUrl && attachmentType && attachmentMime);
      if (!cleanText.trim() && !hasAttachment) return;

      let safeUrl = "";
      let safeType = "";
      let safeMime = "";
      let safeSize = 0;

      if (hasAttachment) {
        safeUrl = String(attachmentUrl || "").slice(0, 300);
        safeType = String(attachmentType || "").slice(0, 20);
        safeMime = String(attachmentMime || "").slice(0, 60);
        safeSize = Number(attachmentSize || 0) || 0;

        // Require our own uploads path
        if (!safeUrl.startsWith("/uploads/")) return;

        // Enforce 10MB max in message data too
        if (safeSize > 10 * 1024 * 1024) return;

        const isImage = ["image/png","image/jpeg","image/webp","image/gif"].includes(safeMime);
        const isVideo = ["video/mp4","video/quicktime"].includes(safeMime);

        if (safeType === "image" && !isImage) return;

        if (safeType === "video") {
          // VIP+ only
          if (roleRank(u.role) < roleRank("VIP")) return;
          if (!isVideo) return;
        }

        // Disallow unknown type
        if (safeType !== "image" && safeType !== "video") return;
      }

      const messageId = randomUUID();
      const ts = Date.now();

      db.run(
        `INSERT INTO messages
         (id, room, user_id, username, role, text, ts, deleted, attachment_url, attachment_type, attachment_mime, attachment_size)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
        [
          messageId, room, socket.user.id, u.username, u.role, cleanText, ts,
          safeUrl, safeType, safeMime, safeSize
        ],
        () => {
          io.to(room).emit("chat message", {
            messageId,
            room,
            user: u.username,
            role: u.role,
            avatar: u.avatar || "",
            mood: u.mood || "",
            text: cleanText,
            ts,
            attachmentUrl: safeUrl,
            attachmentType: safeType,
            attachmentMime: safeMime,
            attachmentSize: safeSize
          });
        }
      );
    });
  });

  // Reactions: 1 per user per message (overwrite)
  socket.on("reaction", ({ messageId, emoji }) => {
    const room = socket.currentRoom;
    if (!room) return;

    messageId = String(messageId || "");
    emoji = String(emoji || "").slice(0, 8);
    if (!messageId || !emoji) return;

    const roomReacts = getRoomReactions(room);
    if (!roomReacts.has(messageId)) roomReacts.set(messageId, {});
    const map = roomReacts.get(messageId);
    map[socket.user.username] = emoji;

    io.to(room).emit("reaction update", { messageId, reactions: map });
  });

  // ---------------- MODERATION ----------------

  socket.on("mod delete message", ({ messageId }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    db.get("SELECT * FROM messages WHERE id = ? AND room = ?", [messageId, room], (_e, msg) => {
      if (!msg) return;
      if (!canModerate(actorRole, msg.role) && msg.user_id !== socket.user.id) return;

      db.run("UPDATE messages SET deleted = 1 WHERE id = ?", [messageId], () => {
        io.to(room).emit("message deleted", { messageId });
        logModAction({
          actor: socket.user,
          action: "DELETE_MESSAGE",
          targetUserId: msg.user_id,
          targetUsername: msg.username,
          room,
          details: `messageId=${messageId}`,
        });
      });
    });
  });

  socket.on("mod kick", ({ username }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = String(username || "").trim().slice(0, 24);

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

      io.to(room).emit("system", `${username} was kicked.`);

      logModAction({
        actor: socket.user,
        action: "KICK",
        targetUserId: target.id,
        targetUsername: username,
        room,
      });
    });
  });

  socket.on("mod mute", ({ username, minutes = 10, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = String(username || "").trim().slice(0, 24);
    const mins = Math.max(1, Math.min(1440, Number(minutes || 10)));
    const expiresAt = Date.now() + mins * 60 * 1000;

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'mute', ?, ?, ?)",
        [target.id, expiresAt, String(reason || "").slice(0, 120), socket.user.id],
        () => {
          io.to(room).emit("system", `${username} was muted for ${mins} minutes.`);
          logModAction({
            actor: socket.user,
            action: "MUTE",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: `minutes=${mins} reason=${String(reason || "").slice(0,120)}`,
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

    username = String(username || "").trim().slice(0, 24);

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "UPDATE punishments SET expires_at = ? WHERE user_id = ? AND type = 'mute' AND (expires_at IS NULL OR expires_at > ?)",
        [Date.now() - 1, target.id, Date.now()],
        function () {
          io.to(room).emit("system", `${username} was unmuted.`);
          logModAction({
            actor: socket.user,
            action: "UNMUTE",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: `updated=${this.changes} reason=${String(reason || "").slice(0,120)}`
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

    username = String(username || "").trim().slice(0, 24);
    const mins = Number(minutes);
    const expiresAt = Number.isFinite(mins) && mins > 0 ? (Date.now() + mins * 60 * 1000) : null;

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'ban', ?, ?, ?)",
        [target.id, expiresAt, String(reason || "").slice(0, 120), socket.user.id],
        () => {
          io.to(room).emit("system", `${username} was banned${expiresAt ? ` for ${mins} minutes` : " permanently"}.`);

          const sid = socketIdByUserId.get(target.id);
          if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

          logModAction({
            actor: socket.user,
            action: "BAN",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: expiresAt ? `minutes=${mins}` : `permanent reason=${String(reason || "").slice(0,120)}`,
          });
        }
      );
    });
  });

  socket.on("mod unban", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return;

    username = String(username || "").trim().slice(0, 24);

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "UPDATE punishments SET expires_at = ? WHERE user_id = ? AND type = 'ban' AND (expires_at IS NULL OR expires_at > ?)",
        [Date.now() - 1, target.id, Date.now()],
        function () {
          io.to(room).emit("system", `${username} was unbanned.`);
          logModAction({
            actor: socket.user,
            action: "UNBAN",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: `updated=${this.changes} reason=${String(reason || "").slice(0,120)}`
          });
        }
      );
    });
  });

  socket.on("mod warn", ({ username, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = String(username || "").trim().slice(0, 24);
    reason = String(reason || "").trim().slice(0, 200);
    if (reason.length < 3) return;

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO warns (ts, user_id, username, reason, by_user_id, by_username, by_role) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [Date.now(), target.id, username, reason, socket.user.id, socket.user.username, socket.user.role],
        () => {
          countWarns(target.id, (count) => {
            io.to(room).emit("system", `${username} was warned. (${count} total warns)`);
            logModAction({ actor: socket.user, action: "WARN", targetUserId: target.id, targetUsername: username, room, details: `count=${count} reason=${reason}` });

            // Auto escalate
            if (count === 3) {
              const mins = 30;
              const expiresAt = Date.now() + mins * 60 * 1000;
              db.run(
                "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'mute', ?, ?, ?)",
                [target.id, expiresAt, "Auto-mute: 3 warnings", socket.user.id],
                () => {
                  io.to(room).emit("system", `${username} was auto-muted for ${mins} minutes (3 warnings).`);
                  logModAction({ actor: socket.user, action: "AUTO_MUTE", targetUserId: target.id, targetUsername: username, room, details: `minutes=${mins} threshold=3` });
                }
              );
            }

            if (count === 5) {
              const mins = 24 * 60;
              const expiresAt = Date.now() + mins * 60 * 1000;
              db.run(
                "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'ban', ?, ?, ?)",
                [target.id, expiresAt, "Auto-ban: 5 warnings", socket.user.id],
                () => {
                  io.to(room).emit("system", `${username} was auto-banned for 24 hours (5 warnings).`);

                  const sid = socketIdByUserId.get(target.id);
                  if (sid) io.sockets.sockets.get(sid)?.disconnect(true);

                  logModAction({ actor: socket.user, action: "AUTO_BAN", targetUserId: target.id, targetUsername: username, room, details: `minutes=${mins} threshold=5` });
                }
              );
            }
          });
        }
      );
    });
  });

  socket.on("mod set role", ({ username, role, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Owner")) return;

    username = String(username || "").trim().slice(0, 24);
    role = normalizeRole(role);
    reason = String(reason || "").slice(0, 120);

    db.get("SELECT id, role AS targetRole FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;

      db.run("UPDATE users SET role = ? WHERE id = ?", [role, target.id], () => {
        io.to(room).emit("system", `${username} role set to ${role}.`);
        logModAction({ actor: socket.user, action: "SET_ROLE", targetUserId: target.id, targetUsername: username, room, details: `role=${role} reason=${reason}` });

        const sid = socketIdByUserId.get(target.id);
        if (sid) io.sockets.sockets.get(sid)?.emit("system", `Your role is now ${role}. Rejoin the room to refresh UI.`);
      });
    });
  });

  socket.on("disconnect", () => {
    socketIdByUserId.delete(socket.user.id);
    leaveCurrentRoom(socket);
    msgRate.delete(socket.id);
    onlineState.delete(socket.user.id);
db.run("UPDATE users SET last_seen = ? WHERE id = ?", [Date.now(), socket.user.id]);
  });
});

// -------------------- Start server --------------------
http.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
