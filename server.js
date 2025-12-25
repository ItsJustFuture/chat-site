// server.js (full)
// Features:
// - Rooms/channels + member list + statuses
// - Typing indicator
// - Reactions (1 per user per message, server authoritative)
// - Login/Register with sessions
// - Persistent users/roles/profiles + avatar uploads (multer)
// - Minimum age enforcement (18)
// - Persistent message history per room (loads last 50 on join)
// - Moderation: kick/mute/ban/delete message (role-based)
// - Moderation logs: audit trail + /mod/logs endpoint
// - Hardening: helmet (CSP disabled for inline scripts), rate limiting, basic message rate limiting

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

const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

const PORT = process.env.PORT || 3000;
const OWNER_USERNAME = process.env.OWNER_USERNAME || "Iri";
const MIN_AGE = 18;

// Helpful for Render/proxies
app.set("trust proxy", 1);

// ---------- Ensure folders ----------
const publicDir = path.join(__dirname, "public");
const avatarDir = path.join(publicDir, "avatars");
const uploadDir = path.join(publicDir, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });
// Serve uploads with safer headers
app.use("/uploads", express.static(uploadDir, {
  setHeaders: (res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    // Optional: avoid browser caching while testing
    // res.setHeader("Cache-Control", "no-store");
  }
}));
fs.mkdirSync(publicDir, { recursive: true });
fs.mkdirSync(avatarDir, { recursive: true });

// ---------- DB ----------
const db = new sqlite3.Database(path.join(__dirname, "chat.db"));

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
      deleted INTEGER DEFAULT 0
    )
  `);
  // warnings
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

  // punishments: type=ban|mute, expires_at null => permanent
  db.run(`
    CREATE TABLE IF NOT EXISTS punishments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      expires_at INTEGER,
      reason TEXT DEFAULT '',
      by_user_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // moderation logs (audit trail)
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
});
// Add attachment columns if missing (safe on existing DB)
db.run("ALTER TABLE messages ADD COLUMN attachment_url TEXT");
db.run("ALTER TABLE messages ADD COLUMN attachment_type TEXT");
db.run("ALTER TABLE messages ADD COLUMN attachment_mime TEXT");
db.run("ALTER TABLE messages ADD COLUMN attachment_size INTEGER");
// ---------- Middleware ----------
app.use(helmet({ contentSecurityPolicy: false })); // IMPORTANT: allows inline <script> in index.html
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "change-me-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
  },
});
app.use(sessionMiddleware);

app.use(express.static(publicDir));

// ---------- Rate limits (auth) ----------
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100, // increase during dev to avoid “stopped working”
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/login", authLimiter);
app.use("/register", authLimiter);
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20, // 20 uploads/min per IP (tune later)
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/upload", uploadLimiter);
// ---------- Helpers ----------
function sanitizeUsername(u) {
  return String(u || "").trim().slice(0, 24);
}

function normalizeRole(role) {
  const allowed = ["Owner", "Co-owner", "Admin", "Moderator", "VIP", "User", "Guest"];
  return allowed.includes(role) ? role : "User";
}

function roleRank(role) {
  return {
    "Owner": 6,
    "Co-owner": 5,
    "Admin": 4,
    "Moderator": 3,
    "VIP": 2,
    "User": 1,
    "Guest": 0,
  }[role] ?? 1;
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

function ensureOwnerRoleIfNeeded(userRow, cb) {
  if (userRow.username === OWNER_USERNAME && userRow.role !== "Owner") {
    db.run("UPDATE users SET role = 'Owner' WHERE id = ?", [userRow.id], () => cb("Owner"));
    return;
  }
  cb(userRow.role);
}

function isActivePunishment(p) {
  if (!p) return false;
  if (p.expires_at == null) return true;
  return Number(p.expires_at) > Date.now();
}
function countWarns(userId, cb) {
  db.get(
    "SELECT COUNT(*) AS c FROM warns WHERE user_id = ?",
    [userId],
    (_e, row) => cb((row && row.c) ? Number(row.c) : 0)
  );
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

function logModAction({ actor, action, targetUserId = null, targetUsername = null, room = null, details = "" }) {
  db.run(
    `
      INSERT INTO mod_logs
      (ts, actor_user_id, actor_username, actor_role, action, target_user_id, target_username, room, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
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

// ---------- Avatar upload ----------
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, avatarDir),
  filename: (req, file, cb) => {
    const userId = req.session?.user?.id;
    const ext = (path.extname(file.originalname || "").toLowerCase() || ".png");
    cb(null, `${userId}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (_req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(file.mimetype);
    cb(ok ? null : new Error("Only image uploads allowed"), ok);
  },
});
const chatUploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // Ignore user-provided filename completely; we choose extension from MIME allowlist below.
    const id = randomUUID();
    const mime = String(file.mimetype || "").toLowerCase();

    let ext = "";
    if (mime === "image/png") ext = ".png";
    else if (mime === "image/jpeg") ext = ".jpg";
    else if (mime === "image/webp") ext = ".webp";
    else if (mime === "image/gif") ext = ".gif";
    else if (mime === "video/mp4") ext = ".mp4";
    else if (mime === "video/quicktime") ext = ".mov"; // MOV

    cb(null, `${id}${ext}`);
  }
});
const chatUpload = multer({
  storage: chatUploadStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    // Everyone can upload images
    const isImage = ["image/png","image/jpeg","image/webp","image/gif"].includes(file.mimetype);

    // VIP+ can upload videos (mp4/mov)
    const role = req.session?.user?.role || "User";
    const vipPlus = roleRank(role) >= roleRank("VIP");
    const isVideo = ["video/mp4","video/quicktime"].includes(file.mimetype); // quicktime = .mov

    if (isImage) return cb(null, true);
    if (vipPlus && isVideo) return cb(null, true);

    cb(new Error("File type not allowed."), false);
  }
});
// ---------- Auth Routes ----------
app.post("/register", async (req, res) => {
  try {
    const username = sanitizeUsername(req.body.username);
    const password = String(req.body.password || "");

    if (username.length < 3) return res.status(400).send("Username must be at least 3 characters.");
    if (password.length < 6) return res.status(400).send("Password must be at least 6 characters.");

    const password_hash = await bcrypt.hash(password, 12);

    db.run(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
      [username, password_hash, "User"],
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
  const username = sanitizeUsername(req.body.username);
  const password = String(req.body.password || "");

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.status(401).send("Invalid login.");

    getActiveBanMute(user.id, async ({ ban }) => {
      if (ban && isActivePunishment(ban)) return res.status(403).send("You are banned.");

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).send("Invalid login.");

      ensureOwnerRoleIfNeeded(user, (fixedRole) => {
        req.session.user = { id: user.id, username: user.username, role: normalizeRole(fixedRole) };
        res.send("Logged in");
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
app.post("/upload", requireLogin, (req, res) => {
  chatUpload.single("file")(req, res, (err) => {
    if (err) {
      const msg = String(err.message || "Upload failed.");
      return res.status(400).send(msg);
    }
    if (!req.file) return res.status(400).send("No file uploaded.");

    const url = `/uploads/${req.file.filename}`;
    const mime = req.file.mimetype;

    let type = "file";
    if (mime.startsWith("image/")) type = "image";
    if (mime === "video/mp4" || mime === "video/quicktime") type = "video";

    res.json({ url, type, mime });
  });
  });
// ---------- Profile Routes ----------
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

// Public profile (for member click popup)
app.get("/profile/:username", (req, res) => {
  const u = sanitizeUsername(req.params.username);
  db.get(
    "SELECT id, username, role, bio, mood, age, gender, avatar, created_at FROM users WHERE username = ?",
    [u],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      res.json(row);
    }
  );
});

app.post("/profile", requireLogin, upload.single("avatar"), (req, res) => {
  const bio = String(req.body.bio || "").slice(0, 400);
  const mood = String(req.body.mood || "").slice(0, 60);

  // MIN AGE ENFORCEMENT (18)
  const ageRaw = req.body.age;
  let age = null;
  if (ageRaw !== "" && ageRaw != null) {
    const n = Number(ageRaw);
    if (!Number.isFinite(n)) return res.status(400).send("Invalid age.");
    if (n < MIN_AGE) return res.status(400).send(`Minimum age is ${MIN_AGE}.`);
    age = Math.min(120, Math.floor(n));
  }

  const gender = String(req.body.gender || "").slice(0, 24);
  const avatarPath = req.file ? `/avatars/${req.file.filename}` : null;

  db.run(
    `
      UPDATE users
      SET bio = ?,
          mood = ?,
          age = ?,
          gender = ?,
          avatar = COALESCE(?, avatar)
      WHERE id = ?
    `,
    [bio, mood, age, gender || null, avatarPath, req.session.user.id],
    (err) => {
      if (err) return res.status(500).send("Profile update failed.");
      res.send("Profile updated");
    }
  );
});

// ---------- Moderation Logs endpoint (for panels) ----------
app.get("/mod/logs", requireLogin, (req, res) => {
  const role = req.session.user.role;
  if (roleRank(role) < roleRank("Moderator")) return res.sendStatus(403);

  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));
  const user = (req.query.user || "").trim();
  const action = (req.query.action || "").trim();

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

// ---------- Socket.IO session bridge ----------
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));
io.use((socket, next) => {
  const sess = socket.request.session;
  if (!sess?.user) return next(new Error("Unauthorized"));
  socket.user = sess.user; // {id, username, role}
  next();
});

// ---------- Realtime state ----------
const roomsState = new Map();      // room -> Map(socket.id -> userObj)
const typingState = new Map();     // room -> Set(username)
const reactionsState = new Map();  // room -> Map(messageId -> { username: emoji })
const socketIdByUserId = new Map();// userId -> socket.id

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

// ---------- Message rate limiting (simple token bucket) ----------
const msgRate = new Map(); // socket.id -> {tokens,last}
function allowMsg(socketId) {
  const now = Date.now();
  const cap = 6; // burst
  const refillPerMs = 6 / 4000; // ~6 per 4s
  const prev = msgRate.get(socketId) || { tokens: cap, last: now };
  const elapsed = now - prev.last;
  const tokens = Math.min(cap, prev.tokens + elapsed * refillPerMs);
  const ok = tokens >= 1;
  msgRate.set(socketId, { tokens: ok ? tokens - 1 : tokens, last: now });
  return ok;
}

// ---------- Socket Events ----------
io.on("connection", (socket) => {
  socket.currentRoom = null;
  socketIdByUserId.set(socket.user.id, socket.id);
socket.on("mod unmute", ({ username, reason = "" }) => {
  const room = socket.currentRoom;
  if (!room) return;
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
  const actorRole = socket.request.session.user.role;
  if (!requireMinRole(actorRole, "Moderator")) return;

  username = sanitizeUsername(username);

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
          details: `reason=${String(reason || "").slice(0,120)} updated=${this.changes}`
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

  username = sanitizeUsername(username);

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
          details: `reason=${String(reason || "").slice(0,120)} updated=${this.changes}`
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

  username = sanitizeUsername(username);
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

          logModAction({
            actor: socket.user,
            action: "WARN",
            targetUserId: target.id,
            targetUsername: username,
            room,
            details: `count=${count} reason=${reason}`
          });

          // Auto escalation
          if (count === 3) {
            const mins = 30;
            const expiresAt = Date.now() + mins * 60 * 1000;
            db.run(
              "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'mute', ?, ?, ?)",
              [target.id, expiresAt, "Auto-mute: 3 warnings", socket.user.id],
              () => {
                io.to(room).emit("system", `${username} was auto-muted for ${mins} minutes (3 warnings).`);
                logModAction({
                  actor: socket.user,
                  action: "AUTO_MUTE",
                  targetUserId: target.id,
                  targetUsername: username,
                  room,
                  details: `minutes=${mins} threshold=3`
                });
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

                logModAction({
                  actor: socket.user,
                  action: "AUTO_BAN",
                  targetUserId: target.id,
                  targetUsername: username,
                  room,
                  details: `minutes=${mins} threshold=5`
                });
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

  username = sanitizeUsername(username);
  role = normalizeRole(role);
  reason = String(reason || "").slice(0,120);

  // prevent demoting the configured owner username unless you REALLY want that
  // if (username === OWNER_USERNAME && role !== "Owner") return;

  db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
    if (!target) return;

    // Owner can change anyone (including admins/mods), but keep a safety check:
    if (username === socket.user.username && roleRank(role) < roleRank("Owner")) {
      // Optional safety: allow it if you want, or block self-demote
      // return;
    }

    db.run("UPDATE users SET role = ? WHERE id = ?", [role, target.id], () => {
      io.to(room).emit("system", `${username} role set to ${role}.`);

      logModAction({
        actor: socket.user,
        action: "SET_ROLE",
        targetUserId: target.id,
        targetUsername: username,
        room,
        details: `role=${role} reason=${reason}`
      });

      // If they're online, update the member list immediately by forcing their room presence to refresh
      const sid = socketIdByUserId.get(target.id);
      if (sid) io.sockets.sockets.get(sid)?.emit("system", `Your role is now ${role}. Rejoin the room to refresh UI.`);
    });
  });
});

  socket.on("join room", ({ room, status }) => {
    room = String(room || "general").toLowerCase();
    status = String(status || "Online");

    getActiveBanMute(socket.user.id, ({ ban }) => {
      if (ban && isActivePunishment(ban)) {
        socket.emit("system", "You are banned.");
        return;
      }

      leaveCurrentRoom(socket);
      socket.join(room);
      socket.currentRoom = room;

      // Refresh profile bits each join
      db.get(
        "SELECT username, role, avatar, mood FROM users WHERE id = ?",
        [socket.user.id],
        (err, row) => {
          if (err || !row) return;

          ensureOwnerRoleIfNeeded(row, (fixedRole) => {
            fixedRole = normalizeRole(fixedRole);
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

            // Send history (last 50)
            db.all(
              "SELECT id, room, username, role, text, ts, deleted, attachment_url, attachment_type, attachment_mime, attachment_size FROM messages WHERE room = ? ORDER BY ts DESC LIMIT 50",
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
        }
      );
    });
  });

  socket.on("status change", ({ status }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const map = getRoomMap(room);
    const u = map.get(socket.id);
    if (!u) return;

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
    if (ban && isActivePunishment(ban)) {
      socket.emit("system", "You are banned.");
      return;
    }
    if (mute && isActivePunishment(mute)) {
      socket.emit("system", "You are muted.");
      return;
    }

    const map = getRoomMap(room);
    const u = map.get(socket.id);
    if (!u) return;

    const cleanText = String(text || "").slice(0, 800);

    const hasAttachment = !!(attachmentUrl && attachmentType && attachmentMime);
    if (!cleanText.trim() && !hasAttachment) return;

    const safeAttachmentUrl = hasAttachment ? String(attachmentUrl).slice(0, 300) : "";
    const safeAttachmentType = hasAttachment ? String(attachmentType).slice(0, 20) : "";
    const safeAttachmentMime = hasAttachment ? String(attachmentMime).slice(0, 60) : "";
    const safeAttachmentSize = hasAttachment ? (Number(attachmentSize) || 0) : 0;

    const messageId = randomUUID();
    const ts = Date.now();

    db.run(
      `INSERT INTO messages
       (id, room, user_id, username, role, text, ts, deleted, attachment_url, attachment_type, attachment_mime, attachment_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
      [
        messageId, room, socket.user.id, u.username, u.role, cleanText, ts,
        safeAttachmentUrl, safeAttachmentType, safeAttachmentMime, safeAttachmentSize
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
          attachmentUrl: safeAttachmentUrl,
          attachmentType: safeAttachmentType,
          attachmentMime: safeAttachmentMime,
          attachmentSize: safeAttachmentSize
        });
      }
    );
  });
});

          });
  // ---------------- MODERATION ----------------

  // Delete message (Moderator+)
  socket.on("mod delete message", ({ messageId }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    db.get(
      "SELECT * FROM messages WHERE id = ? AND room = ?",
      [messageId, room],
      (_e, msg) => {
        if (!msg) return;

        // optional check: mods can't delete higher roles unless it's their own message
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
      }
    );
  });

  // Kick user (Moderator+)
  socket.on("mod kick", ({ username }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);

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

  // Mute user (Moderator+)
  socket.on("mod mute", ({ username, minutes = 10, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    username = sanitizeUsername(username);

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

  // Ban user (Admin+)
  socket.on("mod ban", ({ username, minutes = 0, reason = "" }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return;

    username = sanitizeUsername(username);

    const mins = Number(minutes);
    const expiresAt = Number.isFinite(mins) && mins > 0 ? (Date.now() + mins * 60 * 1000) : null;

    db.get("SELECT id, role FROM users WHERE username = ?", [username], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'ban', ?, ?, ?)",
        [target.id, expiresAt, String(reason || "").slice(0, 120), socket.user.id],
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
            details: expiresAt ? `minutes=${mins}` : `permanent reason=${String(reason || "").slice(0,120)}`,
          });
        }
      );
    });
  });

  socket.on("disconnect", () => {
    socketIdByUserId.delete(socket.user.id);
    leaveCurrentRoom(socket);
    msgRate.delete(socket.id);
  });
http.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
