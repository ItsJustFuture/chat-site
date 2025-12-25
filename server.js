// server.js — Full build with:
// Rooms, member list, statuses, auto-idle (client), typing, reactions (1/user/message),
// login/register + sessions, persistent roles + profiles + avatars,
// profile popup endpoint, message history (SQLite), search/mentions (client),
// moderation: mute/kick/ban/delete (role-based),
// hardening: dotenv, helmet, rate limits, message rate limit

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
const meStatusText = document.getElementById("meStatusText");
meStatusText.textContent = statusSelect.value;

const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

const PORT = process.env.PORT || 3000;
const OWNER_USERNAME = process.env.OWNER_USERNAME || "Iri";

// ---------- Folders ----------
const publicDir = path.join(__dirname, "public");
const avatarDir = path.join(publicDir, "avatars");
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
});

// ---------- Middleware ----------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false },
});
app.use(sessionMiddleware);

app.use(express.static(publicDir));

// ---------- Rate limits ----------
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/login", authLimiter);
app.use("/register", authLimiter);

// ---------- Helpers ----------
function sanitizeUsername(u) {
  return String(u || "").trim().slice(0, 24);
}
function normalizeRole(role) {
  const allowed = ["Owner", "Co-owner", "Admin", "Moderator", "VIP", "User", "Guest"];
  return allowed.includes(role) ? role : "User";
}
function roleRank(role) {
  // higher = more power
  switch (role) {
    case "Owner": return 6;
    case "Co-owner": return 5;
    case "Admin": return 4;
    case "Moderator": return 3;
    case "VIP": return 2;
    case "User": return 1;
    case "Guest": return 0;
    default: return 1;
  }
}
function ensureOwnerRoleIfNeeded(userRow, cb) {
  if (userRow.username === OWNER_USERNAME && userRow.role !== "Owner") {
    db.run("UPDATE users SET role = 'Owner' WHERE id = ?", [userRow.id], () => cb("Owner"));
    return;
  }
  cb(userRow.role);
}
function requireLogin(req, res, next) {
  if (!req.session.user) return res.sendStatus(401);
  next();
}
function isActivePunishment(p) {
  if (!p) return false;
  if (p.expires_at == null) return true;
  return Number(p.expires_at) > Date.now();
}
function getActivePunishments(userId, cb) {
  db.all(
    "SELECT * FROM punishments WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC",
    [userId, Date.now()],
    (err, rows) => cb(err, rows || [])
  );
}
function getActiveBanMute(userId, cb) {
  getActivePunishments(userId, (_err, rows) => {
    const ban = rows.find(r => r.type === "ban");
    const mute = rows.find(r => r.type === "mute");
    cb({ ban, mute });
  });
}

// ---------- Multer avatar upload ----------
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
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(file.mimetype);
    cb(ok ? null : new Error("Only images allowed"), ok);
  },
});

// ---------- Auth ----------
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

    // ban check
    getActiveBanMute(user.id, async ({ ban }) => {
      if (ban) return res.status(403).send("You are banned.");

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

// ---------- Profiles ----------
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

// Public profile for popup (by username)
app.get("/profile/:username", (req, res) => {
  const u = sanitizeUsername(req.params.username);
  db.get(
    "SELECT id, username, role, bio, mood, age, gender, avatar, created_at FROM users WHERE username = ?",
    [u],
    (err, row) => {
      if (err || !row) return res.status(404).send("Not found");
      // You can hide age/gender later with privacy settings
      res.json(row);
    }
  );
});

app.post("/profile", requireLogin, upload.single("avatar"), (req, res) => {
  const bio = String(req.body.bio || "").slice(0, 400);
  const mood = String(req.body.mood || "").slice(0, 60);
 const MIN_AGE = 18;

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
    [bio, mood, Number.isFinite(age) ? age : null, gender || null, avatarPath, req.session.user.id],
    (err) => {
      if (err) return res.status(500).send("Profile update failed.");
      res.send("Profile updated");
    }
  );
});

// ---------- Socket session bridge ----------
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));
io.use((socket, next) => {
  const sess = socket.request.session;
  if (!sess?.user) return next(new Error("Unauthorized"));
  socket.user = sess.user; // {id, username, role}
  next();
});

// ---------- Realtime state ----------
const roomsState = new Map(); // room -> Map(socket.id -> userObj)
const typingState = new Map(); // room -> Set(username)
const reactionsState = new Map(); // room -> Map(messageId -> { username: emoji })
const socketIdByUserId = new Map(); // userId -> socket.id

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

// message rate limit per socket
const msgRate = new Map(); // socket.id -> {tokens,last}
function allowMsg(socketId) {
  const now = Date.now();
  const cap = 6;          // burst
  const refillPerMs = 6 / 4000; // ~6 msgs per 4s
  const prev = msgRate.get(socketId) || { tokens: cap, last: now };
  const elapsed = now - prev.last;
  const tokens = Math.min(cap, prev.tokens + elapsed * refillPerMs);
  const ok = tokens >= 1;
  msgRate.set(socketId, { tokens: ok ? tokens - 1 : tokens, last: now });
  return ok;
}

// ---------- Moderation checks ----------
function canModerate(actorRole, targetRole) {
  return roleRank(actorRole) > roleRank(targetRole);
}
function requireMinRole(actorRole, minRole) {
  return roleRank(actorRole) >= roleRank(minRole);
}

// ---------- Socket events ----------
io.on("connection", (socket) => {
  socket.currentRoom = null;
  socketIdByUserId.set(socket.user.id, socket.id);

  socket.on("join room", ({ room, status }) => {
    room = String(room || "general").toLowerCase();
    status = String(status || "Online");

    // ban check (ban blocks socket participation)
    getActiveBanMute(socket.user.id, ({ ban }) => {
      if (ban) {
        socket.emit("system", "You are banned.");
        return;
      }

      leaveCurrentRoom(socket);
      socket.join(room);
      socket.currentRoom = room;

      // load fresh profile bits
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

            // send last 50 messages
            db.all(
              "SELECT id, room, username, role, text, ts, deleted FROM messages WHERE room = ? ORDER BY ts DESC LIMIT 50",
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

  socket.on("chat message", ({ text }) => {
    const room = socket.currentRoom;
    if (!room) return;

    if (!allowMsg(socket.id)) {
      socket.emit("system", "You are sending messages too fast.");
      return;
    }

    getActiveBanMute(socket.user.id, ({ mute, ban }) => {
      if (ban) {
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
      if (!cleanText.trim()) return;

      const messageId = randomUUID();
      const ts = Date.now();

      db.run(
        "INSERT INTO messages (id, room, user_id, username, role, text, ts, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        [messageId, room, socket.user.id, u.username, u.role, cleanText, ts],
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
          });
        }
      );
    });
  });

  // reactions: 1 per user per message
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

  // ---------- Moderation ----------
  // Delete message: Moderator+ can delete any; Users can delete their own if you want (disabled here).
  socket.on("mod delete message", ({ messageId }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    db.get("SELECT * FROM messages WHERE id = ? AND room = ?", [messageId, room], (_e, msg) => {
      if (!msg) return;
      // Optional: enforce you can’t delete higher roles’ messages unless your role outranks
      if (!canModerate(actorRole, msg.role) && msg.user_id !== socket.user.id) return;

      db.run("UPDATE messages SET deleted = 1 WHERE id = ?", [messageId], () => {
        io.to(room).emit("message deleted", { messageId });
      });
    });
  });

  // Mute user: Moderator+
  socket.on("mod mute", ({ username, minutes, reason }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    const mins = Math.max(1, Math.min(1440, Number(minutes || 10)));
    const expiresAt = Date.now() + mins * 60 * 1000;

    db.get("SELECT id, role FROM users WHERE username = ?", [String(username || "")], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'mute', ?, ?, ?)",
        [target.id, expiresAt, String(reason || "").slice(0, 120), socket.user.id],
        () => {
          io.to(room).emit("system", `${username} was muted for ${mins} minutes.`);
        }
      );
    });
  });

  // Ban user: Admin+
  socket.on("mod ban", ({ username, minutes, reason }) => {
    const room = socket.currentRoom;
    if (!room) return;
    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Admin")) return;

    const mins = Number(minutes);
    const expiresAt = Number.isFinite(mins) && mins > 0 ? (Date.now() + mins * 60 * 1000) : null;

    db.get("SELECT id, role FROM users WHERE username = ?", [String(username || "")], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      db.run(
        "INSERT INTO punishments (user_id, type, expires_at, reason, by_user_id) VALUES (?, 'ban', ?, ?, ?)",
        [target.id, expiresAt, String(reason || "").slice(0, 120), socket.user.id],
        () => {
          io.to(room).emit("system", `${username} was banned${expiresAt ? ` for ${mins} minutes` : ""}.`);

          // kick if online
          const sid = socketIdByUserId.get(target.id);
          if (sid) {
            const s = io.sockets.sockets.get(sid);
            if (s) s.disconnect(true);
          }
        }
      );
    });
  });

  // Kick user: Moderator+ (disconnect only, no DB record)
  socket.on("mod kick", ({ username }) => {
    const room = socket.currentRoom;
    if (!room) return;

    const actorRole = socket.request.session.user.role;
    if (!requireMinRole(actorRole, "Moderator")) return;

    db.get("SELECT id, role FROM users WHERE username = ?", [String(username || "")], (_e, target) => {
      if (!target) return;
      if (!canModerate(actorRole, target.role)) return;

      const sid = socketIdByUserId.get(target.id);
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) s.disconnect(true);
      }
      io.to(room).emit("system", `${username} was kicked.`);
    });
  });

  socket.on("disconnect", () => {
    socketIdByUserId.delete(socket.user.id);
    leaveCurrentRoom(socket);
    msgRate.delete(socket.id);
  });
});

http.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
