const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./database");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;

/* ---------------- MIDDLEWARE SETUP ---------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
});

app.use(sessionMiddleware);
app.use(express.static("public"));

// Attach session to socket.io
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

/* ---------------- AVATAR UPLOAD SETUP ---------------- */
const uploadDir = "./public/avatars";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    if (!req.session.user) return cb(new Error("Unauthorized"));
    cb(null, req.session.user.id + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif/;
    if (allowed.test(path.extname(file.originalname).toLowerCase())) {
      cb(null, true);
    } else {
      cb(new Error("Invalid image type"));
    }
  }
});

/* ---------------- HELPER FUNCTIONS ---------------- */
function sanitize(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

function validateUsername(username) {
  return username && username.length >= 3 && username.length <= 20;
}

function validatePassword(password) {
  return password && password.length >= 6;
}

/* ---------------- AUTH ROUTES ---------------- */
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!validateUsername(username)) {
    return res.status(400).json({ error: "Username must be 3-20 characters" });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [sanitize(username), hash],
      err => {
        if (err) {
          return res.status(400).json({ error: "Username already exists" });
        }
        res.json({ success: true });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  db.get(
    "SELECT id, username, password, role FROM users WHERE username = ?",
    [sanitize(username)],
    async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: "Invalid login" });
      }

      try {
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
          return res.status(401).json({ error: "Invalid login" });
        }

        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ success: true });
      } catch (err) {
        res.status(500).json({ error: "Login failed" });
      }
    }
  );
});

app.get("/me", (req, res) => {
  res.json(req.session.user || null);
});

app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    res.json({ success: true });
  });
});

/* ---------------- PROFILE ROUTES ---------------- */
app.get("/profile", (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  db.get(
    "SELECT username, role, bio, mood, age, gender, avatar, created_at FROM users WHERE id = ?",
    [req.session.user.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json(row || {});
    }
  );
});

app.post("/profile", upload.single("avatar"), (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  const { bio, mood, age, gender } = req.body;
  const avatar = req.file ? `/avatars/${req.file.filename}` : null;

  db.run(
    `UPDATE users SET bio = ?, mood = ?, age = ?, gender = ?, avatar = COALESCE(?, avatar) WHERE id = ?`,
    [sanitize(bio), sanitize(mood), age, sanitize(gender), avatar, req.session.user.id],
    err => {
      if (err) return res.status(500).json({ error: "Update failed" });
      res.json({ success: true });
    }
  );
});

/* ---------------- SOCKET.IO SETUP ---------------- */
const rooms = {};

io.use((socket, next) => {
  if (!socket.request.session || !socket.request.session.user) {
    return next(new Error("Unauthorized"));
  }
  socket.user = socket.request.session.user;
  next();
});

io.on("connection", socket => {
  socket.on("join room", ({ room, status }) => {
    const safeRoom = sanitize(room);
    socket.join(safeRoom);

    if (!rooms[safeRoom]) rooms[safeRoom] = [];
    rooms[safeRoom] = rooms[safeRoom].filter(u => u.id !== socket.user.id);

    db.get(
      "SELECT username, role, avatar, mood FROM users WHERE id = ?",
      [socket.user.id],
      (err, user) => {
        if (err || !user) return;

        rooms[safeRoom].push({
          id: socket.user.id,
          name: user.username,
          role: user.role,
          avatar: user.avatar,
          mood: user.mood,
          status: status || "Online"
        });

        io.to(safeRoom).emit("user list", rooms[safeRoom]);
        io.to(safeRoom).emit("system", `${user.username} joined #${safeRoom}`);
      }
    );
  });

  socket.on("chat message", msg => {
    if (!msg.room || !msg.text) return;
    const safeRoom = sanitize(msg.room);
    const safeText = sanitize(msg.text);

    io.to(safeRoom).emit("chat message", {
      user: socket.user.username,
      role: socket.user.role,
      text: safeText,
      timestamp: new Date().toISOString()
    });
  });

  socket.on("typing", ({ room }) => {
    const safeRoom = sanitize(room);
    socket.to(safeRoom).emit("typing", socket.user.username);
  });

  socket.on("stop typing", ({ room }) => {
    const safeRoom = sanitize(room);
    socket.to(safeRoom).emit("stop typing", socket.user.username);
  });

  socket.on("reaction", data => {
    if (!data.room || !data.messageId || !data.emoji) return;
    const safeRoom = sanitize(data.room);
    io.to(safeRoom).emit("reaction", {
      room: safeRoom,
      messageId: data.messageId,
      emoji: data.emoji,
      user: socket.user.username
    });
  });

  socket.on("disconnecting", () => {
    for (const r of socket.rooms) {
      if (rooms[r]) {
        rooms[r] = rooms[r].filter(u => u.id !== socket.user.id);
        if (rooms[r].length === 0) {
          delete rooms[r];
        } else {
          io.to(r).emit("user list", rooms[r]);
        }
      }
    }
  });

  socket.on("error", err => console.error("Socket error:", err));
});

http.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
