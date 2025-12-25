const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./database");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const avatarsDir = path.join(__dirname, "public", "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: avatarsDir,
  filename: (req, file, cb) => {
    cb(null, req.session.user.id + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false
}));

app.use(express.static("public"));

/* ---------------- AUTH ROUTES ---------------- */

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hash],
    err => {
      if (err) return res.status(400).send("Username already exists");
      res.send("Registered");
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user) return res.status(401).send("Invalid login");

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).send("Invalid login");

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      res.send("Logged in");
    }
  );
});

app.get("/me", (req, res) => {
  res.json(req.session.user || null);
});

/* ---------------- SOCKET.IO ---------------- */
app.get("/profile", (req, res) => {
  if (!req.session || !req.session.user) return res.sendStatus(401);

  db.get(
    "SELECT * FROM users WHERE id = ?",
    [req.session.user.id],
    (err, user) => {
      if (err) return res.sendStatus(500);
      res.json(user);
    }
  );
});

app.post("/profile", upload.single("avatar"), (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  const { bio, mood, age, gender } = req.body;
  const avatar = req.file ? `/avatars/${req.file.filename}` : null;

  db.run(
    `
    UPDATE users SET
      bio = ?,
      mood = ?,
      age = ?,
      gender = ?,
      avatar = COALESCE(?, avatar)
    WHERE id = ?
    `,
    [bio, mood, age, gender, avatar, req.session.user.id],
    () => res.sendStatus(200)
  );
});

const rooms = {};

io.use((socket, next) => {
  const req = socket.request;
  if (!req.session || !req.session.user) return next(new Error("Unauthorized"));
  socket.user = req.session.user;
  next();
});

io.on("connection", socket => {
  socket.on("join room", ({ room, status }) => {
    socket.join(room);
    if (!rooms[room]) rooms[room] = [];

    rooms[room].push({
      id: socket.user.id,
      name: socket.user.username,
      role: socket.user.role,
      status
    });

    io.to(room).emit("user list", rooms[room]);
  });

  socket.on("chat message", msg => {
    io.to(msg.room).emit("chat message", {
      user: socket.user.username,
      role: socket.user.role,
      text: msg.text
    });
  });

  socket.on("disconnect", () => {
    for (const r in rooms) {
      rooms[r] = rooms[r].filter(u => u.id !== socket.user.id);
      io.to(r).emit("user list", rooms[r]);
    }
  });
});
http.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
