const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./chat.db");

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
    if (!hasPasswordHash || !hasLegacyPassword) return;

    db.all(
      `SELECT id, password, password_hash FROM users
       WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL`,
      [],
      async (_e, legacyRows) => {
        if (!legacyRows?.length) return;
        const bcrypt = require("bcrypt");
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
      type TEXT NOT NULL,
      expires_at INTEGER,
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
});

module.exports = db;
