"use strict";

const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");
const db = new sqlite3.Database(DB_FILE);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

async function columnExists(table, column) {
  const rows = await all(`PRAGMA table_info(${table})`);
  return rows.some((r) => r.name === column);
}

async function addColumnIfMissing(table, column, definition) {
  const exists = await columnExists(table, column);
  if (exists) return false;
  await run(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
  return true;
}

async function ensureColumns(table, cols) {
  for (const [colName, ddl] of cols) {
    await addColumnIfMissing(table, colName, ddl);
  }
}

async function migrateLegacyPasswords() {
  const rows = await all("PRAGMA table_info(users)");
  const hasPasswordHash = rows.some((r) => r.name === "password_hash");
  const hasLegacyPassword = rows.some((r) => r.name === "password");
  if (!hasPasswordHash || !hasLegacyPassword) return;

  const legacyRows = await all(
    `SELECT id, password, password_hash FROM users
       WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL`
  );

  if (!legacyRows?.length) return;

  for (const row of legacyRows) {
    const legacy = String(row.password || "");
    if (!legacy) continue;
    const hash = legacy.startsWith("$2") ? legacy : await bcrypt.hash(legacy, 10);
    await run("UPDATE users SET password_hash = ?, password = NULL WHERE id = ?", [hash, row.id]);
  }
}

async function seedDefaultRooms() {
  const now = Date.now();
  const seedRooms = ["main", "nsfw", "music", "diceroom"];
  for (const r of seedRooms) {
    await run(`INSERT OR IGNORE INTO rooms (name, created_by, created_at) VALUES (?, NULL, ?)`, [r, now]);
  }
}

async function runSqliteMigrations() {
  await run(`
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

  await run(`
    CREATE TABLE IF NOT EXISTS rooms (
      name TEXT PRIMARY KEY,
      created_by INTEGER,
      created_at INTEGER NOT NULL
    )
  `);

  await ensureColumns("rooms", [
    ["slowmode_seconds", "slowmode_seconds INTEGER NOT NULL DEFAULT 0"],
    ["is_locked", "is_locked INTEGER NOT NULL DEFAULT 0"],
    ["pinned_message_ids", "pinned_message_ids TEXT"],
    ["maintenance_mode", "maintenance_mode INTEGER NOT NULL DEFAULT 0"],
  ]);

  await seedDefaultRooms();

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
    ["prefs_json", "prefs_json TEXT NOT NULL DEFAULT '{}'"],
    ["gold", "gold INTEGER NOT NULL DEFAULT 0"],
    ["xp", "xp INTEGER NOT NULL DEFAULT 0"],
    ["lastXpMessageAt", "lastXpMessageAt INTEGER"],
    ["lastDailyLoginAt", "lastDailyLoginAt INTEGER"],
    ["lastGoldTickAt", "lastGoldTickAt INTEGER"],
    ["lastMessageGoldAt", "lastMessageGoldAt INTEGER"],
    ["lastDailyLoginGoldAt", "lastDailyLoginGoldAt INTEGER"],
    ["lastDiceRollAt", "lastDiceRollAt INTEGER"],
    ["dice_sixes", "dice_sixes INTEGER NOT NULL DEFAULT 0"],
    ["vibe_tags", "vibe_tags TEXT"],
    ["header_grad_a", "header_grad_a TEXT"],
    ["header_grad_b", "header_grad_b TEXT"],
  ];
  await ensureColumns("users", userColumns);
  await run("UPDATE users SET vibe_tags='[]' WHERE vibe_tags IS NULL");
  await run("UPDATE users SET prefs_json='{}' WHERE prefs_json IS NULL OR prefs_json='' ");

  await migrateLegacyPasswords();

  await run(`
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

  await ensureColumns("messages", [
    ["reply_to_id", "reply_to_id INTEGER"],
    ["reply_to_user", "reply_to_user TEXT"],
    ["reply_to_text", "reply_to_text TEXT"],
    ["edited_at", "edited_at INTEGER"],
  ]);

  await run(`
    CREATE TABLE IF NOT EXISTS reactions (
      message_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      emoji TEXT NOT NULL,
      PRIMARY KEY (message_id, username)
    )
  `);

  await run(`
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

  await run(`
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

  await run(`
    CREATE TABLE IF NOT EXISTS profile_likes (
      user_id INTEGER NOT NULL,
      target_user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, target_user_id)
    )
  `);

  await run(`
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
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_changelog_seq ON changelog_entries(seq)`);

  await run(`
    CREATE TABLE IF NOT EXISTS changelog_reactions (
      entry_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      reaction TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(entry_id, user_id, reaction)
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_changelog_react_entry ON changelog_reactions(entry_id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_changelog_react_user ON changelog_reactions(user_id)`);

  await run(`
    CREATE TABLE IF NOT EXISTS faq_questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at INTEGER NOT NULL,
      question_title TEXT NOT NULL,
      question_details TEXT,
      answer_body TEXT,
      answered_at INTEGER,
      answered_by INTEGER,
      is_deleted INTEGER NOT NULL DEFAULT 0
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_faq_created_at ON faq_questions(created_at DESC)`);

  await run(`
    CREATE TABLE IF NOT EXISTS faq_reactions (
      question_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      reaction_key TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(question_id, username, reaction_key)
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_faq_react_question ON faq_reactions(question_id)`);

  await run(`
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

  await run(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS dm_threads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      is_group INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS dm_participants (
      thread_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      added_by INTEGER,
      joined_at INTEGER NOT NULL,
      UNIQUE(thread_id, user_id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS dm_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      text TEXT,
      ts INTEGER NOT NULL
    )
  `);

  await ensureColumns("dm_messages", [
    ["reply_to_id", "reply_to_id INTEGER"],
    ["reply_to_user", "reply_to_user TEXT"],
    ["reply_to_text", "reply_to_text TEXT"],
    ["edited_at", "edited_at INTEGER"],
    ["attachment_url", "attachment_url TEXT"],
    ["attachment_mime", "attachment_mime TEXT"],
    ["attachment_type", "attachment_type TEXT"],
    ["attachment_size", "attachment_size INTEGER"],
]);
  // DM reactions (1 reaction per user per DM message)
  await run(`
    CREATE TABLE IF NOT EXISTS dm_reactions (
      thread_id INTEGER NOT NULL,
      message_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      emoji TEXT NOT NULL,
      PRIMARY KEY (thread_id, message_id, username)
    )
  `);


  await ensureColumns("dm_threads", [
    ["title", "title TEXT"],
    ["is_group", "is_group INTEGER NOT NULL DEFAULT 0"],
    ["created_by", "created_by INTEGER NOT NULL DEFAULT 0"],
    ["created_at", "created_at INTEGER NOT NULL DEFAULT 0"],
    ["user_low", "user_low INTEGER"],
    ["user_high", "user_high INTEGER"],
    ["last_message_id", "last_message_id INTEGER"],
    ["last_message_at", "last_message_at INTEGER"],
  ]);

  await ensureColumns("dm_participants", [
    ["added_by", "added_by INTEGER"],
    ["joined_at", "joined_at INTEGER NOT NULL DEFAULT 0"],
    ["last_read_at", "last_read_at INTEGER NOT NULL DEFAULT 0"],
  ]);

  await run(`CREATE INDEX IF NOT EXISTS idx_dm_participants_user ON dm_participants(user_id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_dm_participants_thread ON dm_participants(thread_id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_dm_messages_thread_ts ON dm_messages(thread_id, ts)`);
  await run(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_dm_threads_pair
       ON dm_threads(user_low, user_high)
       WHERE is_group = 0 AND user_low IS NOT NULL AND user_high IS NOT NULL`
  );

  await run("UPDATE users SET role='Owner' WHERE lower(username)='iri'");
}

const migrationsReady = runSqliteMigrations();

module.exports = {
  db,
  migrationsReady,
  runSqliteMigrations,
};
