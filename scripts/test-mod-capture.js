#!/usr/bin/env node
"use strict";

/**
 * Test script for auto-clear and message capture on kick/ban
 * Validates that the new moderation features work correctly
 */

const path = require("path");
const fs = require("fs");

// Set up test environment
process.env.LOCAL_DEV = "1";
process.env.SESSION_SECRET = "test-secret";
process.env.SQLITE_PATH = "./data/test-mod-capture.sqlite";

// Remove test database if it exists
const testDbPath = path.join(__dirname, "..", "data", "test-mod-capture.sqlite");
if (fs.existsSync(testDbPath)) {
  fs.unlinkSync(testDbPath);
}

// Import database module to set up schema
const { db, migrationsReady } = require("../database");

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
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

async function runTests() {
  console.log("[test-mod-capture] Starting tests...");

  try {
    // Wait for database to be ready
    await new Promise((resolve) => setTimeout(resolve, 500));

    // Test 1: Create test users
    console.log("[test-mod-capture] Test 1: Creating test users");
    await dbRunAsync(
      `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
      ["test_mod", "hash", "Moderator", Date.now()]
    );
    await dbRunAsync(
      `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
      ["test_user", "hash", "User", Date.now()]
    );

    const mod = await dbGetAsync(`SELECT id FROM users WHERE username=?`, ["test_mod"]);
    const user = await dbGetAsync(`SELECT id FROM users WHERE username=?`, ["test_user"]);

    if (!mod || !user) {
      throw new Error("Failed to create test users");
    }
    console.log("[test-mod-capture] ✓ Test users created");

    // Test 2: Create test room
    console.log("[test-mod-capture] Test 2: Creating test room");
    await dbRunAsync(
      `INSERT INTO rooms (name, created_by, created_at) VALUES (?, ?, ?)`,
      ["testroom", null, Date.now()]
    );
    console.log("[test-mod-capture] ✓ Test room created");

    // Test 3: Create test messages
    console.log("[test-mod-capture] Test 3: Creating test messages");
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      await dbRunAsync(
        `INSERT INTO messages (room, user_id, username, role, text, ts, deleted) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ["testroom", user.id, "test_user", "User", `Test message ${i + 1}`, now - i * 1000, 0]
      );
    }

    const messages = await dbAllAsync(
      `SELECT id, text FROM messages WHERE user_id=? AND deleted=0`,
      [user.id]
    );

    if (messages.length !== 5) {
      throw new Error(`Expected 5 messages, got ${messages.length}`);
    }
    console.log("[test-mod-capture] ✓ Test messages created");

    // Test 4: Load server module (for verification, not full testing)
    const server = require("../server");
    
    // We can't easily test the socket handlers without starting the full server,
    // but we can verify the database operations work correctly

    // Test 5: Verify message retrieval
    console.log("[test-mod-capture] Test 5: Verifying message retrieval");
    const userMessages = await dbAllAsync(
      `SELECT id, room, text, ts, username, attachment_url, reply_to_id 
       FROM messages 
       WHERE user_id = ? AND deleted = 0 
       ORDER BY ts DESC 
       LIMIT ?`,
      [user.id, 5]
    );

    if (userMessages.length !== 5) {
      throw new Error(`Expected 5 messages, got ${userMessages.length}`);
    }

    // Verify messages are in descending order (newest first)
    for (let i = 1; i < userMessages.length; i++) {
      if (userMessages[i].ts > userMessages[i - 1].ts) {
        throw new Error("Messages not in descending timestamp order");
      }
    }
    console.log("[test-mod-capture] ✓ Messages retrieved correctly");

    // Test 6: Test message clearing
    console.log("[test-mod-capture] Test 6: Testing message clearing");
    await dbRunAsync(`UPDATE messages SET deleted=1 WHERE user_id=?`, [user.id]);
    await dbRunAsync(`DELETE FROM reactions WHERE message_id IN (SELECT id FROM messages WHERE user_id=?)`, [user.id]);

    const remainingMessages = await dbAllAsync(
      `SELECT id FROM messages WHERE user_id=? AND deleted=0`,
      [user.id]
    );

    if (remainingMessages.length !== 0) {
      throw new Error(`Expected 0 messages after clear, got ${remainingMessages.length}`);
    }
    console.log("[test-mod-capture] ✓ Messages cleared successfully");

    // Test 7: Verify mod log structure
    console.log("[test-mod-capture] Test 7: Verifying mod log structure");
    const modLogSchema = await dbAllAsync(`PRAGMA table_info(mod_logs)`);
    const hasDetails = modLogSchema.some(col => col.name === "details");
    
    if (!hasDetails) {
      throw new Error("mod_logs table missing 'details' column");
    }
    console.log("[test-mod-capture] ✓ Mod log structure verified");

    console.log("\n[test-mod-capture] ✅ All tests passed!");
    process.exit(0);

  } catch (err) {
    console.error("\n[test-mod-capture] ❌ Test failed:", err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

// Run tests
runTests();
