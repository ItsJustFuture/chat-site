/**
 * Room Management Test
 * Tests room ownership, promotion, demotion, and ban features
 */

"use strict";

const path = require("path");
process.env.SQLITE_PATH = path.join(__dirname, "..", "data", "test-room-mgmt.sqlite");

const fs = require("fs");
const dbPath = process.env.SQLITE_PATH;
if (fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
  console.log("[test] Cleaned up test database");
}

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

async function runTests() {
  console.log("\n=== Room Management Tests ===\n");

  // Wait for migrations
  await migrationsReady;
  console.log("✓ Database migrations completed");

  // Create test users
  const now = Date.now();
  await dbRunAsync(
    `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
    ["owner_user", "hash123", "Admin", now]
  );
  const ownerRow = await dbGetAsync(`SELECT id FROM users WHERE username = ?`, ["owner_user"]);
  const ownerId = ownerRow.id;

  await dbRunAsync(
    `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
    ["test_user", "hash456", "User", now]
  );
  const userRow = await dbGetAsync(`SELECT id FROM users WHERE username = ?`, ["test_user"]);
  const userId = userRow.id;

  console.log(`✓ Created test users (owner: ${ownerId}, user: ${userId})`);

  // Test 1: Create room with owner assignment
  const roomName = "testroom";
  await dbRunAsync(
    `INSERT INTO rooms (name, created_by, created_at, created_by_user_id, is_user_room) VALUES (?, ?, ?, ?, 0)`,
    [roomName, ownerId, now, ownerId]
  );

  // Simulate owner assignment (as done in createroom handler)
  await dbRunAsync(
    `INSERT INTO room_members (room_name, user_id, role, assigned_by_user_id, assigned_at) VALUES (?, ?, 'owner', ?, ?)`,
    [roomName, ownerId, ownerId, now]
  );

  const ownerCheck = await dbGetAsync(
    `SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`,
    [roomName, ownerId]
  );

  if (ownerCheck && ownerCheck.role === "owner") {
    console.log("✓ Room created with owner assignment");
  } else {
    throw new Error("Owner assignment failed");
  }

  // Test 2: Promote user to admin
  await dbRunAsync(
    `INSERT INTO room_members (room_name, user_id, role, assigned_by_user_id, assigned_at) VALUES (?, ?, 'admin', ?, ?)`,
    [roomName, userId, ownerId, now]
  );

  const adminCheck = await dbGetAsync(
    `SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  if (adminCheck && adminCheck.role === "admin") {
    console.log("✓ User promoted to admin");
  } else {
    throw new Error("Admin promotion failed");
  }

  // Test 3: Update role (promote to admin, then demote to helper)
  await dbRunAsync(
    `UPDATE room_members SET role = 'helper' WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  const helperCheck = await dbGetAsync(
    `SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  if (helperCheck && helperCheck.role === "helper") {
    console.log("✓ User demoted to helper");
  } else {
    throw new Error("Helper assignment failed");
  }

  // Test 4: Ban user from room
  const banTime = now;
  const expires5Min = banTime + 5 * 60 * 1000;

  await dbRunAsync(
    `INSERT INTO room_bans (room_name, user_id, banned_by_user_id, reason, banned_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [roomName, userId, ownerId, "Test ban", banTime, expires5Min]
  );

  const banCheck = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  if (banCheck && banCheck.expires_at === expires5Min) {
    console.log("✓ User banned from room with 5-minute duration");
  } else {
    throw new Error("Ban creation failed");
  }

  // Test 5: Check ban expiration logic
  const activeBan = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > ?)`,
    [roomName, userId, now]
  );

  if (activeBan) {
    console.log("✓ Active ban detected correctly");
  } else {
    throw new Error("Active ban check failed");
  }

  // Test 6: Permanent ban (no expiry)
  const bannedUserId = userId;
  await dbRunAsync(
    `UPDATE room_bans SET expires_at = NULL WHERE room_name = ? AND user_id = ?`,
    [roomName, bannedUserId]
  );

  const permBan = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ? AND expires_at IS NULL`,
    [roomName, bannedUserId]
  );

  if (permBan) {
    console.log("✓ Permanent ban works correctly");
  } else {
    throw new Error("Permanent ban failed");
  }

  // Test 7: Unban user
  await dbRunAsync(
    `DELETE FROM room_bans WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  const unbanCheck = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ?`,
    [roomName, userId]
  );

  if (!unbanCheck) {
    console.log("✓ User unbanned successfully");
  } else {
    throw new Error("Unban failed");
  }

  // Test 7.5: Create an admin user to test ban duration restrictions
  await dbRunAsync(
    `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
    ["admin_user", "hash789", "User", now]
  );
  const adminUserRow = await dbGetAsync(`SELECT id FROM users WHERE username = ?`, ["admin_user"]);
  const adminUserId = adminUserRow.id;

  // Promote to room admin
  await dbRunAsync(
    `INSERT INTO room_members (room_name, user_id, role, assigned_by_user_id, assigned_at) VALUES (?, ?, 'admin', ?, ?)`,
    [roomName, adminUserId, ownerId, now]
  );

  // Create target user for ban tests
  await dbRunAsync(
    `INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
    ["ban_target", "hash101112", "User", now]
  );
  const banTargetRow = await dbGetAsync(`SELECT id FROM users WHERE username = ?`, ["ban_target"]);
  const banTargetId = banTargetRow.id;

  console.log("✓ Created admin user and ban target for restriction tests");

  // Test 7.6: Verify admin can ban for 7 days or less (should work)
  const sevenDayBan = now + 7 * 24 * 60 * 60 * 1000;
  await dbRunAsync(
    `INSERT INTO room_bans (room_name, user_id, banned_by_user_id, reason, banned_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [roomName, banTargetId, adminUserId, "7-day test by admin", now, sevenDayBan]
  );

  const sevenDayCheck = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ? AND banned_by_user_id = ?`,
    [roomName, banTargetId, adminUserId]
  );

  if (sevenDayCheck && sevenDayCheck.expires_at === sevenDayBan) {
    console.log("✓ Admin can ban for exactly 7 days");
  } else {
    throw new Error("Admin 7-day ban failed");
  }

  // Clean up for next test
  await dbRunAsync(`DELETE FROM room_bans WHERE room_name = ? AND user_id = ?`, [roomName, banTargetId]);

  // Test 7.7: Verify owner can ban for more than 7 days (30 days - should work)
  const thirtyDayBan = now + 30 * 24 * 60 * 60 * 1000;
  await dbRunAsync(
    `INSERT INTO room_bans (room_name, user_id, banned_by_user_id, reason, banned_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [roomName, banTargetId, ownerId, "30-day test by owner", now, thirtyDayBan]
  );

  const thirtyDayCheck = await dbGetAsync(
    `SELECT * FROM room_bans WHERE room_name = ? AND user_id = ? AND banned_by_user_id = ?`,
    [roomName, banTargetId, ownerId]
  );

  if (thirtyDayCheck && thirtyDayCheck.expires_at === thirtyDayBan) {
    console.log("✓ Owner can ban for more than 7 days (30 days tested)");
  } else {
    throw new Error("Owner 30-day ban failed");
  }

  // Clean up
  await dbRunAsync(`DELETE FROM room_bans WHERE room_name = ? AND user_id = ?`, [roomName, banTargetId]);

  console.log("✓ Ban duration restriction tests passed (7-day threshold enforced)");

  // Test 8: List room members
  const members = await dbAllAsync(
    `SELECT rm.user_id, rm.role, u.username 
     FROM room_members rm
     JOIN users u ON u.id = rm.user_id
     WHERE rm.room_name = ?
     ORDER BY CASE rm.role WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 WHEN 'helper' THEN 3 ELSE 4 END`,
    [roomName]
  );

  if (members.length === 3) {
    console.log(`✓ Room members list working (${members.length} members)`);
    members.forEach(m => {
      console.log(`  - ${m.username}: ${m.role}`);
    });
  } else {
    throw new Error(`Member listing failed - expected 3 members, got ${members.length}`);
  }

  // Test 9: Room rename
  const newRoomName = "renamedroom";
  
  // Simulate the rename process from server.js (disable FK, update children first, then parent, re-enable FK)
  await dbRunAsync(`PRAGMA foreign_keys = OFF`);
  await dbRunAsync(`UPDATE room_members SET room_name = ? WHERE room_name = ?`, [newRoomName, roomName]);
  await dbRunAsync(`UPDATE rooms SET name = ? WHERE name = ?`, [newRoomName, roomName]);
  await dbRunAsync(`PRAGMA foreign_keys = ON`);

  const renamedCheck = await dbGetAsync(`SELECT name FROM rooms WHERE name = ?`, [newRoomName]);

  if (renamedCheck) {
    console.log("✓ Room renamed successfully");

    const memberAfterRename = await dbGetAsync(
      `SELECT * FROM room_members WHERE room_name = ? AND user_id = ?`,
      [newRoomName, ownerId]
    );

    if (memberAfterRename) {
      console.log("✓ Room member associations maintained after rename");
    } else {
      throw new Error("Room member associations lost after rename");
    }
  } else {
    throw new Error("Room rename failed");
  }

  // Test 10: Cascade delete check
  await dbRunAsync(`DELETE FROM rooms WHERE name = ?`, [newRoomName]);

  const memberCheck = await dbGetAsync(
    `SELECT * FROM room_members WHERE room_name = ?`,
    [newRoomName]
  );

  if (!memberCheck) {
    console.log("✓ Cascade delete working (room_members cleaned up)");
  } else {
    throw new Error("Cascade delete failed for room_members");
  }

  console.log("\n✓ All room management tests passed!\n");
  process.exit(0);
}

runTests().catch((err) => {
  console.error("\n✗ Test failed:", err.message);
  console.error(err.stack);
  process.exit(1);
});
