"use strict";

/**
 * database.js
 * Single SQLite connection helper.
 *
 * IMPORTANT:
 * - server.js is the authoritative place that runs SQLite migrations/schema setup.
 * - This module intentionally does NOT define tables/columns to avoid schema drift.
 */

const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const DB_FILE = process.env.DB_FILE || path.join(__dirname, "chat.db");

// Export a ready-to-use connection (same DB file as server.js)
const db = new sqlite3.Database(DB_FILE);

module.exports = db;
