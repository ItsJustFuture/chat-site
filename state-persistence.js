"use strict";

/**
 * State Persistence Module
 * Provides database-backed state storage that survives server restarts
 * Drop-in replacement for in-memory Maps and Sets
 */

// Will be initialized with db references from server.js
let dbRunAsync = null;
let dbAllAsync = null;
let pgPool = null;
let pgSafeWarned = false;

/**
 * Safe Postgres query helper - never blocks or crashes
 */
async function pgSafe(query, params = []) {
  if (!pgPool) return null;
  try {
    return await pgPool.query(query, params);
  } catch (err) {
    if (!pgSafeWarned) {
      console.warn("[state-persistence][Postgres skipped]", err.message);
      pgSafeWarned = true;
    }
    return null;
  }
}

/**
 * Initialize with database references
 */
function initStateManagement(sqliteRun, sqliteAll, postgres) {
  dbRunAsync = sqliteRun;
  dbAllAsync = sqliteAll;
  pgPool = postgres;
}

/**
 * Create state tables
 */
async function createStateTables() {
  if (!dbRunAsync) return;
  
  // SQLite
  await dbRunAsync(`
    CREATE TABLE IF NOT EXISTS state_kv (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      expires_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `);
  
  await dbRunAsync(`
    CREATE INDEX IF NOT EXISTS idx_state_kv_expires ON state_kv(expires_at)
  `);
  
  // Postgres
  if (pgPool) {
    try {
      await pgSafe(`
        CREATE TABLE IF NOT EXISTS state_kv (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          expires_at BIGINT,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL
        )
      `);
      
      await pgSafe(`
        CREATE INDEX IF NOT EXISTS idx_state_kv_expires ON state_kv(expires_at)
      `);
    } catch (err) {
      // Table may already exist
    }
  }
}

/**
 * Set a state value with optional TTL
 */
async function setState(key, value, ttlSeconds = null) {
  if (!key || !dbRunAsync) return;
  
  const now = Date.now();
  const expiresAt = ttlSeconds ? now + (ttlSeconds * 1000) : null;
  const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
  
  // SQLite
  try {
    await dbRunAsync(
      `INSERT OR REPLACE INTO state_kv (key, value, expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
      [key, valueStr, expiresAt, now, now]
    );
  } catch (err) {
    console.error('[state] SQLite set error:', err.message);
  }
  
  // Postgres
  if (pgPool) {
    try {
      await pgSafe(
        `INSERT INTO state_kv (key, value, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3, updated_at = $5`,
        [key, valueStr, expiresAt, now, now]
      );
    } catch (err) {
      // Silent fail for Postgres
    }
  }
}

/**
 * Get a state value
 */
async function getState(key) {
  if (!key || !dbAllAsync) return null;
  
  const now = Date.now();
  
  try {
    const rows = await dbAllAsync(
      "SELECT value, expires_at FROM state_kv WHERE key = ?",
      [key]
    );
    
    if (!rows || !rows.length) {
      // Try Postgres
      if (pgPool) {
        const result = await pgSafe(
          "SELECT value, expires_at FROM state_kv WHERE key = $1",
          [key]
        );
        
        if (result?.rows && result.rows.length) {
          const row = result.rows[0];
          if (row.expires_at && row.expires_at < now) {
            await deleteState(key);
            return null;
          }
          return row.value;
        }
      }
      return null;
    }
    
    const row = rows[0];
    
    if (row.expires_at && row.expires_at < now) {
      await deleteState(key);
      return null;
    }
    
    return row.value;
  } catch (err) {
    console.error('[state] Get error:', err.message);
    return null;
  }
}

/**
 * Delete a state value
 */
async function deleteState(key) {
  if (!key || !dbRunAsync) return;
  
  try {
    await dbRunAsync("DELETE FROM state_kv WHERE key = ?", [key]);
  } catch (err) {
    // Silent fail
  }
  
  if (pgPool) {
    try {
      await pgSafe("DELETE FROM state_kv WHERE key = $1", [key]);
    } catch (err) {
      // Silent fail
    }
  }
}

/**
 * Check if key exists
 */
async function hasState(key) {
  const value = await getState(key);
  return value !== null;
}

/**
 * Get all keys with prefix
 */
async function getKeysByPrefix(prefix) {
  if (!prefix || !dbAllAsync) return [];
  
  const now = Date.now();
  const pattern = `${prefix}%`;
  
  try {
    const rows = await dbAllAsync(
      "SELECT key FROM state_kv WHERE key LIKE ? AND (expires_at IS NULL OR expires_at > ?)",
      [pattern, now]
    );
    
    return rows.map(row => row.key);
  } catch (err) {
    console.error('[state] Get keys error:', err.message);
    return [];
  }
}

/**
 * Delete keys by prefix
 */
async function deleteByPrefix(prefix) {
  if (!prefix || !dbRunAsync) return;
  
  const pattern = `${prefix}%`;
  
  try {
    await dbRunAsync("DELETE FROM state_kv WHERE key LIKE ?", [pattern]);
  } catch (err) {
    // Silent fail
  }
  
  if (pgPool) {
    try {
      await pgSafe("DELETE FROM state_kv WHERE key LIKE $1", [pattern]);
    } catch (err) {
      // Silent fail
    }
  }
}

/**
 * Cleanup expired state
 */
async function cleanupExpiredState() {
  if (!dbRunAsync) return;
  
  const now = Date.now();
  
  try {
    await dbRunAsync(
      "DELETE FROM state_kv WHERE expires_at IS NOT NULL AND expires_at < ?",
      [now]
    );
  } catch (err) {
    // Silent fail
  }
  
  if (pgPool) {
    try {
      await pgSafe(
        "DELETE FROM state_kv WHERE expires_at IS NOT NULL AND expires_at < $1",
        [now]
      );
    } catch (err) {
      // Silent fail
    }
  }
}

// Cleanup every 5 minutes
setInterval(cleanupExpiredState, 5 * 60 * 1000).unref?.();

// ====================================
// CONVENIENCE HELPERS
// ====================================

/**
 * Track user online status
 */
async function setUserOnline(userId, online = true) {
  const key = `user:${userId}:online`;
  if (online) {
    await setState(key, '1', 300); // 5 minute TTL
  } else {
    await deleteState(key);
  }
}

/**
 * Check if user is online
 */
async function isUserOnline(userId) {
  const key = `user:${userId}:online`;
  return await hasState(key);
}

/**
 * Track typing indicator
 */
async function setTyping(room, userId, typing = true) {
  const key = `room:${room}:typing:${userId}`;
  if (typing) {
    await setState(key, '1', 5); // 5 second TTL
  } else {
    await deleteState(key);
  }
}

/**
 * Get typing users in room
 */
async function getTypingUsers(room) {
  const prefix = `room:${room}:typing:`;
  const keys = await getKeysByPrefix(prefix);
  return keys.map(key => {
    const userId = key.slice(prefix.length);
    return parseInt(userId, 10);
  }).filter(id => !isNaN(id));
}

/**
 * Add to survival lobby
 */
async function addToSurvivalLobby(roomDbId, userId) {
  const key = `survival:lobby:${roomDbId}:${userId}`;
  await setState(key, '1'); // No expiry
}

/**
 * Remove from survival lobby
 */
async function removeFromSurvivalLobby(roomDbId, userId) {
  const key = `survival:lobby:${roomDbId}:${userId}`;
  await deleteState(key);
}

/**
 * Get survival lobby participants
 */
async function getSurvivalLobby(roomDbId) {
  const prefix = `survival:lobby:${roomDbId}:`;
  const keys = await getKeysByPrefix(prefix);
  return keys.map(key => {
    const userId = key.slice(prefix.length);
    return parseInt(userId, 10);
  }).filter(id => !isNaN(id));
}

/**
 * Clear survival lobby
 */
async function clearSurvivalLobby(roomDbId) {
  const prefix = `survival:lobby:${roomDbId}:`;
  await deleteByPrefix(prefix);
}

module.exports = {
  initStateManagement,
  createStateTables,
  setState,
  getState,
  deleteState,
  hasState,
  getKeysByPrefix,
  deleteByPrefix,
  cleanupExpiredState,
  
  // Convenience helpers
  setUserOnline,
  isUserOnline,
  setTyping,
  getTypingUsers,
  addToSurvivalLobby,
  removeFromSurvivalLobby,
  getSurvivalLobby,
  clearSurvivalLobby,
};
