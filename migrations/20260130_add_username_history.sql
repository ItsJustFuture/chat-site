-- Migration: Add username history tracking
-- Date: 2026-01-30
-- Purpose: Track all username changes for moderation purposes

-- Create username_history table to track all username changes
CREATE TABLE IF NOT EXISTS username_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  old_username TEXT NOT NULL,
  new_username TEXT NOT NULL,
  changed_at INTEGER NOT NULL,
  changed_by TEXT NOT NULL DEFAULT 'self',
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_username_history_user ON username_history(user_id);
CREATE INDEX IF NOT EXISTS idx_username_history_changed_at ON username_history(changed_at DESC);
