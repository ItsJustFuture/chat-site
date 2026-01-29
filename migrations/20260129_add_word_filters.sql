-- Add word filter table for in-site moderation
-- Allows owner/co-owner/admin to manage filtered words and phrases

CREATE TABLE IF NOT EXISTS word_filters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filter_text TEXT NOT NULL UNIQUE,
  is_phrase INTEGER NOT NULL DEFAULT 0,
  is_hardcoded INTEGER NOT NULL DEFAULT 0,
  added_by_user_id INTEGER,
  added_by_username TEXT,
  created_at INTEGER NOT NULL,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_word_filters_text ON word_filters(filter_text);
CREATE INDEX IF NOT EXISTS idx_word_filters_hardcoded ON word_filters(is_hardcoded);
