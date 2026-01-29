-- Migration: Add message delivery, read receipts, and soft-delete support
-- This migration adds fields to track message delivery state and read receipts

-- Add delivery and read receipt columns to messages table
-- These are backwards-compatible (nullable timestamps)
ALTER TABLE messages ADD COLUMN delivered_at INTEGER;
ALTER TABLE messages ADD COLUMN read_at INTEGER;

-- Note: edited_at and deleted columns already exist in the schema
-- If they don't exist in older installs, the database.js ensureColumns will add them

-- Create message_edits table to track edit history
CREATE TABLE IF NOT EXISTS message_edits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  old_text TEXT NOT NULL,
  new_text TEXT NOT NULL,
  edited_by_user_id INTEGER NOT NULL,
  edited_by_username TEXT NOT NULL,
  edited_at INTEGER NOT NULL,
  FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_message_edits_message ON message_edits(message_id);
CREATE INDEX IF NOT EXISTS idx_message_edits_timestamp ON message_edits(edited_at);

-- Note: reactions table already exists in the schema
-- It has structure: (message_id, username, emoji) with PRIMARY KEY (message_id, username)
