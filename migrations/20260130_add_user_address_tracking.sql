-- Migration: Add user address tracking for MAC and IP addresses
-- Date: 2026-01-30
-- Purpose: Track all MAC addresses and IP addresses per user for moderation and linked account detection

-- Create user_addresses table to track all addresses used by each user
CREATE TABLE IF NOT EXISTS user_addresses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  address_type TEXT NOT NULL CHECK(address_type IN ('ip', 'mac')),
  address_value TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  connection_count INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, address_type, address_value)
);

CREATE INDEX IF NOT EXISTS idx_user_addresses_user ON user_addresses(user_id);
CREATE INDEX IF NOT EXISTS idx_user_addresses_value ON user_addresses(address_value, address_type);
CREATE INDEX IF NOT EXISTS idx_user_addresses_last_seen ON user_addresses(last_seen);

-- Create address_bans table for banned addresses (separate from user bans)
CREATE TABLE IF NOT EXISTS address_bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address_type TEXT NOT NULL CHECK(address_type IN ('ip', 'mac')),
  address_value TEXT NOT NULL,
  reason TEXT,
  banned_by_user_id INTEGER,
  banned_by_username TEXT,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(address_type, address_value)
);

CREATE INDEX IF NOT EXISTS idx_address_bans_value ON address_bans(address_value, address_type);
CREATE INDEX IF NOT EXISTS idx_address_bans_expires ON address_bans(expires_at);
