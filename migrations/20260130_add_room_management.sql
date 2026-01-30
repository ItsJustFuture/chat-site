-- Migration: Add room management features (owner roles, admin roles, room bans)
-- Date: 2026-01-30

-- Create room_members table for tracking room roles (owner, admin, helper)
CREATE TABLE IF NOT EXISTS room_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_name TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT NOT NULL, -- 'owner', 'admin', 'helper'
  assigned_by_user_id INTEGER,
  assigned_at INTEGER NOT NULL,
  FOREIGN KEY (room_name) REFERENCES rooms(name) ON DELETE CASCADE,
  UNIQUE(room_name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_members_room ON room_members(room_name);
CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);
CREATE INDEX IF NOT EXISTS idx_room_members_role ON room_members(room_name, role);

-- Create room_bans table for tracking room-specific bans with durations
CREATE TABLE IF NOT EXISTS room_bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_name TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  banned_by_user_id INTEGER NOT NULL,
  reason TEXT,
  banned_at INTEGER NOT NULL,
  expires_at INTEGER, -- NULL means permanent ban (100 years from banned_at)
  FOREIGN KEY (room_name) REFERENCES rooms(name) ON DELETE CASCADE,
  UNIQUE(room_name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_bans_room ON room_bans(room_name);
CREATE INDEX IF NOT EXISTS idx_room_bans_user ON room_bans(user_id);
CREATE INDEX IF NOT EXISTS idx_room_bans_expires ON room_bans(expires_at);
