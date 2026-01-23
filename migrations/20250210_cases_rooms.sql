-- Mod cases unified system
CREATE TABLE IF NOT EXISTS mod_cases (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'normal',
  subject_user_id INTEGER,
  created_by_user_id INTEGER,
  assigned_to_user_id INTEGER,
  room_id TEXT,
  title TEXT,
  summary TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  closed_at INTEGER,
  closed_reason TEXT
);

CREATE TABLE IF NOT EXISTS mod_case_events (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL,
  actor_user_id INTEGER,
  event_type TEXT NOT NULL,
  event_payload TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mod_case_notes (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL,
  author_user_id INTEGER,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mod_case_evidence (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL,
  evidence_type TEXT NOT NULL,
  room_id TEXT,
  message_id INTEGER,
  message_excerpt TEXT,
  url TEXT,
  text TEXT,
  created_by_user_id INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mod_case_events_case ON mod_case_events(case_id);
CREATE INDEX IF NOT EXISTS idx_mod_case_notes_case ON mod_case_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_mod_case_evidence_case ON mod_case_evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_mod_cases_status ON mod_cases(status);
CREATE INDEX IF NOT EXISTS idx_mod_cases_type ON mod_cases(type);

CREATE TABLE IF NOT EXISTS room_structure_audit (
  id INTEGER PRIMARY KEY,
  action TEXT NOT NULL,
  actor_user_id INTEGER,
  payload TEXT,
  created_at INTEGER NOT NULL
);

-- Room structure indexes (ordering)
CREATE INDEX IF NOT EXISTS idx_room_categories_master_sort ON room_categories(master_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_rooms_category_sort ON rooms(category_id, room_sort_order);
