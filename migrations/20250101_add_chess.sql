-- Chess tables for Postgres
CREATE TABLE IF NOT EXISTS chess_user_stats (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  chess_elo INTEGER NOT NULL DEFAULT 1200,
  chess_games_played INTEGER NOT NULL DEFAULT 0,
  chess_wins INTEGER NOT NULL DEFAULT 0,
  chess_losses INTEGER NOT NULL DEFAULT 0,
  chess_draws INTEGER NOT NULL DEFAULT 0,
  chess_peak_elo INTEGER NOT NULL DEFAULT 1200,
  chess_last_game_at BIGINT,
  updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS chess_games (
  game_id TEXT PRIMARY KEY,
  context_type TEXT NOT NULL,
  context_id TEXT NOT NULL,
  white_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  black_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  fen TEXT NOT NULL,
  pgn TEXT NOT NULL,
  status TEXT NOT NULL,
  turn TEXT NOT NULL,
  result TEXT,
  rated BOOLEAN,
  rated_reason TEXT,
  plies_count INTEGER NOT NULL DEFAULT 0,
  draw_offer_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  draw_offer_at BIGINT,
  white_elo_change INTEGER,
  black_elo_change INTEGER,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  last_move_at BIGINT
);

CREATE TABLE IF NOT EXISTS chess_challenges (
  challenge_id TEXT PRIMARY KEY,
  dm_thread_id INTEGER NOT NULL,
  challenger_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenged_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chess_games_context ON chess_games(context_type, context_id);
CREATE INDEX IF NOT EXISTS idx_chess_games_status ON chess_games(status);
CREATE INDEX IF NOT EXISTS idx_chess_challenges_thread ON chess_challenges(dm_thread_id);
CREATE INDEX IF NOT EXISTS idx_chess_challenges_status ON chess_challenges(status);
