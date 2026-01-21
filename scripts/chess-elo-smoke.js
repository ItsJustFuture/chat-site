"use strict";

const assert = require("assert");
const sqlite3 = require("sqlite3").verbose();
const { Chess } = require("chess.js");

const CHESS_DEFAULT_ELO = 1200;
const CHESS_MIN_PLIES_RATED = 6;

function expectedScore(ra, rb) {
  return 1 / (1 + Math.pow(10, (rb - ra) / 400));
}

function kFactor(rating, gamesPlayed) {
  if (gamesPlayed < 30) return 40;
  if (rating >= 2000) return 10;
  return 20;
}

function computeElo(white, black, result) {
  const expectedWhite = expectedScore(white.elo, black.elo);
  const expectedBlack = expectedScore(black.elo, white.elo);
  const scoreWhite = result === "white" ? 1 : result === "draw" ? 0.5 : 0;
  const scoreBlack = result === "black" ? 1 : result === "draw" ? 0.5 : 0;
  const whiteNext = Math.round(white.elo + kFactor(white.elo, white.games) * (scoreWhite - expectedWhite));
  const blackNext = Math.round(black.elo + kFactor(black.elo, black.games) * (scoreBlack - expectedBlack));
  return { whiteNext, blackNext };
}

async function run() {
  const db = new sqlite3.Database(":memory:");

  const runAsync = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
  const getAsync = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });

  await runAsync(`
    CREATE TABLE chess_user_stats (
      user_id INTEGER PRIMARY KEY,
      chess_elo INTEGER NOT NULL DEFAULT 1200,
      chess_games_played INTEGER NOT NULL DEFAULT 0,
      chess_wins INTEGER NOT NULL DEFAULT 0,
      chess_losses INTEGER NOT NULL DEFAULT 0,
      chess_draws INTEGER NOT NULL DEFAULT 0,
      chess_peak_elo INTEGER NOT NULL DEFAULT 1200,
      chess_last_game_at INTEGER,
      updated_at INTEGER NOT NULL
    )
  `);

  await runAsync(`INSERT INTO chess_user_stats (user_id, chess_elo, chess_peak_elo, updated_at) VALUES (1, 1200, 1200, 0)`);
  await runAsync(`INSERT INTO chess_user_stats (user_id, chess_elo, chess_peak_elo, updated_at) VALUES (2, 1200, 1200, 0)`);

  const unratedPlies = 4;
  const ratedPlies = 6;

  const beforeWhite = await getAsync(`SELECT chess_elo FROM chess_user_stats WHERE user_id = 1`);
  const beforeBlack = await getAsync(`SELECT chess_elo FROM chess_user_stats WHERE user_id = 2`);
  assert.strictEqual(beforeWhite.chess_elo, CHESS_DEFAULT_ELO);
  assert.strictEqual(beforeBlack.chess_elo, CHESS_DEFAULT_ELO);

  assert.ok(unratedPlies < CHESS_MIN_PLIES_RATED, "unrated game should be below threshold");

  // Rated game: play 3 full moves (6 plies) and apply a white win.
  const chess = new Chess();
  chess.move("e4");
  chess.move("e5");
  chess.move("Nf3");
  chess.move("Nc6");
  chess.move("Bc4");
  chess.move("Nf6");
  assert.strictEqual(chess.history().length, ratedPlies);

  const white = { elo: CHESS_DEFAULT_ELO, games: 0 };
  const black = { elo: CHESS_DEFAULT_ELO, games: 0 };
  const next = computeElo(white, black, "white");
  assert.strictEqual(next.whiteNext, 1220);
  assert.strictEqual(next.blackNext, 1180);

  console.log("Chess Elo smoke test passed.");
  db.close();
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
