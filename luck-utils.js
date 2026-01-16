"use strict";

const crypto = require("crypto");

// ---- Luck system tuning constants (server-authoritative)
const LUCK_MIN = -2.0;
const LUCK_MAX = 0.30;

const LUCK_MESSAGE_MIN_LEN = 15;
const LUCK_BASE_GAIN = 0.003;
const LUCK_MESSAGE_DECAY = 0.85;
const LUCK_MESSAGE_WINDOW_MS = 60_000;
const LUCK_REPEAT_WINDOW_MS = 10 * 60_000;

const LUCK_STREAK_THRESHOLD = 15;
const LUCK_STREAK_BASE_PENALTY = 0.01;
const LUCK_STREAK_PENALTY_STEP = 0.003;
const LUCK_STREAK_PENALTY_CAP = 0.08;

const LUCK_CADENCE_WINDOW = 8;
const LUCK_CADENCE_STDDEV_THRESHOLD_MS = 120;
const LUCK_CADENCE_MEAN_MAX_MS = 1800;
const LUCK_CADENCE_PENALTY = 0.02;
const LUCK_RECENT_BREAK_WINDOW_MS = 5 * 60_000;

function clampLuck(value) {
  const num = Number(value || 0);
  return Math.max(LUCK_MIN, Math.min(LUCK_MAX, num));
}

function normalizeLuckMessage(text) {
  return String(text || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function hashLuckMessage(text) {
  const normalized = normalizeLuckMessage(text);
  return crypto.createHash("sha256").update(normalized).digest("hex");
}

function computeQualifyingLuckGain(countInWindow) {
  const count = Math.max(0, Number(countInWindow || 0));
  return LUCK_BASE_GAIN * Math.pow(LUCK_MESSAGE_DECAY, count);
}

function computeRollStreakPenalty(rollStreak) {
  const streak = Number(rollStreak || 0);
  if (streak <= LUCK_STREAK_THRESHOLD) return 0;
  const excess = streak - LUCK_STREAK_THRESHOLD;
  const penalty = LUCK_STREAK_BASE_PENALTY + LUCK_STREAK_PENALTY_STEP * excess;
  return Math.min(penalty, LUCK_STREAK_PENALTY_CAP);
}

function applyWinCut(luck, didWin) {
  const value = Number(luck || 0);
  if (!didWin || value <= 0) return value;
  return value * 0.5;
}

function computeEffectiveLuck(luck) {
  const value = Number(luck || 0);
  const pos = Math.max(value, 0);
  const neg = Math.min(value, 0);
  return pos * 0.35 + neg * 0.90;
}

module.exports = {
  LUCK_MIN,
  LUCK_MAX,
  LUCK_MESSAGE_MIN_LEN,
  LUCK_BASE_GAIN,
  LUCK_MESSAGE_DECAY,
  LUCK_MESSAGE_WINDOW_MS,
  LUCK_REPEAT_WINDOW_MS,
  LUCK_STREAK_THRESHOLD,
  LUCK_STREAK_BASE_PENALTY,
  LUCK_STREAK_PENALTY_STEP,
  LUCK_STREAK_PENALTY_CAP,
  LUCK_CADENCE_WINDOW,
  LUCK_CADENCE_STDDEV_THRESHOLD_MS,
  LUCK_CADENCE_MEAN_MAX_MS,
  LUCK_CADENCE_PENALTY,
  LUCK_RECENT_BREAK_WINDOW_MS,
  clampLuck,
  normalizeLuckMessage,
  hashLuckMessage,
  computeQualifyingLuckGain,
  computeRollStreakPenalty,
  applyWinCut,
  computeEffectiveLuck,
};
