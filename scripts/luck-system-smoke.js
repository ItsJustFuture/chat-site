const assert = require("assert");
const {
  LUCK_MIN,
  LUCK_MAX,
  LUCK_BASE_GAIN,
  computeQualifyingLuckGain,
  computeRollStreakPenalty,
  applyWinCut,
  clampLuck,
} = require("../luck-utils");
const { rollDiceVariantWithLuck, isLuckWin } = require("../dice-utils");

function simulate(variant, luck, runs = 60000) {
  let wins = 0;
  let jackpots = 0;
  let oneSix = 0;
  for (let i = 0; i < runs; i += 1) {
    const roll = rollDiceVariantWithLuck(variant, luck);
    if (isLuckWin(variant, roll.result, roll.breakdown)) wins += 1;
    if (variant === "d20" && roll.result === 20) jackpots += 1;
    if (variant === "2d6" && Array.isArray(roll.breakdown)) {
      const sixes = roll.breakdown.filter((n) => n === 6).length;
      if (sixes === 2) jackpots += 1;
      if (sixes === 1) oneSix += 1;
    }
    if (variant === "d100" && roll.result === 100) jackpots += 1;
  }
  return {
    winRate: wins / runs,
    jackpotRate: jackpots / runs,
    oneSixRate: oneSix / runs,
  };
}

assert.strictEqual(clampLuck(99), LUCK_MAX);
assert.strictEqual(clampLuck(-99), LUCK_MIN);

assert.strictEqual(computeRollStreakPenalty(15), 0);
assert.ok(computeRollStreakPenalty(16) > 0);

assert.strictEqual(applyWinCut(0.2, true), 0.1);
assert.strictEqual(applyWinCut(-0.2, true), -0.2);
assert.strictEqual(applyWinCut(0.2, false), 0.2);

assert.strictEqual(computeQualifyingLuckGain(0), LUCK_BASE_GAIN);
assert.ok(computeQualifyingLuckGain(1) < LUCK_BASE_GAIN);

const d6Pos = simulate("d6", LUCK_MAX);
const d6Neg = simulate("d6", LUCK_MIN);
assert.ok(d6Pos.winRate <= 0.19 && d6Pos.winRate >= 0.15);
assert.ok(d6Neg.winRate <= 0.13 && d6Neg.winRate >= 0.09);

const d20Pos = simulate("d20", LUCK_MAX);
const d20Neg = simulate("d20", LUCK_MIN);
assert.ok(d20Pos.jackpotRate <= 0.06 && d20Pos.jackpotRate >= 0.03);
assert.ok(d20Neg.jackpotRate <= 0.055 && d20Neg.jackpotRate >= 0.025);
assert.ok(d20Pos.winRate <= 0.7 && d20Pos.winRate >= 0.35);
assert.ok(d20Neg.winRate <= 0.7 && d20Neg.winRate >= 0.3);

const twoD6Pos = simulate("2d6", LUCK_MAX);
const twoD6Neg = simulate("2d6", LUCK_MIN);
assert.ok(twoD6Pos.jackpotRate <= 0.035 && twoD6Pos.jackpotRate >= 0.015);
assert.ok(twoD6Neg.jackpotRate <= 0.035 && twoD6Neg.jackpotRate >= 0.015);
assert.ok(twoD6Pos.oneSixRate <= 0.32 && twoD6Pos.oneSixRate >= 0.1);
assert.ok(twoD6Neg.oneSixRate <= 0.32 && twoD6Neg.oneSixRate >= 0.1);

const d100Pos = simulate("d100", LUCK_MAX);
const d100Neg = simulate("d100", LUCK_MIN);
assert.ok(d100Pos.jackpotRate <= 0.012 && d100Pos.jackpotRate >= 0.005);
assert.ok(d100Neg.jackpotRate <= 0.012 && d100Neg.jackpotRate >= 0.005);

console.log("luck-system-smoke: ok");
