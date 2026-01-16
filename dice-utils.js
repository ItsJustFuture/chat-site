const DICE_VARIANTS = ["d6", "d20", "2d6", "d100"];

const DICE_VARIANT_LABELS = {
  d6: "d6",
  d20: "d20",
  "2d6": "2d6",
  d100: "1–100",
};

const { computeEffectiveLuck } = require("./luck-utils");

function normalizeDiceVariant(variant) {
  const v = String(variant || "").toLowerCase();
  return DICE_VARIANTS.includes(v) ? v : null;
}

function rollDiceVariant(variant) {
  const v = normalizeDiceVariant(variant) || "d6";
  if (v === "2d6") {
    const die1 = Math.floor(Math.random() * 6) + 1;
    const die2 = Math.floor(Math.random() * 6) + 1;
    const result = die1 + die2;
    return {
      variant: v,
      result,
      breakdown: [die1, die2],
      won: result === 12,
    };
  }
  const max = v === "d6" ? 6 : v === "d20" ? 20 : 100;
  const result = Math.floor(Math.random() * max) + 1;
  return {
    variant: v,
    result,
    breakdown: null,
    won: result === max,
  };
}

function clampNumber(value, min, max) {
  const num = Number(value || 0);
  return Math.max(min, Math.min(max, num));
}

// Luck-biased dice rolls. Luck only adjusts win odds; payouts remain unchanged.
function rollDiceVariantWithLuck(variant, luck) {
  const v = normalizeDiceVariant(variant) || "d6";
  const effective = computeEffectiveLuck(luck);
  const rand = Math.random();

  if (v === "d6") {
    const baseP6 = 1 / 6;
    const delta = clampNumber(effective * 0.06, -0.06, 0.01);
    const p6 = clampNumber(baseP6 + delta, 0.10, 0.22);
    if (rand < p6) {
      return { variant: v, result: 6, breakdown: null, won: true };
    }
    const result = Math.floor(Math.random() * 5) + 1;
    return { variant: v, result, breakdown: null, won: result === 6 };
  }

  if (v === "d20") {
    const jackpotDelta = clampNumber(effective * 0.004, -0.015, 0.004);
    const goodDelta = clampNumber(effective * 0.03, -0.15, 0.02);
    const pJackpot = clampNumber(0.05 + jackpotDelta, 0.03, 0.054);
    const pGood = clampNumber(0.45 + goodDelta, 0.30, 0.47);
    const pBad = Math.max(0, 1 - pJackpot - pGood);

    if (rand < pJackpot) {
      return { variant: v, result: 20, breakdown: null, won: true };
    }
    if (rand < pJackpot + pGood) {
      const result = Math.floor(Math.random() * 9) + 11;
      return { variant: v, result, breakdown: null, won: result === 20 };
    }
    const result = Math.floor(Math.random() * 10) + 1;
    return { variant: v, result, breakdown: null, won: result === 20 };
  }

  if (v === "2d6") {
    const baseJackpot = 1 / 36;
    const baseOneSix = 10 / 36;
    const jackpotDelta = clampNumber(effective * 0.003, -0.01, 0.003);
    const oneSixDelta = clampNumber(effective * 0.03, -0.15, 0.02);
    const pJackpot = clampNumber(baseJackpot + jackpotDelta, 0.018, 0.031);
    const pOneSix = clampNumber(baseOneSix + oneSixDelta, 0.13, 0.30);
    const pNoSix = Math.max(0, 1 - pJackpot - pOneSix);
    const bucketRoll = Math.random() * (pJackpot + pOneSix + pNoSix);

    if (bucketRoll < pJackpot) {
      return { variant: v, result: 12, breakdown: [6, 6], won: true };
    }
    if (bucketRoll < pJackpot + pOneSix) {
      const other = Math.floor(Math.random() * 5) + 1;
      const pickFirst = Math.random() < 0.5;
      const breakdown = pickFirst ? [6, other] : [other, 6];
      return { variant: v, result: breakdown[0] + breakdown[1], breakdown, won: false };
    }
    const die1 = Math.floor(Math.random() * 5) + 1;
    const die2 = Math.floor(Math.random() * 5) + 1;
    return { variant: v, result: die1 + die2, breakdown: [die1, die2], won: false };
  }

  // d100
  const delta100 = clampNumber(effective * 0.001, -0.004, 0.001);
  const delta69 = clampNumber(effective * 0.005, -0.008, 0.005);
  const p100 = clampNumber(0.01 + delta100, 0.006, 0.011);
  const p69 = clampNumber(0.01 + delta69, 0.005, 0.015);

  if (rand < p100) {
    return { variant: v, result: 100, breakdown: null, won: true };
  }
  if (rand < p100 + p69) {
    return { variant: v, result: 69, breakdown: null, won: false };
  }
  const pool = [];
  for (let i = 1; i <= 100; i += 1) {
    if (i === 69 || i === 100) continue;
    pool.push(i);
  }
  const result = pool[Math.floor(Math.random() * pool.length)];
  return { variant: v, result, breakdown: null, won: false };
}

function isLuckWin(variant, result, breakdown) {
  const v = normalizeDiceVariant(variant) || "d6";
  const r = Number(result || 0);
  if (v === "d6") return r === 6;
  if (v === "d20") return r >= 11 && r <= 20;
  if (v === "2d6") {
    const b = Array.isArray(breakdown) ? breakdown.map((n) => Number(n || 0)) : [];
    return b.includes(6);
  }
  return r === 69 || r === 100;
}

// Reward rules (January 2026):
// - d6: -50 for 1-5, +500 for 6
// - d20: -250 (1-5), -100 (6-10), +100 (11-14), +250 (15-17), +500 (18-19), +1000 (20)
// - 2d6: +500 if one die is 6, +1500 if both are 6, else -100
// - d100: 69 => +69, 100 => +5000, else -25
function computeDiceReward(variant, result, breakdown) {
  const v = normalizeDiceVariant(variant) || "d6";
  const r = Number(result || 0);
  if (v === "d6") {
    return {
      deltaGold: r === 6 ? 500 : -50,
      minBalanceRequired: 50,
      outcome: r === 6 ? "win" : "loss",
      isJackpot: false,
    };
  }
  if (v === "d20") {
    let deltaGold = -100;
    let outcome = "loss";
    if (r >= 1 && r <= 5) deltaGold = -250;
    else if (r >= 6 && r <= 10) deltaGold = -100;
    else if (r >= 11 && r <= 14) { deltaGold = 100; outcome = "win"; }
    else if (r >= 15 && r <= 17) { deltaGold = 250; outcome = "win"; }
    else if (r >= 18 && r <= 19) { deltaGold = 500; outcome = "bigwin"; }
    else if (r === 20) { deltaGold = 1000; outcome = "jackpot"; }
    return {
      deltaGold,
      minBalanceRequired: 250,
      outcome,
      isJackpot: r === 20,
    };
  }
  if (v === "2d6") {
    const b = Array.isArray(breakdown) ? breakdown.map((n) => Number(n || 0)) : [];
    const sixes = b.filter((n) => n === 6).length;
    if (sixes >= 2) {
      return { deltaGold: 1500, minBalanceRequired: 100, outcome: "jackpot", isJackpot: true };
    }
    if (sixes === 1) {
      return { deltaGold: 500, minBalanceRequired: 100, outcome: "win", isJackpot: false };
    }
    return { deltaGold: -100, minBalanceRequired: 100, outcome: "loss", isJackpot: false };
  }
  // d100
  if (r === 69) {
    return { deltaGold: 69, minBalanceRequired: 25, outcome: "nice", isJackpot: false };
  }
  if (r === 100) {
    return { deltaGold: 5000, minBalanceRequired: 25, outcome: "jackpot", isJackpot: true };
  }
  return { deltaGold: -25, minBalanceRequired: 25, outcome: "loss", isJackpot: false };
}

module.exports = {
  DICE_VARIANTS,
  DICE_VARIANT_LABELS,
  normalizeDiceVariant,
  rollDiceVariant,
  rollDiceVariantWithLuck,
  isLuckWin,
  computeDiceReward,
};
