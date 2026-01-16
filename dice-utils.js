const DICE_VARIANTS = ["d6", "d20", "2d6", "d100"];

const DICE_VARIANT_LABELS = {
  d6: "d6",
  d20: "d20",
  "2d6": "2d6",
  d100: "1–100",
};

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
  computeDiceReward,
};
