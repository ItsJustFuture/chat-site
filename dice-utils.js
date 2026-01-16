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

module.exports = {
  DICE_VARIANTS,
  DICE_VARIANT_LABELS,
  normalizeDiceVariant,
  rollDiceVariant,
};
