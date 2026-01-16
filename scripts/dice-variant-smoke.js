const assert = require("assert");
const { DICE_VARIANTS, normalizeDiceVariant, rollDiceVariant } = require("../dice-utils");

const runs = 50;

assert.strictEqual(normalizeDiceVariant("d6"), "d6");
assert.strictEqual(normalizeDiceVariant("D20"), "d20");
assert.strictEqual(normalizeDiceVariant("2d6"), "2d6");
assert.strictEqual(normalizeDiceVariant("d100"), "d100");
assert.strictEqual(normalizeDiceVariant("nope"), null);

for (const variant of DICE_VARIANTS) {
  for (let i = 0; i < runs; i += 1) {
    const roll = rollDiceVariant(variant);
    assert.strictEqual(roll.variant, variant);
    if (variant === "d6") {
      assert.ok(roll.result >= 1 && roll.result <= 6);
      assert.strictEqual(roll.won, roll.result === 6);
    } else if (variant === "d20") {
      assert.ok(roll.result >= 1 && roll.result <= 20);
      assert.strictEqual(roll.won, roll.result === 20);
    } else if (variant === "2d6") {
      assert.ok(roll.result >= 2 && roll.result <= 12);
      assert.ok(Array.isArray(roll.breakdown));
      assert.strictEqual(roll.breakdown.length, 2);
      assert.strictEqual(roll.result, roll.breakdown[0] + roll.breakdown[1]);
      assert.strictEqual(roll.won, roll.result === 12);
    } else if (variant === "d100") {
      assert.ok(roll.result >= 1 && roll.result <= 100);
      assert.strictEqual(roll.won, roll.result === 100);
    }
  }
}

console.log("dice-variant-smoke: ok");
