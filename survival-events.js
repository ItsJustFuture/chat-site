"use strict";

const SURVIVAL_ITEM_POOL = {
  weapon: [
    "folding chair",
    "foam bat",
    "rubber mallet",
    "camping spatula",
    "broomstick spear",
    "staple gun",
    "plastic sabre",
    "glitter cannon",
    "trophy wrench",
    "umbrella sword",
  ],
  food: [
    "mystery granola",
    "spicy ramen",
    "pocket cookies",
    "trail mix",
    "moon cheese",
    "energy gummies",
    "suspicious sandwich",
    "marshmallow pack",
    "midnight noodles",
    "canned peaches",
  ],
  medkit: [
    "first-aid kit",
    "bandage roll",
    "ice pack",
    "herbal salve",
    "peppermint balm",
    "recovery spray",
  ],
  trap: [
    "tripwire",
    "noise maker",
    "sticky mat",
    "smoke popper",
    "glitter bomb",
  ],
  map: [
    "crumpled map",
    "glow compass",
    "scribbled blueprint",
    "weathered chart",
    "trail markers",
  ],
};

const soloLoot = [
  { text: "{A} finds a {ITEM} and declares it a legendary artifact.", tag: "weapon" },
  { text: "{A} uncovers {ITEM} stashed inside a hollow log.", tag: "food" },
  { text: "{A} fishes out a {ITEM} from a supply crate.", tag: "medkit" },
  { text: "{A} scores a {ITEM} and refuses to explain how.", tag: "trap" },
  { text: "{A} pockets a {ITEM} and whispers, 'mine now'.", tag: "map" },
  { text: "{A} stumbles on a {ITEM} and instantly feels faster.", tag: "weapon" },
  { text: "{A} grabs a {ITEM} and does a victory lap.", tag: "food" },
  { text: "{A} discovers a {ITEM} hidden under a rock.", tag: "medkit" },
  { text: "{A} sets aside a {ITEM} for 'later shenanigans'.", tag: "trap" },
  { text: "{A} snags a {ITEM} and navigates with swagger.", tag: "map" },
  { text: "{A} opens a locker and finds {ITEM}.", tag: "weapon" },
  { text: "{A} raids a cooler for {ITEM}.", tag: "food" },
  { text: "{A} pulls a {ITEM} from their sock. Why was it there?", tag: "medkit" },
  { text: "{A} finds a {ITEM} and labels it \"Emergency prank\".", tag: "trap" },
  { text: "{A} flips a page and reveals a {ITEM}.", tag: "map" },
  { text: "{A} discovers {ITEM} hanging from a tree branch.", tag: "weapon" },
  { text: "{A} pockets {ITEM} and munches immediately.", tag: "food" },
  { text: "{A} salvages {ITEM} from a ruined tent.", tag: "medkit" },
  { text: "{A} rolls a {ITEM} into their bag like a pro.", tag: "trap" },
  { text: "{A} finds {ITEM} and marks a route in the dirt.", tag: "map" },
];

const soloHeal = [
  "{A} wraps up a scrape and feels brand-new.",
  "{A} rests by a warm vent and recovers some energy.",
  "{A} brews a calming tea and steadies their nerves.",
  "{A} finds a quiet nook and patches up.",
  "{A} does stretches and heals a stubborn ache.",
  "{A} meditates under a flickering light and regains focus.",
  "{A} treats a bruise with surprising professionalism.",
  "{A} naps for exactly twelve minutes and feels better.",
  "{A} hums a battle song and shrugs off the pain.",
  "{A} tightens a bandage and gets back in the game.",
];

const soloInjure = [
  "{A} slips on wet leaves and lands badly.",
  "{A} misjudges a leap and takes a rough tumble.",
  "{A} gets bonked by a swinging branch.",
  "{A} steps into a puddle that was deeper than expected.",
  "{A} bumps into a fence and regrets it.",
  "{A} trips over their own shoelace. Classic.",
  "{A} knocks into a crate and bruises a shoulder.",
  "{A} sprints too hard and pulls something important.",
  "{A} gets startled by an owl and stumbles.",
  "{A} faceplants while trying to look cool.",
];

const soloNeutral = [
  "{A} scouts the area and keeps moving.",
  "{A} hides in a bush and listens carefully.",
  "{A} hums a tune to stay calm.",
  "{A} takes a cautious shortcut.",
  "{A} finds a cozy hiding spot and chills.",
  "{A} builds a tiny fort and feels accomplished.",
  "{A} practices dramatic monologues. It helps.",
  "{A} spends the hour reorganizing their bag.",
  "{A} stares at the horizon like a hero.",
  "{A} counts clouds and avoids trouble.",
  "{A} doodles survival notes on a leaf.",
  "{A} checks the wind and changes course.",
  "{A} does a silent victory dance.",
  "{A} strategizes and stays out of sight.",
  "{A} finds a decent perch and watches the chaos.",
  "{A} spends time inventing a new handshake.",
  "{A} chooses caution over chaos.",
  "{A} reads the vibes and keeps moving.",
  "{A} listens for footsteps and keeps still.",
  "{A} quietly snacks and waits.",
];

const duoAlliance = [
  "{A} and {B} agree to watch each other's backs... for now.",
  "{A} and {B} form a truce sealed by a fist bump.",
  "{A} shares a plan with {B}; it might actually work.",
  "{A} teams up with {B} after a suspicious nod.",
  "{A} and {B} create a secret signal and giggle.",
  "{A} and {B} trade snacks and form an alliance.",
  "{A} and {B} vow to avoid chaos together.",
  "{A} and {B} agree to split any loot evenly.",
  "{A} and {B} decide to go duo mode.",
  "{A} and {B} share a map and a promise.",
];

const duoSteal = [
  "{A} swipes supplies from {B} while whistling innocently.",
  "{A} borrows {B}'s gear without asking. Bold.",
  "{A} lifts a pouch from {B} and vanishes.",
  "{A} pickpockets {B} and pretends to be shocked.",
  "{A} nabs a snack from {B}'s stash.",
  "{A} trades {B} a pebble for a real item. {B} is not amused.",
];

const duoInjure = [
  "{A} and {B} argue loudly and both get scratched in the mess.",
  "{A} bumps into {B} during a scramble; both take a hit.",
  "{A} shoves {B} aside; chaos follows.",
  "{A} and {B} collide in a narrow passage.",
  "{A} and {B} get tangled in the same net.",
  "{A} spooks {B}, and the panic hurts someone.",
  "{A} tries to sprint past {B} and wipes out.",
  "{A} and {B} slam into a door at the same time.",
];

const duoKill = [
  "{A} wins a tense standoff against {B}.",
  "{A} outsmarts {B} in a quick duel.",
  "{A} sets a trap that {B} walks into.",
  "{A} surprises {B} from the shadows and it's over fast.",
  "{A} pushes {B} into a pit they never saw.",
  "{A} lands the final strike on {B}.",
  "{A} flips the tables and takes out {B}.",
  "{A} ambushes {B} with a wild plan that works.",
];

const duoBetrayal = [
  "{A} betrays {B} when the opportunity appears.",
  "{A} decides {B} is too risky to keep around.",
  "{A} breaks the alliance with {B} in dramatic fashion.",
  "{A} turns on {B} after a tense stare.",
  "{A} leaves {B} behind when the alarms go off.",
  "{A} whispers sorry and strikes at {B}.",
];

const trioAlliance = [
  "{A}, {B}, and {C} agree to share scouting duties.",
  "{A}, {B}, and {C} form a pact over a pile of snacks.",
  "{A}, {B}, and {C} vow to protect each other... mostly.",
  "{A}, {B}, and {C} link up and look unstoppable.",
  "{A}, {B}, and {C} agree on a rotating lookout schedule.",
  "{A}, {B}, and {C} form the most chaotic trio.",
];

const trioChaos = [
  "{A}, {B}, and {C} start a loud argument that attracts trouble.",
  "{A}, {B}, and {C} chase the same supply crate and trip over each other.",
  "{A}, {B}, and {C} get lost arguing over directions.",
  "{A}, {B}, and {C} accidentally trigger a noise maker.",
  "{A}, {B}, and {C} spend the phase debating snack rules.",
  "{A}, {B}, and {C} sprint away from an imagined threat.",
];

const quadShowdown = [
  "{A}, {B}, {C}, and {D} face off and immediately regret it.",
  "{A}, {B}, {C}, and {D} argue about territory and scatter.",
  "{A}, {B}, {C}, and {D} collide in a chaotic pileup.",
  "{A}, {B}, {C}, and {D} make a temporary truce just to breathe.",
  "{A}, {B}, {C}, and {D} hear a roar and sprint in different directions.",
  "{A}, {B}, {C}, and {D} throw shade and then bail.",
];



// --- Additional event pools (replayability pack)
const soloSpicy = [
  "{A} finds a broken radio and gets static that sounds suspiciously like their own name.",
  "{A} steals a moment to hype themselves up in the reflection of a puddle.",
  "{A} follows glitter in the dirt and immediately regrets trusting sparkle.",
  "{A} discovers a tiny flag planted in the ground. It simply says: 'RUN'.",
  "{A} finds footprints that match their exact shoe size. Creepy.",
  "{A} builds a decoy campfire to lure trouble somewhere else.",
  "{A} pockets a shiny token and swears it's 'for later'.",
  "{A} practices dramatic victory poses for morale.",
  "{A} hears distant cheering and decides not to investigate.",
  "{A} finds a note: 'Trust no one.' They nod like they already knew.",
];

const soloZoneLoot = [
  "{A} raids a half-buried crate and pulls out {ITEM}.",
  "{A} digs up a stash and claims {ITEM} like it was destiny.",
  "{A} spots {ITEM} wedged under rubble and yoinks it free.",
  "{A} trades a sock and a promise to the universe for {ITEM}.",
  "{A} finds {ITEM} and whispers, 'this changes everything'.",
];

const soloNearMiss = [
  "{A} trips a trap but escapes with only pride damage.",
  "{A} narrowly avoids a falling branch. The arena is rude today.",
  "{A} hears a click underfoot and freezes. Nothing happens. Yet.",
  "{A} ducks as something whistles past their head. Nope nope nope.",
];

const duoBanter = [
  "{A} and {B} share a snack and an awkward silence.",
  "{A} and {B} argue about directions until they realize they're both lost.",
  "{A} and {B} make a temporary pact: 'no funny business'.",
  "{A} and {B} swap tips and pretend it wasn't wholesome.",
  "{A} and {B} spot each other at the same time and both pretend they didn't.",
];

const duoAmbush = [
  "{A} ambushes {B} and leaves them battered.",
  "{A} charges {B} in a messy clash — both get hurt.",
  "{A} flanks {B} and lands a brutal hit.",
  "{A} and {B} fight over a supply crate. It gets ugly.",
];

const duoTheft = [
  "{A} distracts {B} and steals their {ITEM}.",
  "{A} yoinks {ITEM} from {B} and vanishes into the chaos.",
  "{A} picks {B}'s pocket and scores {ITEM}.",
];

const trioDisaster = [
  "{A}, {B}, and {C} trigger a chain reaction and scramble for cover.",
  "{A}, {B}, and {C} run straight into trouble and barely escape.",
  "{A}, {B}, and {C} start a plan and immediately abandon it.",
  "{A}, {B}, and {C} get spooked by a noise and sprint in three different directions.",
];

const rareMythic = [
  "A horn blares. The ground trembles. {A} realizes the arena just got meaner.",
  "A spotlight sweeps the arena — {A} freezes as if the sky is watching.",
  "A strange calm settles over everything. {A} feels like something big is coming.",
];

const coupleSpecial = [
  "{A} dives in to protect {B} and takes the hit.",
  "{A} and {B} share supplies and promise to regroup.",
  "{A} shields {B} from danger with surprising heroics.",
  "{A} and {B} trade a lucky charm before splitting up.",
  "{A} distracts the danger so {B} can escape.",
  "{A} and {B} plan a safe route together.",
];

// Extra replayability: more varied events (some mention zones/landmarks — the server prefers same-zone groups).
const soloWeird = [
  "{A} hears their name whispered from the distance... but it's just the wind.",
  "{A} finds a tiny note pinned to a tree: 'RUN.' They don't.",
  "{A} discovers a cache of glitter bombs and immediately regrets touching it.",
  "{A} builds a decoy campfire and watches it fool absolutely no one.",
  "{A} trips a harmless trap and becomes paranoid anyway.",
  "{A} stares into the fog until the fog stares back.",
];

function makeTemplates(list, build) {
  return list.map((entry, idx) => build(entry, idx));
}

const SURVIVAL_EVENT_TEMPLATES = [
  ...makeTemplates(soloLoot, (entry, idx) => ({
    id: `solo_loot_${idx + 1}`,
    participants: 1,
    weight: 3,
    type: "loot",
    lootTag: entry.tag,
    text: entry.text,
    outcome: { type: "loot", target: "A", tag: entry.tag },
  })),
  ...makeTemplates(soloHeal, (text, idx) => ({
    id: `solo_heal_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "heal",
    text,
    outcome: { type: "heal", target: "A", amount: [12, 28] },
  })),
  ...makeTemplates(soloInjure, (text, idx) => ({
    id: `solo_injure_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "injure",
    text,
    outcome: { type: "injure", target: "A", amount: [12, 30] },
  })),
  ...makeTemplates(soloNeutral, (text, idx) => ({
    id: `solo_neutral_${idx + 1}`,
    participants: 1,
    weight: 3,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(soloWeird, (text, idx) => ({
    id: `solo_weird_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(duoAlliance, (text, idx) => ({
    id: `duo_alliance_${idx + 1}`,
    participants: 2,
    weight: 3,
    type: "alliance",
    text,
    requiresNoAlliance: true,
    outcome: { type: "alliance", members: ["A", "B"] },
  })),
  ...makeTemplates(duoSteal, (text, idx) => ({
    id: `duo_steal_${idx + 1}`,
    participants: 2,
    weight: 2,
    type: "steal",
    text,
    outcome: { type: "steal", thief: "A", victim: "B" },
  })),
  ...makeTemplates(duoInjure, (text, idx) => ({
    id: `duo_injure_${idx + 1}`,
    participants: 2,
    weight: 2,
    type: "injure",
    text,
    outcome: { type: "injure", target: "A", amount: [10, 24], splashTarget: "B", splashAmount: [6, 18] },
  })),
  ...makeTemplates(duoKill, (text, idx) => ({
    id: `duo_kill_${idx + 1}`,
    participants: 2,
    weight: 1,
    type: "kill",
    text: text + " ☠️",
    outcome: { type: "kill", killer: "A", victim: "B" },
  })),
  ...makeTemplates(duoBetrayal, (text, idx) => ({
    id: `duo_betray_${idx + 1}`,
    participants: 2,
    weight: 1,
    type: "betray",
    text: text + " ☠️",
    requiresAlliance: true,
    outcome: { type: "betray", killer: "A", victim: "B" },
  })),
  ...makeTemplates(trioAlliance, (text, idx) => ({
    id: `trio_alliance_${idx + 1}`,
    participants: 3,
    weight: 2,
    type: "alliance",
    text,
    requiresNoAlliance: true,
    outcome: { type: "alliance", members: ["A", "B", "C"] },
  })),
  ...makeTemplates(trioChaos, (text, idx) => ({
    id: `trio_chaos_${idx + 1}`,
    participants: 3,
    weight: 2,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(quadShowdown, (text, idx) => ({
    id: `quad_showdown_${idx + 1}`,
    participants: 4,
    weight: 1,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(soloSpicy, (text, idx) => ({
    id: `solo_spicy_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(soloZoneLoot, (text, idx) => ({
    id: `solo_zone_loot_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "loot",
    text,
    lootTag: (["weapon","food","medkit","trap","map"][idx % 5] || "food"),
    outcome: { type: "loot", target: "A" },
  })),
  ...makeTemplates(soloNearMiss, (text, idx) => ({
    id: `solo_near_${idx + 1}`,
    participants: 1,
    weight: 2,
    type: "injure",
    text,
    outcome: { type: "injure", target: "A", amount: [4, 12] },
  })),
  ...makeTemplates(duoBanter, (text, idx) => ({
    id: `duo_banter_${idx + 1}`,
    participants: 2,
    weight: 2,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(duoAmbush, (text, idx) => ({
    id: `duo_ambush_${idx + 1}`,
    participants: 2,
    weight: 1,
    type: "injure",
    text,
    outcome: { type: "injure", target: "B", amount: [10, 22], splashTarget: "A", splashAmount: [4, 10] },
  })),
  ...makeTemplates(duoTheft, (text, idx) => ({
    id: `duo_theft_${idx + 1}`,
    participants: 2,
    weight: 1,
    type: "steal",
    text,
    lootTag: "map",
    outcome: { type: "steal", thief: "A", victim: "B" },
  })),
  ...makeTemplates(trioDisaster, (text, idx) => ({
    id: `trio_disaster_${idx + 1}`,
    participants: 3,
    weight: 2,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(rareMythic, (text, idx) => ({
    id: `rare_mythic_${idx + 1}`,
    participants: 1,
    weight: 1,
    type: "neutral",
    text,
    outcome: { type: "nothing" },
  })),
  ...makeTemplates(coupleSpecial, (text, idx) => ({
    id: `couple_${idx + 1}`,
    participants: 2,
    weight: 2,
    type: "couple",
    text,
    requiresCouple: true,
    outcome: { type: "protect", protector: "A", protected: "B" },
  })),
];

module.exports = {
  SURVIVAL_EVENT_TEMPLATES,
  SURVIVAL_ITEM_POOL,
};
