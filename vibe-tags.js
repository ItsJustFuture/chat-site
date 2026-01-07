"use strict";

const VIBE_TAG_LIMIT = 3;

const VIBE_TAGS = Object.freeze([
  { id: "chill", label: "Chill", emoji: "😌" },
  { id: "chaotic", label: "Chaotic", emoji: "🌪️" },
  { id: "night-owl", label: "Night Owl", emoji: "🦉" },
  { id: "cozy", label: "Cozy", emoji: "🛋️" },
  { id: "loud", label: "Loud", emoji: "📢" },
  { id: "quiet", label: "Quiet", emoji: "🤫" },
  { id: "curious", label: "Curious", emoji: "👀" },
  { id: "unhinged", label: "Unhinged", emoji: "🧨" },
  { id: "friendly", label: "Friendly", emoji: "😊" },
  { id: "competitive", label: "Competitive", emoji: "🏆" },
  { id: "high", label: "High", emoji: "🌿" },
  { id: "horny", label: "Horny", emoji: "🔥" },
  { id: "flirty", label: "Flirty", emoji: "💋" },
  { id: "teasing", label: "Teasing", emoji: "🤭" },
  { id: "bratty", label: "Bratty", emoji: "😈" },
  { id: "submissive", label: "Submissive", emoji: "🧎" },
  { id: "dominant", label: "Dominant", emoji: "🐺" },
  { id: "switch", label: "Switch", emoji: "🔀" },
  { id: "clingy", label: "Clingy", emoji: "🫶" },
  { id: "thirsty", label: "Thirsty", emoji: "🥵" },
  { id: "playful", label: "Playful", emoji: "🎲" },
  { id: "seductive", label: "Seductive", emoji: "🕯️" },
  { id: "provocative", label: "Provocative", emoji: "💄" },
  { id: "spicy", label: "Spicy", emoji: "🌶️" },
  { id: "filthy-minded", label: "Filthy Minded", emoji: "🧠" },
  { id: "touch-starved", label: "Touch Starved", emoji: "✋" },
  { id: "down-bad", label: "Down Bad", emoji: "🫠" },
  { id: "hopeless-romantic", label: "Hopeless Romantic", emoji: "💞" },
  { id: "confident", label: "Confident", emoji: "💪" },
  { id: "shy", label: "Shy", emoji: "🙈" },
  { id: "mysterious", label: "Mysterious", emoji: "🌒" },
  { id: "bold", label: "Bold", emoji: "⚡" },
  { id: "softcore", label: "Softcore", emoji: "🫦" },
  { id: "after-dark", label: "After Dark", emoji: "🌙" }
]);

module.exports = {
  VIBE_TAG_LIMIT,
  VIBE_TAGS
};
