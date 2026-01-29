"use strict";

/**
 * Emoji Utilities
 * 
 * Provides emoji shortcode replacement for common emoji codes
 * Example: :smile: -> 😄, :heart: -> ❤️
 */

// Common emoji shortcodes
const EMOJI_MAP = {
  // Smileys & People
  ":smile:": "😄",
  ":smiley:": "😃",
  ":grin:": "😁",
  ":laughing:": "😆",
  ":joy:": "😂",
  ":rofl:": "🤣",
  ":wink:": "😉",
  ":blush:": "😊",
  ":relaxed:": "☺️",
  ":innocent:": "😇",
  ":heart_eyes:": "😍",
  ":kissing_heart:": "😘",
  ":kissing:": "😗",
  ":yum:": "😋",
  ":stuck_out_tongue:": "😛",
  ":stuck_out_tongue_winking_eye:": "😜",
  ":stuck_out_tongue_closed_eyes:": "😝",
  ":neutral_face:": "😐",
  ":expressionless:": "😑",
  ":no_mouth:": "😶",
  ":smirk:": "😏",
  ":unamused:": "😒",
  ":grimacing:": "😬",
  ":lying_face:": "🤥",
  ":relieved:": "😌",
  ":pensive:": "😔",
  ":sleepy:": "😪",
  ":sleeping:": "😴",
  ":tired_face:": "😫",
  ":cry:": "😢",
  ":sob:": "😭",
  ":triumph:": "😤",
  ":angry:": "😠",
  ":rage:": "😡",
  ":confounded:": "😖",
  ":confused:": "😕",
  ":worried:": "😟",
  ":frowning:": "☹️",
  ":anguished:": "😧",
  ":fearful:": "😨",
  ":weary:": "😩",
  ":dizzy_face:": "😵",
  ":astonished:": "😲",
  ":flushed:": "😳",
  ":scream:": "😱",
  ":cold_sweat:": "😰",
  ":disappointed:": "😞",
  ":sweat:": "😓",
  ":sunglasses:": "😎",
  ":nerd_face:": "🤓",
  ":thinking:": "🤔",
  ":face_with_monocle:": "🧐",
  ":zipper_mouth_face:": "🤐",
  ":face_with_raised_eyebrow:": "🤨",
  ":neutral_face:": "😐",
  ":shushing_face:": "🤫",
  ":yawn:": "🥱",
  ":partying_face:": "🥳",
  ":smiling_face_with_tear:": "🥲",
  ":pleading_face:": "🥺",
  
  // Hearts
  ":heart:": "❤️",
  ":orange_heart:": "🧡",
  ":yellow_heart:": "💛",
  ":green_heart:": "💚",
  ":blue_heart:": "💙",
  ":purple_heart:": "💜",
  ":brown_heart:": "🤎",
  ":black_heart:": "🖤",
  ":white_heart:": "🤍",
  ":broken_heart:": "💔",
  ":sparkling_heart:": "💖",
  ":two_hearts:": "💕",
  ":heartbeat:": "💓",
  ":revolving_hearts:": "💞",
  ":cupid:": "💘",
  ":love_letter:": "💌",
  
  // Hands
  ":thumbsup:": "👍",
  ":thumbsdown:": "👎",
  ":ok_hand:": "👌",
  ":punch:": "👊",
  ":fist:": "✊",
  ":v:": "✌️",
  ":wave:": "👋",
  ":raised_hand:": "✋",
  ":clap:": "👏",
  ":pray:": "🙏",
  ":handshake:": "🤝",
  ":muscle:": "💪",
  
  // Common symbols
  ":star:": "⭐",
  ":sparkles:": "✨",
  ":fire:": "🔥",
  ":100:": "💯",
  ":trophy:": "🏆",
  ":medal:": "🏅",
  ":crown:": "👑",
  ":checkmark:": "✔️",
  ":check:": "✅",
  ":x:": "❌",
  ":warning:": "⚠️",
  ":exclamation:": "❗",
  ":question:": "❓",
  ":zzz:": "💤",
  ":boom:": "💥",
  ":dizzy:": "💫",
  ":sweat_drops:": "💦",
  ":rocket:": "🚀",
  ":bulb:": "💡",
  
  // Nature
  ":sun:": "☀️",
  ":moon:": "🌙",
  ":star2:": "🌟",
  ":cloud:": "☁️",
  ":rain:": "🌧️",
  ":snowflake:": "❄️",
  ":rainbow:": "🌈",
  ":ocean:": "🌊",
  ":tree:": "🌲",
  ":leaves:": "🍃",
  ":rose:": "🌹",
  ":sunflower:": "🌻",
  
  // Food
  ":pizza:": "🍕",
  ":hamburger:": "🍔",
  ":fries:": "🍟",
  ":hotdog:": "🌭",
  ":taco:": "🌮",
  ":burrito:": "🌯",
  ":popcorn:": "🍿",
  ":cookie:": "🍪",
  ":cake:": "🍰",
  ":birthday:": "🎂",
  ":coffee:": "☕",
  ":beer:": "🍺",
  ":wine_glass:": "🍷",
  ":cocktail:": "🍹",
  
  // Animals
  ":dog:": "🐶",
  ":cat:": "🐱",
  ":mouse:": "🐭",
  ":rabbit:": "🐰",
  ":fox:": "🦊",
  ":bear:": "🐻",
  ":panda:": "🐼",
  ":koala:": "🐨",
  ":tiger:": "🐯",
  ":lion:": "🦁",
  ":cow:": "🐮",
  ":pig:": "🐷",
  ":frog:": "🐸",
  ":monkey:": "🐵",
  ":chicken:": "🐔",
  ":penguin:": "🐧",
  ":bird:": "🐦",
  ":fish:": "🐟",
  ":dolphin:": "🐬",
  ":whale:": "🐋",
  ":unicorn:": "🦄",
  
  // Activities
  ":soccer:": "⚽",
  ":basketball:": "🏀",
  ":football:": "🏈",
  ":baseball:": "⚾",
  ":tennis:": "🎾",
  ":volleyball:": "🏐",
  ":8ball:": "🎱",
  ":video_game:": "🎮",
  ":dart:": "🎯",
  ":dice:": "🎲",
  ":music:": "🎵",
  ":guitar:": "🎸",
  ":microphone:": "🎤",
  ":headphones:": "🎧",
  ":art:": "🎨",
  ":camera:": "📷",
  ":movie_camera:": "🎥",
};

/**
 * Replace emoji shortcodes with actual emoji
 * @param {string} text - Text containing shortcodes
 * @returns {string} - Text with emoji
 */
function replaceEmojiShortcodes(text) {
  if (!text || typeof text !== "string") {
    return text;
  }

  let result = text;
  
  // Replace all known shortcodes
  for (const [shortcode, emoji] of Object.entries(EMOJI_MAP)) {
    // Use a simple replace for now - could be optimized with regex
    result = result.split(shortcode).join(emoji);
  }

  return result;
}

/**
 * Get list of all supported shortcodes
 * @returns {string[]} - Array of shortcode strings
 */
function getSupportedShortcodes() {
  return Object.keys(EMOJI_MAP);
}

/**
 * Get emoji for a specific shortcode
 * @param {string} shortcode - The shortcode (e.g., ":smile:")
 * @returns {string|null} - The emoji or null if not found
 */
function getEmoji(shortcode) {
  return EMOJI_MAP[shortcode] || null;
}

module.exports = {
  replaceEmojiShortcodes,
  getSupportedShortcodes,
  getEmoji,
  EMOJI_MAP,
};
