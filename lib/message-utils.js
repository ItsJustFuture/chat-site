"use strict";

/**
 * Message utilities for database operations
 * Thin wrappers around database.js APIs for message-related operations
 */

// Database references (initialized from server.js)
let dbRunAsync = null;
let dbGetAsync = null;
let dbAllAsync = null;

/**
 * Initialize with database references from server.js
 */
function init(runFunc, getFunc, allFunc) {
  dbRunAsync = runFunc;
  dbGetAsync = getFunc;
  dbAllAsync = allFunc;
}

/**
 * Save a new message to the database
 * @param {Object} messageData - Message data object
 * @returns {Promise<Object>} Inserted message with ID
 */
async function dbSaveMessage(messageData) {
  const {
    room,
    user_id,
    username,
    role,
    avatar,
    text,
    tone,
    ts,
    attachment_url,
    attachment_type,
    attachment_mime,
    attachment_size,
    reply_to_id,
    reply_to_user,
    reply_to_text
  } = messageData;

  const result = await dbRunAsync(
    `INSERT INTO messages (
      room, user_id, username, role, avatar, text, tone, ts,
      attachment_url, attachment_type, attachment_mime, attachment_size,
      reply_to_id, reply_to_user, reply_to_text
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      room, user_id, username, role, avatar, text, tone, ts,
      attachment_url, attachment_type, attachment_mime, attachment_size,
      reply_to_id, reply_to_user, reply_to_text
    ]
  );

  return { ...messageData, id: result.lastID };
}

/**
 * Mark a message as delivered
 * @param {number} messageId - Message ID
 * @param {number} timestamp - Delivery timestamp
 */
async function markMessageDelivered(messageId, timestamp = Date.now()) {
  if (!dbRunAsync) return;
  
  await dbRunAsync(
    `UPDATE messages SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL`,
    [timestamp, messageId]
  );
}

/**
 * Mark a message as read
 * @param {number} messageId - Message ID
 * @param {number} timestamp - Read timestamp
 */
async function markMessageRead(messageId, timestamp = Date.now()) {
  if (!dbRunAsync) return;
  
  await dbRunAsync(
    `UPDATE messages SET read_at = ? WHERE id = ? AND read_at IS NULL`,
    [timestamp, messageId]
  );
}

/**
 * Persist a reaction to the database
 * @param {Object} reactionData - Reaction data
 */
async function persistReaction(reactionData) {
  if (!dbRunAsync) return;
  
  const { message_id, user_id, username, emoji, created_at } = reactionData;
  
  try {
    await dbRunAsync(
      `INSERT INTO message_reactions (message_id, user_id, username, emoji, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(message_id, user_id, emoji) DO NOTHING`,
      [message_id, user_id, username, emoji, created_at || Date.now()]
    );
  } catch (err) {
    // Fallback for SQLite without ON CONFLICT support
    await dbRunAsync(
      `INSERT OR IGNORE INTO message_reactions (message_id, user_id, username, emoji, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [message_id, user_id, username, emoji, created_at || Date.now()]
    );
  }
}

/**
 * Remove a reaction from the database
 * @param {number} messageId - Message ID
 * @param {number} userId - User ID
 * @param {string} emoji - Emoji to remove
 */
async function removeReaction(messageId, userId, emoji) {
  if (!dbRunAsync) return;
  
  await dbRunAsync(
    `DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?`,
    [messageId, userId, emoji]
  );
}

/**
 * Get all reactions for a message
 * @param {number} messageId - Message ID
 * @returns {Promise<Array>} Array of reactions
 */
async function getMessageReactions(messageId) {
  if (!dbAllAsync) return [];
  
  return await dbAllAsync(
    `SELECT * FROM message_reactions WHERE message_id = ? ORDER BY created_at ASC`,
    [messageId]
  );
}

/**
 * Persist an edit to the message_edits table
 * @param {Object} editData - Edit data
 */
async function persistEdit(editData) {
  if (!dbRunAsync) return;
  
  const { message_id, user_id, previous_text, new_text, edited_at } = editData;
  
  // Store edit history
  await dbRunAsync(
    `INSERT INTO message_edits (message_id, user_id, previous_text, new_text, edited_at)
     VALUES (?, ?, ?, ?, ?)`,
    [message_id, user_id, previous_text, new_text, edited_at || Date.now()]
  );
  
  // Update the message with new text and edited timestamp
  await dbRunAsync(
    `UPDATE messages SET text = ?, edited_at = ? WHERE id = ?`,
    [new_text, edited_at || Date.now(), message_id]
  );
}

/**
 * Get edit history for a message
 * @param {number} messageId - Message ID
 * @returns {Promise<Array>} Array of edits
 */
async function getMessageEdits(messageId) {
  if (!dbAllAsync) return [];
  
  return await dbAllAsync(
    `SELECT * FROM message_edits WHERE message_id = ? ORDER BY edited_at ASC`,
    [messageId]
  );
}

/**
 * Soft delete a message (sets deleted flag and deleted_at timestamp)
 * @param {number} messageId - Message ID
 * @param {number} timestamp - Deletion timestamp
 */
async function softDeleteMessage(messageId, timestamp = Date.now()) {
  if (!dbRunAsync) return;
  
  await dbRunAsync(
    `UPDATE messages SET deleted = 1, deleted_at = ? WHERE id = ?`,
    [timestamp, messageId]
  );
}

module.exports = {
  init,
  dbSaveMessage,
  markMessageDelivered,
  markMessageRead,
  persistReaction,
  removeReaction,
  getMessageReactions,
  persistEdit,
  getMessageEdits,
  softDeleteMessage
};
