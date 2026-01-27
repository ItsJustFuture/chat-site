"use strict";

const { z } = require("zod");

// ====================================
// VALIDATION SCHEMAS
// ====================================

const ChatMessageSchema = z.object({
  room: z.string().min(1).max(100).trim(),
  text: z.string().min(1).max(2000),
  replyTo: z.number().int().positive().optional(),
});

const DMMessageSchema = z.object({
  threadId: z.number().int().positive(),
  text: z.string().min(1).max(2000),
  replyTo: z.number().int().positive().optional(),
});

const EditMessageSchema = z.object({
  messageId: z.number().int().positive(),
  newText: z.string().min(1).max(2000),
});

const ReactionSchema = z.object({
  messageId: z.number().int().positive(),
  emoji: z.string().min(1).max(10),
});

const DiceRollSchema = z.object({
  variant: z.enum(["d6", "d20", "2d6", "d100"]).optional(),
});

const StatusChangeSchema = z.object({
  status: z.enum(["online", "away", "dnd"]),
});

const JoinRoomSchema = z.object({
  room: z.string().min(1).max(100).trim(),
  status: z.enum(["online", "away", "dnd"]).optional(),
});

// ====================================
// VALIDATION HELPERS
// ====================================

/**
 * Validates data against a Zod schema
 */
function validate(schema, data) {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  const errorMessages = result.error.errors.map(err => {
    return `${err.path.join('.')}: ${err.message}`;
  }).join(', ');
  
  return { success: false, error: errorMessages };
}

/**
 * Sanitizes text by removing dangerous characters
 */
function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  
  return text
    .replace(/[\u200B-\u200D\uFEFF]/g, '') // Remove zero-width chars
    .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '') // Remove control chars
    .trim()
    .replace(/\n{4,}/g, '\n\n\n'); // Limit consecutive newlines
}

/**
 * Validates username
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }
  
  const cleaned = username.trim();
  
  if (cleaned.length < 2) {
    return { valid: false, error: 'Username must be at least 2 characters' };
  }
  
  if (cleaned.length > 50) {
    return { valid: false, error: 'Username must be 50 characters or less' };
  }
  
  if (!/^[a-zA-Z0-9 _-]+$/.test(cleaned)) {
    return { valid: false, error: 'Username can only contain letters, numbers, spaces, underscores, and hyphens' };
  }
  
  return { valid: true, username: cleaned };
}

/**
 * Validates password
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }
  
  if (password.length < 12) {
    return { valid: false, error: 'Password must be at least 12 characters' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'Password must be 128 characters or less' };
  }
  
  return { valid: true };
}

module.exports = {
  // Schemas
  ChatMessageSchema,
  DMMessageSchema,
  EditMessageSchema,
  ReactionSchema,
  DiceRollSchema,
  StatusChangeSchema,
  JoinRoomSchema,
  
  // Functions
  validate,
  sanitizeText,
  validateUsername,
  validatePassword,
};
