"use strict";

/**
 * Email Verification Helper
 * Handles email verification and password reset logic
 */

const {
  generateVerificationCode,
  generateResetToken,
  sendVerificationEmail,
  sendPasswordResetEmail,
  isValidEmail,
} = require("./email-service");

// Will be initialized with database references
let dbRunAsync = null;
let dbAllAsync = null;
let dbGetAsync = null;
let pgPool = null;

const VERIFICATION_CODE_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes
const PASSWORD_RESET_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

/**
 * Initialize with database references
 */
function initEmailVerification(sqliteRun, sqliteAll, sqliteGet, postgres) {
  dbRunAsync = sqliteRun;
  dbAllAsync = sqliteAll;
  dbGetAsync = sqliteGet;
  pgPool = postgres;
}

/**
 * Create email verification tables
 */
async function createEmailTables() {
  if (!dbRunAsync) return;
  
  // Add email columns to users table
  try {
    await dbRunAsync(`ALTER TABLE users ADD COLUMN email TEXT`);
  } catch (err) {
    // Column may already exist
  }
  
  try {
    await dbRunAsync(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`);
  } catch (err) {
    // Column may already exist
  }
  
  // Create email verifications table
  await dbRunAsync(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      verified_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  
  await dbRunAsync(`CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id)`);
  await dbRunAsync(`CREATE INDEX IF NOT EXISTS idx_email_verifications_code ON email_verifications(code)`);
  await dbRunAsync(`CREATE INDEX IF NOT EXISTS idx_email_verifications_expires ON email_verifications(expires_at)`);
  
  // Create password resets table
  await dbRunAsync(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  
  await dbRunAsync(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`);
  await dbRunAsync(`CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at)`);
  
  // Postgres
  if (pgPool) {
    try {
      await pgPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
      await pgPool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified INTEGER NOT NULL DEFAULT 0`);
      
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS email_verifications (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          email TEXT NOT NULL,
          code TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          expires_at BIGINT NOT NULL,
          verified_at BIGINT
        )
      `);
      
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_email_verifications_code ON email_verifications(code)`);
      
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS password_resets (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          email TEXT NOT NULL,
          token TEXT NOT NULL UNIQUE,
          created_at BIGINT NOT NULL,
          expires_at BIGINT NOT NULL,
          used_at BIGINT
        )
      `);
      
      await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`);
    } catch (err) {
      // Tables may already exist
    }
  }
}

/**
 * Send verification code to user
 */
async function sendVerificationCode(userId, email, username) {
  if (!isValidEmail(email)) {
    return { success: false, error: "Invalid email address" };
  }
  
  const code = generateVerificationCode();
  const now = Date.now();
  const expiresAt = now + VERIFICATION_CODE_EXPIRY_MS;
  
  // Store verification code
  try {
    await dbRunAsync(
      `INSERT INTO email_verifications (user_id, email, code, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, email, code, now, expiresAt]
    );
    
    if (pgPool) {
      await pgPool.query(
        `INSERT INTO email_verifications (user_id, email, code, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, email, code, now, expiresAt]
      );
    }
  } catch (err) {
    console.error("[email-verification] Failed to store code:", err);
    return { success: false, error: "Failed to generate verification code" };
  }
  
  // Send email
  const sent = await sendVerificationEmail(email, code, username);
  
  if (!sent) {
    return { success: false, error: "Failed to send email" };
  }
  
  return { success: true, expiresAt };
}

/**
 * Verify email with code
 */
async function verifyEmailCode(userId, code) {
  const now = Date.now();
  
  try {
    // Find valid verification
    const rows = await dbAllAsync(
      `SELECT * FROM email_verifications 
       WHERE user_id = ? AND code = ? AND verified_at IS NULL AND expires_at > ?
       ORDER BY created_at DESC LIMIT 1`,
      [userId, code, now]
    );
    
    if (!rows || rows.length === 0) {
      return { success: false, error: "Invalid or expired verification code" };
    }
    
    const verification = rows[0];
    
    // Mark as verified
    await dbRunAsync(
      `UPDATE email_verifications SET verified_at = ? WHERE id = ?`,
      [now, verification.id]
    );
    
    // Update user email
    await dbRunAsync(
      `UPDATE users SET email = ?, email_verified = 1 WHERE id = ?`,
      [verification.email, userId]
    );
    
    if (pgPool) {
      await pgPool.query(
        `UPDATE email_verifications SET verified_at = $1 WHERE user_id = $2 AND code = $3`,
        [now, userId, code]
      );
      
      await pgPool.query(
        `UPDATE users SET email = $1, email_verified = 1 WHERE id = $2`,
        [verification.email, userId]
      );
    }
    
    return { success: true, email: verification.email };
  } catch (err) {
    console.error("[email-verification] Verify error:", err);
    return { success: false, error: "Failed to verify code" };
  }
}

/**
 * Request password reset
 */
async function requestPasswordReset(email) {
  if (!isValidEmail(email)) {
    return { success: false, error: "Invalid email address" };
  }
  
  try {
    // Find user by email
    const rows = await dbAllAsync(
      `SELECT id, username, email FROM users WHERE lower(email) = lower(?) AND email_verified = 1 LIMIT 1`,
      [email]
    );
    
    if (!rows || rows.length === 0) {
      // Don't reveal if email exists - security best practice
      return { success: true, message: "If that email is registered, you'll receive a reset link" };
    }
    
    const user = rows[0];
    const token = generateResetToken();
    const now = Date.now();
    const expiresAt = now + PASSWORD_RESET_EXPIRY_MS;
    
    // Store reset token
    await dbRunAsync(
      `INSERT INTO password_resets (user_id, email, token, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [user.id, email, token, now, expiresAt]
    );
    
    if (pgPool) {
      await pgPool.query(
        `INSERT INTO password_resets (user_id, email, token, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [user.id, email, token, now, expiresAt]
      );
    }
    
    // Send email
    await sendPasswordResetEmail(email, token, user.username);
    
    return { success: true, message: "If that email is registered, you'll receive a reset link" };
  } catch (err) {
    console.error("[email-verification] Password reset request error:", err);
    return { success: false, error: "Failed to process request" };
  }
}

/**
 * Verify password reset token
 */
async function verifyResetToken(token) {
  const now = Date.now();
  
  try {
    const rows = await dbAllAsync(
      `SELECT * FROM password_resets 
       WHERE token = ? AND used_at IS NULL AND expires_at > ?
       LIMIT 1`,
      [token, now]
    );
    
    if (!rows || rows.length === 0) {
      return { success: false, error: "Invalid or expired reset token" };
    }
    
    const reset = rows[0];
    return { success: true, userId: reset.user_id, email: reset.email };
  } catch (err) {
    console.error("[email-verification] Token verification error:", err);
    return { success: false, error: "Failed to verify token" };
  }
}

/**
 * Reset password with token
 */
async function resetPasswordWithToken(token, newPasswordHash) {
  const now = Date.now();
  
  try {
    const rows = await dbAllAsync(
      `SELECT * FROM password_resets 
       WHERE token = ? AND used_at IS NULL AND expires_at > ?
       LIMIT 1`,
      [token, now]
    );
    
    if (!rows || rows.length === 0) {
      return { success: false, error: "Invalid or expired reset token" };
    }
    
    const reset = rows[0];
    
    // Update password
    await dbRunAsync(
      `UPDATE users SET password_hash = ? WHERE id = ?`,
      [newPasswordHash, reset.user_id]
    );
    
    // Mark token as used
    await dbRunAsync(
      `UPDATE password_resets SET used_at = ? WHERE id = ?`,
      [now, reset.id]
    );
    
    if (pgPool) {
      await pgPool.query(
        `UPDATE users SET password_hash = $1 WHERE id = $2`,
        [newPasswordHash, reset.user_id]
      );
      
      await pgPool.query(
        `UPDATE password_resets SET used_at = $1 WHERE token = $2`,
        [now, token]
      );
    }
    
    return { success: true };
  } catch (err) {
    console.error("[email-verification] Password reset error:", err);
    return { success: false, error: "Failed to reset password" };
  }
}

/**
 * Check if user has verified email
 */
async function isEmailVerified(userId) {
  try {
    const row = await dbGetAsync(
      `SELECT email_verified FROM users WHERE id = ?`,
      [userId]
    );
    
    return row && row.email_verified === 1;
  } catch (err) {
    return false;
  }
}

/**
 * Get user email
 */
async function getUserEmail(userId) {
  try {
    const row = await dbGetAsync(
      `SELECT email, email_verified FROM users WHERE id = ?`,
      [userId]
    );
    
    return row ? { email: row.email, verified: row.email_verified === 1 } : null;
  } catch (err) {
    return null;
  }
}

/**
 * Cleanup expired codes and tokens
 */
async function cleanupExpired() {
  const now = Date.now();
  
  try {
    await dbRunAsync(`DELETE FROM email_verifications WHERE expires_at < ? AND verified_at IS NULL`, [now]);
    await dbRunAsync(`DELETE FROM password_resets WHERE expires_at < ? AND used_at IS NULL`, [now]);
    
    if (pgPool) {
      await pgPool.query(`DELETE FROM email_verifications WHERE expires_at < $1 AND verified_at IS NULL`, [now]);
      await pgPool.query(`DELETE FROM password_resets WHERE expires_at < $1 AND used_at IS NULL`, [now]);
    }
  } catch (err) {
    // Silent fail
  }
}

// Cleanup every 10 minutes
setInterval(cleanupExpired, 10 * 60 * 1000).unref?.();

module.exports = {
  initEmailVerification,
  createEmailTables,
  sendVerificationCode,
  verifyEmailCode,
  requestPasswordReset,
  verifyResetToken,
  resetPasswordWithToken,
  isEmailVerified,
  getUserEmail,
  cleanupExpired,
};
