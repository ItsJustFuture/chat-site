"use strict";

/**
 * Email Service
 * Handles sending verification codes and password reset emails
 * Supports multiple providers: nodemailer (SMTP), SendGrid, AWS SES
 */

const crypto = require("crypto");

// Email provider configuration
const EMAIL_PROVIDER = process.env.EMAIL_PROVIDER || "console"; // console, smtp, sendgrid, ses
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@banter-brats.com";
const FROM_NAME = process.env.FROM_NAME || "Banter & Brats";

// For development: just log to console
// For production: configure SMTP or use SendGrid/SES

let emailTransport = null;

/**
 * Initialize email provider
 */
async function initializeEmailService() {
  if (EMAIL_PROVIDER === "console") {
    console.log("[email] Using console mode (emails logged to console)");
    return;
  }
  
  if (EMAIL_PROVIDER === "smtp") {
    // Nodemailer SMTP
    const nodemailer = require("nodemailer");
    emailTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: parseInt(process.env.SMTP_PORT || "587"),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
    
    // Verify connection
    await emailTransport.verify();
    console.log("[email] SMTP transport ready");
  }
  
  // Add SendGrid or SES support here if needed
}

/**
 * Generate a 6-digit verification code
 */
function generateVerificationCode() {
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * Generate a secure password reset token
 */
function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Send verification email
 */
async function sendVerificationEmail(email, code, username) {
  const subject = "Verify your email - Banter & Brats";
  const text = `
Hi ${username}!

Welcome to Banter & Brats! Please verify your email address.

Your verification code is: ${code}

This code will expire in 15 minutes.

If you didn't request this, please ignore this email.

Thanks,
Banter & Brats Team
  `.trim();
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #5865f2; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
    .code { font-size: 32px; font-weight: bold; color: #5865f2; letter-spacing: 4px; text-align: center; margin: 20px 0; padding: 15px; background: white; border-radius: 8px; }
    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Verify Your Email</h1>
    </div>
    <div class="content">
      <p>Hi <strong>${username}</strong>!</p>
      <p>Welcome to Banter & Brats! Please verify your email address by entering this code:</p>
      <div class="code">${code}</div>
      <p>This code will expire in 15 minutes.</p>
      <p>If you didn't request this, please ignore this email.</p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} Banter & Brats. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
  `.trim();
  
  return await sendEmail(email, subject, text, html);
}

/**
 * Send password reset email
 */
async function sendPasswordResetEmail(email, token, username) {
  const resetUrl = `${process.env.BASE_URL || "http://localhost:3000"}/reset-password?token=${token}`;
  
  const subject = "Reset your password - Banter & Brats";
  const text = `
Hi ${username}!

You requested a password reset for your Banter & Brats account.

Click this link to reset your password:
${resetUrl}

This link will expire in 1 hour.

If you didn't request this, please ignore this email. Your password will remain unchanged.

Thanks,
Banter & Brats Team
  `.trim();
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #5865f2; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
    .button { display: inline-block; padding: 12px 24px; background: #5865f2; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Reset Your Password</h1>
    </div>
    <div class="content">
      <p>Hi <strong>${username}</strong>!</p>
      <p>You requested a password reset for your Banter & Brats account.</p>
      <p style="text-align: center;">
        <a href="${resetUrl}" class="button">Reset Password</a>
      </p>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all; background: white; padding: 10px; border-radius: 4px;">${resetUrl}</p>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email. Your password will remain unchanged.</p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} Banter & Brats. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
  `.trim();
  
  return await sendEmail(email, subject, text, html);
}

/**
 * Core email sending function
 */
async function sendEmail(to, subject, text, html) {
  if (EMAIL_PROVIDER === "console") {
    // Development mode: just log to console
    console.log("\n" + "=".repeat(60));
    console.log("[email] Email would be sent:");
    console.log("To:", to);
    console.log("Subject:", subject);
    console.log("Text:", text);
    console.log("=".repeat(60) + "\n");
    return true;
  }
  
  if (EMAIL_PROVIDER === "smtp" && emailTransport) {
    try {
      await emailTransport.sendMail({
        from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
        to,
        subject,
        text,
        html,
      });
      console.log(`[email] Sent to ${to}: ${subject}`);
      return true;
    } catch (err) {
      console.error(`[email] Failed to send to ${to}:`, err.message);
      return false;
    }
  }
  
  console.warn("[email] No email provider configured");
  return false;
}

/**
 * Validate email format
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  
  // Basic email regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

module.exports = {
  initializeEmailService,
  generateVerificationCode,
  generateResetToken,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendEmail,
  isValidEmail,
};
