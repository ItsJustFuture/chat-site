# Email Verification & Password Reset - Implementation Guide

## 📧 Overview

This guide shows you how to add email verification and password reset functionality to your chat application.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

This installs `nodemailer` for sending emails.

### 2. Run Database Migration

```bash
sqlite3 data/dev.sqlite < migrations/20260128_email_verification.sql
```

Or for PostgreSQL:
```bash
psql $DATABASE_URL -f migrations/20260128_email_verification.sql
```

### 3. Configure Environment Variables

Add to your `.env` file:

```env
# Email Configuration
EMAIL_PROVIDER=console         # Use 'console' for development, 'smtp' for production
BASE_URL=http://localhost:3000 # Your app URL

# For production (SMTP):
FROM_EMAIL=noreply@yourdomain.com
FROM_NAME=Banter & Brats
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### 4. Add to server.js

Add these imports at the top of `server.js` (after other requires):

```javascript
const { initializeEmailService } = require('./email-service');
const {
  initEmailVerification,
  createEmailTables,
  sendVerificationCode,
  verifyEmailCode,
  requestPasswordReset,
  verifyResetToken,
  resetPasswordWithToken,
  isEmailVerified,
  getUserEmail,
} = require('./email-verification');
```

Add initialization in your startup function (where other tables are created):

```javascript
// Inside your startup/initialization code
async function initializeServer() {
  // ... existing code ...
  
  // Initialize email service
  console.log('[startup] Initializing email service...');
  await initializeEmailService();
  
  // Initialize email verification
  console.log('[startup] Setting up email verification...');
  initEmailVerification(dbRunAsync, dbAllAsync, dbGetAsync, pgPool);
  await createEmailTables();
  
  console.log('[startup] Email verification ready ✓');
}
```

---

## 📝 API Endpoints to Add

### Registration with Email

Add to your registration endpoint:

```javascript
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  // Validate inputs
  const usernameCheck = validateUsername(username);
  if (!usernameCheck.valid) {
    return res.status(400).json({ error: usernameCheck.error });
  }
  
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.error });
  }
  
  const { isValidEmail } = require('./email-service');
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  
  try {
    // Check if email already registered
    const existingEmail = await dbGetAsync(
      'SELECT id FROM users WHERE lower(email) = lower(?)',
      [email]
    );
    
    if (existingEmail) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Check if username exists
    const existingUser = await dbGetAsync(
      'SELECT id FROM users WHERE lower(username) = lower(?)',
      [username]
    );
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    
    // Create user
    const passwordHash = await bcrypt.hash(password, 10);
    const now = Date.now();
    
    const result = await dbRunAsync(
      `INSERT INTO users (username, password_hash, email, email_verified, created_at, last_seen, role)
       VALUES (?, ?, ?, 0, ?, ?, 'user')`,
      [username, passwordHash, email, now, now]
    );
    
    const userId = result.lastID;
    
    // Send verification email
    const verificationResult = await sendVerificationCode(userId, email, username);
    
    if (!verificationResult.success) {
      console.error('[register] Failed to send verification:', verificationResult.error);
    }
    
    // Log user in
    req.session.userId = userId;
    req.session.username = username;
    req.session.role = 'user';
    req.session.emailVerified = false;
    
    res.json({
      success: true,
      message: 'Registration successful! Check your email for a verification code.',
      userId,
      username,
      emailSent: verificationResult.success,
    });
    
  } catch (err) {
    console.error('[register] Error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});
```

### Send Verification Code

```javascript
app.post('/send-verification-code', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const user = await dbGetAsync(
      'SELECT username, email, email_verified FROM users WHERE id = ?',
      [req.session.userId]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.email_verified === 1) {
      return res.status(400).json({ error: 'Email already verified' });
    }
    
    if (!user.email) {
      return res.status(400).json({ error: 'No email on file' });
    }
    
    const result = await sendVerificationCode(
      req.session.userId,
      user.email,
      user.username
    );
    
    if (!result.success) {
      return res.status(500).json({ error: result.error });
    }
    
    res.json({
      success: true,
      message: 'Verification code sent to your email',
      expiresAt: result.expiresAt,
    });
    
  } catch (err) {
    console.error('[send-verification] Error:', err);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});
```

### Verify Email Code

```javascript
app.post('/verify-email', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { code } = req.body;
  
  if (!code || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Invalid code format' });
  }
  
  try {
    const result = await verifyEmailCode(req.session.userId, code);
    
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    
    // Update session
    req.session.emailVerified = true;
    
    res.json({
      success: true,
      message: 'Email verified successfully!',
      email: result.email,
    });
    
  } catch (err) {
    console.error('[verify-email] Error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});
```

### Request Password Reset

```javascript
app.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;
  
  const { isValidEmail } = require('./email-service');
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  
  try {
    const result = await requestPasswordReset(email);
    
    // Always return success to prevent email enumeration
    res.json({
      success: true,
      message: result.message,
    });
    
  } catch (err) {
    console.error('[password-reset-request] Error:', err);
    res.status(500).json({ error: 'Failed to process request' });
  }
});
```

### Reset Password

```javascript
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.error });
  }
  
  try {
    // Verify token is valid
    const tokenCheck = await verifyResetToken(token);
    if (!tokenCheck.success) {
      return res.status(400).json({ error: tokenCheck.error });
    }
    
    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    
    // Reset password
    const result = await resetPasswordWithToken(token, passwordHash);
    
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    
    res.json({
      success: true,
      message: 'Password reset successfully! You can now log in.',
    });
    
  } catch (err) {
    console.error('[reset-password] Error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});
```

### Get Email Status

```javascript
app.get('/email-status', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const emailData = await getUserEmail(req.session.userId);
    
    res.json({
      email: emailData?.email || null,
      verified: emailData?.verified || false,
    });
    
  } catch (err) {
    console.error('[email-status] Error:', err);
    res.status(500).json({ error: 'Failed to get email status' });
  }
});
```

---

## 🎨 Frontend Integration

### Email Verification UI (add to your HTML)

```html
<!-- Email Verification Modal -->
<div id="emailVerificationModal" class="modal" style="display: none;">
  <div class="modal-content">
    <h2>Verify Your Email</h2>
    <p>We've sent a 6-digit code to your email address.</p>
    
    <form id="verifyEmailForm">
      <div class="field">
        <label for="verificationCode">Verification Code</label>
        <input 
          type="text" 
          id="verificationCode" 
          placeholder="000000" 
          maxlength="6" 
          pattern="\d{6}"
          required
        />
      </div>
      
      <div class="actions">
        <button type="submit" class="btn btnPrimary">Verify</button>
        <button type="button" class="btn btnSecondary" id="resendCodeBtn">
          Resend Code
        </button>
      </div>
    </form>
    
    <div id="verificationMessage" class="message"></div>
  </div>
</div>

<!-- Password Reset Modal -->
<div id="passwordResetModal" class="modal" style="display: none;">
  <div class="modal-content">
    <h2>Reset Password</h2>
    <p>Enter your email address to receive a reset link.</p>
    
    <form id="requestResetForm">
      <div class="field">
        <label for="resetEmail">Email Address</label>
        <input 
          type="email" 
          id="resetEmail" 
          placeholder="your@email.com" 
          required
        />
      </div>
      
      <div class="actions">
        <button type="submit" class="btn btnPrimary">Send Reset Link</button>
      </div>
    </form>
    
    <div id="resetMessage" class="message"></div>
  </div>
</div>
```

### JavaScript for Email Verification

```javascript
// In your public/app.js or similar

// Show email verification modal
function showEmailVerificationModal() {
  document.getElementById('emailVerificationModal').style.display = 'block';
}

// Handle verification form submission
document.getElementById('verifyEmailForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const code = document.getElementById('verificationCode').value;
  const messageEl = document.getElementById('verificationMessage');
  
  try {
    const response = await fetch('/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    
    const data = await response.json();
    
    if (data.success) {
      messageEl.textContent = 'Email verified successfully!';
      messageEl.className = 'message success';
      
      // Close modal after 2 seconds
      setTimeout(() => {
        document.getElementById('emailVerificationModal').style.display = 'none';
      }, 2000);
    } else {
      messageEl.textContent = data.error || 'Verification failed';
      messageEl.className = 'message error';
    }
  } catch (err) {
    messageEl.textContent = 'Network error. Please try again.';
    messageEl.className = 'message error';
  }
});

// Resend verification code
document.getElementById('resendCodeBtn')?.addEventListener('click', async () => {
  const messageEl = document.getElementById('verificationMessage');
  
  try {
    const response = await fetch('/send-verification-code', {
      method: 'POST',
    });
    
    const data = await response.json();
    
    if (data.success) {
      messageEl.textContent = 'Code resent! Check your email.';
      messageEl.className = 'message success';
    } else {
      messageEl.textContent = data.error || 'Failed to resend code';
      messageEl.className = 'message error';
    }
  } catch (err) {
    messageEl.textContent = 'Network error. Please try again.';
    messageEl.className = 'message error';
  }
});

// Handle password reset request
document.getElementById('requestResetForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const email = document.getElementById('resetEmail').value;
  const messageEl = document.getElementById('resetMessage');
  
  try {
    const response = await fetch('/request-password-reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    
    const data = await response.json();
    
    messageEl.textContent = data.message;
    messageEl.className = 'message success';
    
  } catch (err) {
    messageEl.textContent = 'Network error. Please try again.';
    messageEl.className = 'message error';
  }
});
```

---

## 🔒 Security Best Practices

### 1. Rate Limiting

Add rate limiting to email endpoints:

```javascript
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many requests, please try again later',
});

app.post('/send-verification-code', emailLimiter, async (req, res) => {
  // ... handler code
});

app.post('/request-password-reset', emailLimiter, async (req, res) => {
  // ... handler code
});
```

### 2. HTTPS Only in Production

Ensure your production environment uses HTTPS to protect tokens in transit.

### 3. Don't Leak User Information

Never reveal whether an email exists in password reset responses (already implemented).

---

## 📧 Email Provider Setup

### Option 1: Gmail (Development)

1. Enable 2FA on your Google account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use in `.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-char-app-password
```

### Option 2: SendGrid (Production)

1. Sign up at https://sendgrid.com
2. Get API key
3. Use different module (needs code update)

### Option 3: AWS SES (Production)

1. Set up AWS SES
2. Verify domain
3. Use AWS credentials

---

## 🧪 Testing

### Development (Console Mode)

Emails are logged to console:

```env
EMAIL_PROVIDER=console
```

Check your terminal for email content!

### Production Testing

Send a test email:

```javascript
const { sendVerificationEmail } = require('./email-service');

// Test sending
await sendVerificationEmail('test@example.com', '123456', 'TestUser');
```

---

## 📊 Database Tables

### email_verifications
- `id` - Primary key
- `user_id` - Foreign key to users
- `email` - Email address
- `code` - 6-digit verification code
- `created_at` - Timestamp
- `expires_at` - Expiration timestamp (15 minutes)
- `verified_at` - When verified (NULL if not verified)

### password_resets
- `id` - Primary key
- `user_id` - Foreign key to users
- `email` - Email address
- `token` - Secure reset token
- `created_at` - Timestamp
- `expires_at` - Expiration timestamp (1 hour)
- `used_at` - When used (NULL if not used)

---

## 🎯 Summary

You now have:
- ✅ Email verification during registration
- ✅ Resend verification codes
- ✅ Password reset via email
- ✅ Secure token generation
- ✅ Auto-expiring codes/tokens
- ✅ Multiple email provider support
- ✅ Production-ready security

Next steps:
1. Run migration
2. Add API endpoints to server.js
3. Update your registration UI
4. Add email verification modal
5. Add "Forgot password?" link
6. Test in development
7. Configure SMTP for production

Happy coding! 🎉
