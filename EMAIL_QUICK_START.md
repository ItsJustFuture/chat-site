# Email Verification & Password Reset - Quick Start

## 📧 What's New

Your chat application now supports:
✅ Email verification during registration
✅ Password reset via email
✅ Secure 6-digit verification codes
✅ Time-limited reset tokens
✅ Multiple email providers (SMTP, Gmail, SendGrid, etc.)

## 🚀 Installation (5 Minutes)

### 1. Install Dependencies
```bash
npm install
```
This adds `nodemailer` for email sending.

### 2. Run Database Migration
```bash
sqlite3 data/dev.sqlite < migrations/20260128_email_verification.sql
```

### 3. Configure Email (Development)
Copy `.env.example` to `.env` and use console mode:
```env
EMAIL_PROVIDER=console
BASE_URL=http://localhost:3000
```

Emails will be logged to your terminal!

### 4. Start Server
```bash
npm run dev
```

Done! Email verification is ready to use.

## 📁 New Files

1. **email-service.js** - Sends emails via SMTP/Gmail/etc
2. **email-verification.js** - Verification logic & database ops
3. **migrations/20260128_email_verification.sql** - Database schema
4. **EMAIL_VERIFICATION_GUIDE.md** - Complete implementation guide

## 🔧 Integration

Read **EMAIL_VERIFICATION_GUIDE.md** for:
- API endpoints to add to server.js
- Frontend HTML/JavaScript examples
- Production email setup (Gmail, SendGrid)
- Security best practices
- Testing instructions

## 📝 Quick Example

### Send Verification Code
```javascript
const { sendVerificationCode } = require('./email-verification');

const result = await sendVerificationCode(userId, email, username);
// User receives 6-digit code via email
```

### Verify Code
```javascript
const { verifyEmailCode } = require('./email-verification');

const result = await verifyEmailCode(userId, code);
if (result.success) {
  // Email is verified!
}
```

### Request Password Reset
```javascript
const { requestPasswordReset } = require('./email-verification');

const result = await requestPasswordReset(email);
// User receives reset link via email
```

### Reset Password
```javascript
const { resetPasswordWithToken } = require('./email-verification');

const passwordHash = await bcrypt.hash(newPassword, 10);
const result = await resetPasswordWithToken(token, passwordHash);
```

## 🎨 Frontend Changes Needed

1. **Registration Form** - Add email field
2. **Email Verification Modal** - 6-digit code input
3. **Login Page** - Add "Forgot password?" link
4. **Password Reset Form** - Email input & new password

Examples provided in EMAIL_VERIFICATION_GUIDE.md!

## 📧 Email Providers

### Development (Easy)
```env
EMAIL_PROVIDER=console
```
Emails printed to terminal. Perfect for testing!

### Production (Gmail)
```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

Get Gmail App Password: https://myaccount.google.com/apppasswords

### Production (SendGrid/AWS SES)
See guide for configuration details.

## 🔒 Security Features

✅ Codes expire after 15 minutes
✅ Tokens expire after 1 hour
✅ Secure random generation
✅ Rate limiting ready
✅ No email enumeration
✅ Auto-cleanup of expired codes

## 🧪 Testing

### Console Mode (Default)
Just check your terminal - emails are printed there!

### Real Email Test
1. Set EMAIL_PROVIDER=smtp
2. Configure SMTP settings
3. Register with real email
4. Check inbox for code

## 📊 Database Changes

Adds 3 columns to `users` table:
- `email` - User's email address
- `email_verified` - Boolean flag

Adds 2 new tables:
- `email_verifications` - Verification codes
- `password_resets` - Reset tokens

## 🎯 Next Steps

1. ✅ Install: `npm install`
2. ✅ Migrate: Run SQL migration
3. ✅ Config: Set EMAIL_PROVIDER=console
4. ✅ Read: EMAIL_VERIFICATION_GUIDE.md
5. ✅ Integrate: Add API endpoints
6. ✅ UI: Add email fields to frontend
7. ✅ Test: Register with fake email
8. ✅ Deploy: Configure production SMTP

## 📞 Support

Everything is documented in:
- **EMAIL_VERIFICATION_GUIDE.md** - Complete guide
- **email-service.js** - JSDoc comments
- **email-verification.js** - JSDoc comments

All functions have detailed comments explaining parameters and return values!

---

**Ready to add email verification to your chat! 🎉**
