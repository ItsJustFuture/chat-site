# Banter & Brats - Chat Application

## Overview
Banter & Brats is an 18+ community chat application built with Node.js and Express. It features rooms, DMs, reactions, leaderboards, themes, profile customization, markdown rendering, message receipts, and more.

## Recent Features (2026-01-29)
- ✨ **Markdown rendering** with DOMPurify sanitization
- 📬 **Message delivery/read receipts** with database tracking
- 😊 **Emoji shortcodes** (`:smile:` → 😊)
- ⌨️ **Keyboard shortcuts** (Enter = send, Shift+Enter = newline)
- ⚡ **Message reactions** with history tracking
- 📝 **Edit history** persisted in database
- 🗑️ **Soft delete** with deleted_at timestamps
- 🔴 **Optional Redis adapter** for Socket.IO scaling
- 📱 **PWA support** (manifest.json, service worker)
- 🔒 **Enhanced security** with Helmet CSP
- 📊 **Optional Sentry** error tracking

## Project Structure
- `server.js` - Main Express server with Socket.IO for real-time chat
- `database.js` - Database utilities for SQLite (local dev) and PostgreSQL (production)
- `lib/message-utils.js` - Helper functions for message operations
- `public/` - Frontend static assets (app.js, theme-init.js, manifest.json, sw.js)
- `index.html` - Main HTML entry point
- `styles.css` - Application styles
- `migrations/` - SQL migration files (auto-applied on startup)
- `scripts/` - Development and testing scripts

## Tech Stack
- **Backend**: Node.js 20, Express 5
- **Database**: PostgreSQL (primary), SQLite (local fallback)
- **Real-time**: Socket.IO (with optional Redis adapter)
- **Auth**: bcrypt for password hashing, express-session
- **Markdown**: marked.js with DOMPurify sanitization
- **Other**: Helmet (security), multer (file uploads)

## Environment Variables

### Required
- `DATABASE_URL` - PostgreSQL connection string (auto-configured by Replit)
- `SESSION_SECRET` - Session encryption key (configured as secret)
- `PORT` - Server port (set to 5000)

### Optional
- `SQLITE_PATH` - Optional local SQLite path
- `REDIS_URL` - Redis connection string for Socket.IO adapter (enables multi-server scaling)
- `SENTRY_DSN` - Sentry DSN for error tracking (enables error monitoring)
- `ENABLE_PWA` - Set to `true` to enable PWA features (service worker)

## Running the App
- **Development**: `npm run dev` (enables LOCAL_DEV mode)
- **Production**: `npm start`
- **Migrations**: Automatically applied on startup from `migrations/` folder

## Database Migrations

The app now supports SQL file-based migrations. Migration files in `migrations/` are automatically executed on server startup.

### Running a migration
1. Place `.sql` file in `migrations/` directory (e.g., `20260129_add_feature.sql`)
2. Start the server - migrations are auto-applied
3. Applied migrations are tracked in `migrations_log` table

### Manual migration check
```sql
SELECT * FROM migrations_log;
```

## Testing
- `npm run test:memory` - Memory sanity checks
- `npm run test:smoke` - Smoke tests
- `npm run check` - Syntax validation
- `npm run audit` - Security audit

## Recent Changes
- 2026-01-29: Added markdown rendering, message receipts, reactions history, PWA support, Redis adapter, Sentry integration
- 2026-01-28: Initial Replit setup, configured PostgreSQL, set PORT to 5000

## Notes
- The app uses both SQLite and PostgreSQL - SQLite for local development, PostgreSQL for production
- Migrations in `migrations/` folder work for both SQLite and PostgreSQL
- All new features are opt-in via environment variables (no breaking changes)
