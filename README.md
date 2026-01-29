# Banter & Brats — Local Dev DB Setup

## Quick start (SQLite fallback)
SQLite is the default for local/dev runs when Postgres is unavailable.

```bash
npm install
npm run dev
```

The server logs a fallback warning and `/health` reports `db=sqlite`.

## Optional Postgres via Docker
If you want Postgres locally:

```bash
docker compose up -d
```

Then set `DATABASE_URL` (see `.env.example`) and run:

```bash
npm run dev
```

`/health` will report `db=postgres` when the connection is live.

## Dev seed + smoke test

```bash
npm run dev:seed
npm run test:smoke
```

## New Features

### Markdown Support
Messages now support markdown formatting including:
- **Bold** with `**text**` or `__text__`
- *Italic* with `*text*` or `_text_`
- `Code` with backticks
- Links, lists, and more

All markdown is sanitized to prevent XSS attacks.

### Emoji Shortcodes
Type emoji shortcodes like `:smile:` `:heart:` `:fire:` and they'll be converted to emoji (😄 ❤️ 🔥). Over 200 common emoji shortcodes are supported.

### Message Read Receipts & Delivery Tracking
Messages now track:
- `delivered_at` - When message was delivered to recipients
- `read_at` - When message was read
- `edited_at` - When message was last edited
- Edit history is preserved in the `message_edits` table

### PWA Support (Optional)
When `ENABLE_PWA=1` is set in production, the app functions as a Progressive Web App with:
- Offline support via service worker
- Install to home screen capability
- App manifest with branding

### Optional Integrations

#### Sentry Error Tracking
Set `SENTRY_DSN` in your environment to enable error tracking and performance monitoring:
```bash
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
SENTRY_TRACES_SAMPLE_RATE=0.1
```

#### Redis for Horizontal Scaling
Set `REDIS_URL` to enable Socket.IO Redis adapter for multi-instance deployments:
```bash
REDIS_URL=redis://localhost:6379
```
Falls back gracefully to single-instance mode if Redis is unavailable.

## Environment Variables

Copy `.env.example` to `.env` and configure:

### Required (Production)
- `DATABASE_URL` - Postgres connection string
- `SESSION_SECRET` - Strong secret for session encryption (16+ chars)

### Optional
- `SQLITE_PATH` - Path to SQLite database (default: `./data/dev.sqlite`)
- `REDIS_URL` - Redis connection for Socket.IO scaling
- `SENTRY_DSN` - Sentry error tracking
- `ENABLE_PWA` - Enable PWA features in production
- `RATE_LIMIT_*` - Configure rate limits (see `.env.example`)

## Database Migrations

New columns are automatically added to existing tables on startup. The migration system is backwards-compatible and won't lose data.

If you need to manually run migrations:
```bash
# Migrations are in migrations/ directory
# They run automatically on server start
```

## Testing

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run smoke tests
npm run test:smoke

# Run memory sanity checks
npm run test:memory
```

## CI/CD

The project includes a GitHub Actions workflow that runs:
- Syntax checks (`npm run check`)
- Unit tests (`npm run test:unit`)
- Smoke tests (`npm run test:smoke`)
- Memory sanity tests (`npm run test:memory`)

Runs on Node.js 18.x, 20.x, and 22.x.
