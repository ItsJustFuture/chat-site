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

## Optional Features

### Redis for Socket.IO Scaling
To enable Redis adapter for multi-server Socket.IO:

```bash
# .env
REDIS_URL=redis://localhost:6379
```

### Sentry Error Tracking
To enable Sentry error monitoring:

```bash
# .env
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
```

### PWA Support
To enable Progressive Web App features:

```bash
# .env or set meta tag in index.html
ENABLE_PWA=true
```

## Database Migrations

SQL migrations in `migrations/` are automatically applied on server startup. To add a new migration:

1. Create a file like `migrations/20260129_description.sql`
2. Add SQL statements (semicolon-separated)
3. Start the server - migration auto-applies

Check applied migrations:
```sql
SELECT * FROM migrations_log;
```

## Dev seed + smoke test

```bash
npm run dev:seed
npm run test:smoke
npm run test:memory
```

## Environment Variables Summary

**Required:**
- `DATABASE_URL` - PostgreSQL connection
- `SESSION_SECRET` - Session encryption key

**Optional:**
- `SQLITE_PATH` - SQLite database path (default: `./data/dev.sqlite`)
- `PGSSL_REJECT_UNAUTHORIZED` - Set to `1`, `true`, or `yes` to enforce cert verification (omit or use any other value for self-signed)
- `REDIS_URL` - Redis connection for Socket.IO adapter
- `SENTRY_DSN` - Sentry error tracking
- `ENABLE_PWA` - Enable PWA features
