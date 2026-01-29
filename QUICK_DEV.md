# Quick Development Reference

## Quick Start

```bash
# Install dependencies
npm install

# Start development server (uses SQLite by default)
npm run dev

# Open http://localhost:3000
```

## Common Tasks

### Code Quality Checks

```bash
# Check JavaScript syntax
npm run check

# Check for security issues
npm run audit

# Run all checks
npm run verify
```

### Testing

```bash
# Run all available tests
npm run test:memory    # Memory sanity checks
npm run test:dice      # Dice mechanics
npm run test:chess     # Chess ELO system
npm run test:smoke     # General smoke tests

# Seed test data
npm run dev:seed
```

### Database

```bash
# View current database (SQLite in dev mode)
sqlite3 data/dev.sqlite "SELECT * FROM migrations_log;"

# Start fresh database
rm -rf data/dev.sqlite && npm run dev
```

### Server Management

```bash
# Development mode (SQLite, LOCAL_DEV=1)
npm run dev

# Production mode
npm start

# With PostgreSQL (via Docker)
docker compose up -d
# Set DATABASE_URL in .env
npm run dev
```

## File Organization

- **server.js** - Main server (Express + Socket.IO)
- **database.js** - Database layer (PostgreSQL/SQLite)
- **public/** - Client-side code (HTML, CSS, JS)
- **scripts/** - Development and test scripts
- **migrations/** - Database migrations (auto-applied on startup)

## Key Features

- **Auto-migrations**: SQL files in `migrations/` run automatically
- **SQLite fallback**: No PostgreSQL? No problem - SQLite works out of the box
- **Type checking**: jsconfig.json enables IntelliSense in editors
- **Hot reload**: Just restart server to see changes

## Troubleshooting

```bash
# Port 3000 already in use
lsof -ti:3000 | xargs kill -9

# Clean reinstall
rm -rf node_modules package-lock.json && npm install

# Database issues
rm -rf data/ && npm run dev
```

## Editor Setup

The repository includes `jsconfig.json` for enhanced JavaScript editing:
- Auto-completion
- Go to definition
- Find references
- Rename refactoring

Works automatically in VS Code, WebStorm, and other modern editors.

## Environment Variables

Create `.env` from `.env.example`:

```bash
# Minimal setup (SQLite)
SESSION_SECRET=your-secret-here

# With PostgreSQL
DATABASE_URL=postgresql://user:pass@localhost:5432/chatsite

# Optional features
REDIS_URL=redis://localhost:6379
SENTRY_DSN=https://...@sentry.io/...
ENABLE_PWA=true
```

## Performance Tips

1. Use SQLite for local development (faster, simpler)
2. Run specific tests, not the full suite
3. Use `npm run dev` for helpful debug output
4. Keep Redis off unless testing multi-server setups

For detailed information, see [DEV_ENVIRONMENT.md](./DEV_ENVIRONMENT.md)
