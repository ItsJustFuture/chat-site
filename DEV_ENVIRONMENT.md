# Development Environment Setup

This document describes the optimal development environment setup for the chat-site project.

## Prerequisites

- **Node.js**: v20.20.0 or higher
- **npm**: 10.8.2 or higher
- **Docker** (optional): For PostgreSQL and Redis

## Initial Setup

### 1. Install Dependencies

```bash
npm install
```

This installs all production and development dependencies, including:
- TypeScript language server for better code intelligence
- Type definitions for Node.js and Express

### 2. Verify Environment

```bash
npm run dev:verify
```

This runs a comprehensive check of your development environment and reports any issues.

### 3. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration. For local development, SQLite is used by default if PostgreSQL is unavailable.

**Key Variables:**
- `SESSION_SECRET` - Required for session encryption
- `DATABASE_URL` - Optional; uses SQLite fallback if not set
- `PGSSL_REJECT_UNAUTHORIZED` - Optional; set to `1`, `true`, or `yes` to enable strict cert verification (defaults to enabled in production, disabled otherwise; use `0`/omit for self-signed)
- `REDIS_URL` - Optional; enables multi-server Socket.IO scaling
- `SENTRY_DSN` - Optional; enables error tracking
- `ENABLE_PWA` - Optional; enables Progressive Web App features

### 4. Start Development Server

```bash
npm run dev
```

The server will start on `http://localhost:3000` with SQLite fallback.

### 5. Optional: Start PostgreSQL with Docker

```bash
docker compose up -d
```

Then set `DATABASE_URL` in your `.env` file.

## Available Scripts

### Development
- `npm run dev` - Start server in development mode with LOCAL_DEV=1
- `npm run dev:seed` - Seed database with test data
- `npm run dev:verify` - Verify development environment setup
- `npm start` - Start server in production mode

### Testing
- `npm run test` - Run all tests (currently placeholder)
- `npm run test:smoke` - Run smoke tests
- `npm run test:memory` - Run memory sanity checks
- `npm run test:dice` - Run dice variant smoke tests
- `npm run test:couples` - Run couples regression tests
- `npm run test:chess` - Run chess ELO smoke tests

### Code Quality
- `npm run check` - Syntax check all JavaScript files
- `npm run audit` - Check for high-level security vulnerabilities
- `npm run verify` - Run fund, check, and audit together

## Code Intelligence Features

### TypeScript Language Server

The repository is configured with TypeScript language server support via `jsconfig.json`. This provides:

- **IntelliSense**: Auto-completion for variables, functions, and imports
- **Type Checking**: Optional type checking in JavaScript files
- **Go to Definition**: Jump to function/variable definitions
- **Find References**: Find all usages of a symbol
- **Rename Symbol**: Safely rename variables/functions across files

### Using the Language Server

The TypeScript language server can be started for enhanced code navigation:

```bash
# The language server is available via tsserver
npx tsserver
```

Most modern editors (VS Code, WebStorm, etc.) will automatically use this configuration.

## Database Migrations

SQL migrations in `migrations/` are automatically applied on server startup.

**To add a new migration:**

1. Create a file: `migrations/YYYYMMDD_description.sql`
2. Add SQL statements (semicolon-separated)
3. Start the server - migration auto-applies

**Check applied migrations:**

```sql
SELECT * FROM migrations_log;
```

## Project Structure

```
chat-site/
├── server.js              # Main server file (Express + Socket.IO)
├── database.js            # Database connection and helpers
├── index.html             # Main HTML file
├── public/               # Static assets
│   ├── app.js           # Client-side JavaScript
│   ├── styles.css       # Client-side styles
│   ├── chess/           # Chess game assets
│   └── arena/           # Arena game assets
├── scripts/             # Development and test scripts
├── migrations/          # Database migration files
├── lib/                 # Shared libraries
└── package.json         # Project dependencies and scripts
```

## Development Workflow

### 1. Make Code Changes

Edit JavaScript files with full IntelliSense support.

### 2. Syntax Check

```bash
npm run check
```

### 3. Run Relevant Tests

```bash
npm run test:memory    # For database changes
npm run test:dice      # For dice mechanics changes
npm run test:chess     # For chess system changes
npm run test:smoke     # For general functionality
```

### 4. Start Development Server

```bash
npm run dev
```

Test your changes at `http://localhost:3000`.

### 5. Security Audit

Before committing:

```bash
npm run audit
```

## Known Issues

### Test Failures

- `test:couples` requires proper Origin header setup and may fail in some environments

### Security Vulnerabilities

Current known vulnerabilities:
- **tar** (high): File overwrite vulnerabilities in sqlite3 dependencies - non-critical for development

These are in development dependencies and don't affect production security when using managed databases.

## Performance Tips

1. **Use SQLite for Local Development**: Faster startup and no external dependencies
2. **Enable Redis Only When Testing Multi-Server**: Reduces complexity for single-instance development
3. **Use `npm run dev`**: Enables LOCAL_DEV mode with helpful debugging output
4. **Run Specific Tests**: Use targeted test scripts instead of full suite

## IDE Configuration

### VS Code

The repository includes `jsconfig.json` which VS Code automatically recognizes. Features:
- Auto-imports
- IntelliSense
- Error detection
- Refactoring support

### Other IDEs

Most modern IDEs (WebStorm, Atom, Sublime) support `jsconfig.json` and will provide enhanced JavaScript editing.

## Troubleshooting

### Port Already in Use

```bash
# Find and kill process on port 3000
lsof -ti:3000 | xargs kill -9
```

### Database Locked

```bash
# Remove SQLite database and restart
rm -rf data/dev.sqlite
npm run dev
```

### Dependencies Issues

```bash
# Clean install
rm -rf node_modules package-lock.json
npm install
```

## Additional Resources

- [README.md](./README.md) - Project overview and setup
- [EMAIL_QUICK_START.md](./EMAIL_QUICK_START.md) - Email service setup
- [EMAIL_VERIFICATION_GUIDE.md](./EMAIL_VERIFICATION_GUIDE.md) - Email verification implementation
- [CHANGELOG.md](./CHANGELOG.md) - Project changes and history
