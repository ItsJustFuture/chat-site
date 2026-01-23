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
