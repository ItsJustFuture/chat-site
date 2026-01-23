"use strict";

const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const { seedDevUser } = require("../database");

const LOCAL_DEV = process.env.LOCAL_DEV === "1";
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_DEV_MODE = LOCAL_DEV || NODE_ENV === "development" || NODE_ENV === "test";

const seed = {
  username: "Iri",
  password: "Perseverance75",
  role: "Owner",
};

async function seedPostgres() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  });
  try {
    const hash = await bcrypt.hash(seed.password, 10);
    await pool.query(
      `
      INSERT INTO users (username, password_hash, role, created_at)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (username)
      DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
      `,
      [seed.username, hash, seed.role, Date.now()]
    );
    console.log("[seed] Postgres: ensured dev user", seed.username);
  } finally {
    await pool.end();
  }
}

async function seedSqlite() {
  await seedDevUser(seed);
  console.log("[seed] SQLite: ensured dev user", seed.username);
}

async function main() {
  if (!IS_DEV_MODE) {
    console.error("[seed] Refusing to seed outside dev mode. Set LOCAL_DEV=1 to override.");
    process.exit(1);
  }

  if (process.env.DATABASE_URL) {
    try {
      await seedPostgres();
      return;
    } catch (err) {
      console.warn("[seed] Postgres failed, falling back to SQLite:", err?.message || err);
    }
  }

  await seedSqlite();
}

main().catch((err) => {
  console.error("[seed] failed:", err);
  process.exit(1);
});
