"use strict";

const { Pool } = require("pg");

const POSTGRES_URL = process.env.DATABASE_URL || "";
const POSTGRES_ENABLED = !!POSTGRES_URL;
const PGSSL_REJECT_ENV = process.env.PGSSL_REJECT_UNAUTHORIZED;
const POSTGRES_SSL_VERIFY = PGSSL_REJECT_ENV
  ? ["1", "true", "yes"].includes(String(PGSSL_REJECT_ENV).toLowerCase())
  : false;
const POSTGRES_SSL = POSTGRES_ENABLED ? { rejectUnauthorized: POSTGRES_SSL_VERIFY } : false;
const POSTGRES_CONFIG = POSTGRES_ENABLED
  ? {
      connectionString: POSTGRES_URL,
      ssl: POSTGRES_SSL,
    }
  : null;

let pgPool = null;
if (POSTGRES_ENABLED) {
  pgPool = new Pool(POSTGRES_CONFIG);
  pgPool.on("error", (err) => {
    console.warn("[db] Postgres pool error:", err?.message || err);
  });
}

module.exports = {
  pgPool,
  POSTGRES_CONFIG,
  POSTGRES_ENABLED,
  POSTGRES_SSL,
  POSTGRES_SSL_VERIFY,
  POSTGRES_URL,
};
