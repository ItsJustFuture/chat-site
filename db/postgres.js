"use strict";

const { Pool } = require("pg");

const POSTGRES_URL = process.env.DATABASE_URL || "";
const POSTGRES_ENABLED = !!POSTGRES_URL;
const NODE_ENV = process.env.NODE_ENV || "development";
const PGSSL_REJECT_ENV = process.env.PGSSL_REJECT_UNAUTHORIZED;
const POSTGRES_SSL_VERIFY = PGSSL_REJECT_ENV === undefined
  ? NODE_ENV === "production"
  : ["1", "true", "yes"].includes(String(PGSSL_REJECT_ENV).toLowerCase());
const POSTGRES_SSL_DISABLED = POSTGRES_ENABLED && POSTGRES_URL.includes("sslmode=disable");
const POSTGRES_SSL = POSTGRES_ENABLED && !POSTGRES_SSL_DISABLED
  ? { rejectUnauthorized: POSTGRES_SSL_VERIFY }
  : false;
const POSTGRES_SSL_MODE = POSTGRES_ENABLED
  ? (POSTGRES_SSL_DISABLED
      ? "disabled"
      : POSTGRES_SSL_VERIFY
        ? "verify"
        : "no-verify")
  : "disabled";
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
  POSTGRES_SSL_DISABLED,
  POSTGRES_SSL_MODE,
  POSTGRES_SSL_VERIFY,
  POSTGRES_URL,
};
