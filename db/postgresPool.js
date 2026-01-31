"use strict";

const { Pool } = require("pg");

const POSTGRES_URL = process.env.DATABASE_URL || "";
const POSTGRES_ENABLED = !!POSTGRES_URL;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_RENDER = Boolean(
  process.env.RENDER || process.env.RENDER_SERVICE_ID || process.env.RENDER_EXTERNAL_URL
);
const IS_PROD = NODE_ENV === "production";
const POSTGRES_SSL_VERIFY = false;
const POSTGRES_SSL = POSTGRES_ENABLED ? { rejectUnauthorized: false } : false;
const POSTGRES_SSL_MODE = POSTGRES_ENABLED ? "no-verify" : "disabled";
const POSTGRES_CONFIG = POSTGRES_ENABLED
  ? {
      connectionString: POSTGRES_URL,
      ssl: POSTGRES_SSL,
    }
  : null;

let pgPool = null;
if (POSTGRES_ENABLED) {
  pgPool = new Pool(POSTGRES_CONFIG);
  const envLabel = IS_RENDER ? "render" : IS_PROD ? "production" : NODE_ENV;
  console.log(
    `[startup] Postgres pool created [db/postgresPool] env=${envLabel} ssl=${POSTGRES_SSL_MODE}`
  );
  pgPool.on("error", (err) => {
    console.warn("[db] Postgres pool error:", err?.message || err);
  });
}

module.exports = {
  pgPool,
  POSTGRES_CONFIG,
  POSTGRES_ENABLED,
  POSTGRES_SSL,
  POSTGRES_SSL_MODE,
  POSTGRES_SSL_VERIFY,
  POSTGRES_URL,
  IS_PROD,
  IS_RENDER,
};
