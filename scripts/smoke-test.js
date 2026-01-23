"use strict";

const http = require("http");
const { spawn } = require("child_process");

const PORT = Number(process.env.PORT || 4010);
const HEALTH_URL = `http://localhost:${PORT}/health`;

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fetchHealth() {
  return new Promise((resolve, reject) => {
    const req = http.get(HEALTH_URL, (res) => {
      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({ status: res.statusCode, body });
      });
    });
    req.on("error", reject);
  });
}

async function waitForHealth(retries = 30) {
  for (let i = 0; i < retries; i += 1) {
    try {
      const res = await fetchHealth();
      if (res.status === 200) return res;
    } catch {
      // ignore
    }
    await wait(500);
  }
  throw new Error("Health check did not respond in time.");
}

async function main() {
  const child = spawn("node", ["server.js"], {
    env: {
      ...process.env,
      LOCAL_DEV: "1",
      NODE_ENV: "development",
      PORT: String(PORT),
    },
    stdio: "inherit",
  });

  let result = null;
  try {
    result = await waitForHealth();
    console.log("[smoke] /health response:", result.body);
  } finally {
    child.kill("SIGTERM");
  }
}

main().catch((err) => {
  console.error("[smoke] failed:", err.message || err);
  process.exit(1);
});
