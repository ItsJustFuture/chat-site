"use strict";

/**
 * Test script to verify environment validation
 * Tests that server exits properly when SESSION_SECRET is missing in production
 */

const { spawn } = require("child_process");
const path = require("path");

console.log("[test-env-validation] Starting environment validation test...");

// Test 1: Missing SESSION_SECRET in production should fail
console.log("[test-env-validation] Test 1: Missing SESSION_SECRET in production");

const serverPath = path.join(__dirname, "..", "server.js");
const server = spawn("node", [serverPath], {
  env: { 
    ...process.env,
    NODE_ENV: "production",
    LOCAL_DEV: undefined, // Remove LOCAL_DEV
    SESSION_SECRET: undefined, // Remove SESSION_SECRET
    PORT: "4021",
  },
  cwd: path.join(__dirname, ".."),
});

let output = "";
let errorOutput = "";
let exitedWithError = false;

server.stdout.on("data", (data) => {
  output += data.toString();
});

server.stderr.on("data", (data) => {
  errorOutput += data.toString();
});

server.on("close", (code) => {
  if (code !== 0 && errorOutput.includes("SESSION_SECRET")) {
    console.log("[test-env-validation] ✓ Server correctly exited with error for missing SESSION_SECRET");
    console.log("[test-env-validation] ========================================");
    console.log("[test-env-validation] ✓ Environment validation test PASSED");
    console.log("[test-env-validation] ========================================");
    process.exit(0);
  } else {
    console.error("[test-env-validation] ========================================");
    console.error("[test-env-validation] ✗ TEST FAILED");
    console.error(`[test-env-validation] Expected exit code != 0, got ${code}`);
    console.error("[test-env-validation] Expected error about SESSION_SECRET");
    console.error("[test-env-validation] Error output:", errorOutput);
    console.error("[test-env-validation] ========================================");
    process.exit(1);
  }
});

// Timeout after 10 seconds
setTimeout(() => {
  console.error("[test-env-validation] ✗ TEST TIMEOUT");
  server.kill();
  process.exit(1);
}, 10000);
