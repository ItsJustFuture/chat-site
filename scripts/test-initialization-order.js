"use strict";

/**
 * Test script to verify server initialization order
 * Verifies that:
 * 1. Database migrations complete before server starts
 * 2. State persistence initializes before server starts
 * 3. All phases execute in correct order
 */

const { spawn } = require("child_process");
const path = require("path");

console.log("[test-init-order] Starting initialization order test...");

// Use a random high port to avoid conflicts
const testPort = Math.floor(Math.random() * 10000) + 40000;

const serverPath = path.join(__dirname, "..", "server.js");
const server = spawn("node", [serverPath], {
  env: { ...process.env, LOCAL_DEV: "1", PORT: String(testPort) },
  cwd: path.join(__dirname, ".."),
});

let output = "";
const expectedPhases = [
  "Phase 1: Environment validation",
  "✓ Environment validation complete",
  "Phase 2: Database initialization",
  "Running SQLite migrations",
  "✓ SQLite migrations complete",
  "✓ SQLite ready with all core tables",
  "✓ Database initialization complete",
  "Phase 3: State management initialization",
  "✓ State management ready",
  "Phase 4: Core data initialization",
  "✓ Core data initialization complete",
  "Phase 5: Word filters initialization",
  "✓ Word filters ready",
  "Phase 6: Starting HTTP server",
  "✓ HTTP server listening on port",
  "=== SERVER FULLY READY ===",
];

let phaseIndex = 0;
let allPhasesFound = false;

server.stdout.on("data", (data) => {
  const text = data.toString();
  output += text;
  
  // Check for phases in order
  while (phaseIndex < expectedPhases.length) {
    const phase = expectedPhases[phaseIndex];
    if (output.includes(phase)) {
      console.log(`[test-init-order] ✓ Found: ${phase}`);
      phaseIndex++;
    } else {
      break;
    }
  }
  
  if (phaseIndex === expectedPhases.length && !allPhasesFound) {
    allPhasesFound = true;
    console.log("[test-init-order] ========================================");
    console.log("[test-init-order] ✓ All initialization phases completed in correct order");
    console.log("[test-init-order] ========================================");
    server.kill();
    process.exit(0);
  }
});

server.stderr.on("data", (data) => {
  const text = data.toString();
  if (!text.includes("ExperimentalWarning")) {
    console.error(`[test-init-order] Error: ${text}`);
  }
});

server.on("close", (code) => {
  if (!allPhasesFound) {
    console.error("[test-init-order] ========================================");
    console.error("[test-init-order] ✗ TEST FAILED");
    console.error("[test-init-order] Not all phases completed in expected order");
    console.error(`[test-init-order] Found ${phaseIndex}/${expectedPhases.length} phases`);
    console.error("[test-init-order] ========================================");
    process.exit(1);
  }
});

// Timeout after 30 seconds
setTimeout(() => {
  console.error("[test-init-order] ✗ TEST TIMEOUT");
  server.kill();
  process.exit(1);
}, 30000);
