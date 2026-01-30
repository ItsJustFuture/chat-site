#!/usr/bin/env node
/**
 * Development Environment Verification Script
 * 
 * This script verifies that the development environment is set up correctly
 * and provides helpful diagnostics.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔍 Verifying development environment...\n');

const checks = {
  passed: [],
  warnings: [],
  failed: []
};

function addCheck(type, message) {
  checks[type].push(message);
}

// Check Node.js version
try {
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1).split('.')[0]);
  if (major >= 20) {
    addCheck('passed', `✓ Node.js version: ${nodeVersion}`);
  } else {
    addCheck('warnings', `⚠ Node.js version ${nodeVersion} (recommend v20+)`);
  }
} catch (err) {
  addCheck('failed', '✗ Could not detect Node.js version');
}

// Check npm version
try {
  const npmVersion = execSync('npm --version', { encoding: 'utf8' }).trim();
  addCheck('passed', `✓ npm version: ${npmVersion}`);
} catch (err) {
  addCheck('failed', '✗ npm not available');
}

// Check node_modules exists
if (fs.existsSync(path.join(__dirname, '..', 'node_modules'))) {
  addCheck('passed', '✓ node_modules installed');
} else {
  addCheck('failed', '✗ node_modules not found - run: npm install');
}

// Check TypeScript availability
try {
  const tsVersion = execSync('npx tsc --version', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  addCheck('passed', `✓ TypeScript available: ${tsVersion}`);
} catch (err) {
  addCheck('warnings', '⚠ TypeScript not available (install with: npm install --save-dev typescript)');
}

// Check jsconfig.json exists
if (fs.existsSync(path.join(__dirname, '..', 'jsconfig.json'))) {
  addCheck('passed', '✓ jsconfig.json configured');
} else {
  addCheck('warnings', '⚠ jsconfig.json missing (IntelliSense may not work)');
}

// Check .env file
if (fs.existsSync(path.join(__dirname, '..', '.env'))) {
  addCheck('passed', '✓ .env file exists');
} else {
  addCheck('warnings', '⚠ .env file not found (copy from .env.example)');
}

// Check if Docker is available (optional)
try {
  execSync('docker --version', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  addCheck('passed', '✓ Docker available (optional)');
} catch (err) {
  addCheck('warnings', '⚠ Docker not available (optional for PostgreSQL)');
}

// Check main files exist
const criticalFiles = ['server.js', 'database.js', 'package.json'];
criticalFiles.forEach(file => {
  if (fs.existsSync(path.join(__dirname, '..', file))) {
    addCheck('passed', `✓ ${file} exists`);
  } else {
    addCheck('failed', `✗ ${file} missing!`);
  }
});

// Check public/index.html exists (served by the app)
if (fs.existsSync(path.join(__dirname, '..', 'public', 'index.html'))) {
  addCheck('passed', '✓ public/index.html exists');
} else {
  addCheck('failed', '✗ public/index.html missing!');
}

// Check migrations directory
if (fs.existsSync(path.join(__dirname, '..', 'migrations'))) {
  const migrations = fs.readdirSync(path.join(__dirname, '..', 'migrations')).filter(f => f.endsWith('.sql'));
  addCheck('passed', `✓ Migrations directory exists (${migrations.length} migrations)`);
} else {
  addCheck('warnings', '⚠ Migrations directory not found');
}

// Run syntax check
try {
  execSync('npm run check', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  addCheck('passed', '✓ JavaScript syntax check passed');
} catch (err) {
  addCheck('failed', '✗ JavaScript syntax check failed');
}

// Check for high-severity vulnerabilities
try {
  execSync('npm audit --audit-level=high', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  addCheck('passed', '✓ No high-severity vulnerabilities');
} catch (err) {
  addCheck('warnings', '⚠ High-severity vulnerabilities detected (see: npm audit)');
}

// Print results
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('Results:');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

if (checks.passed.length > 0) {
  checks.passed.forEach(msg => console.log(msg));
  console.log();
}

if (checks.warnings.length > 0) {
  console.log('Warnings:');
  checks.warnings.forEach(msg => console.log(msg));
  console.log();
}

if (checks.failed.length > 0) {
  console.log('Failed:');
  checks.failed.forEach(msg => console.log(msg));
  console.log();
}

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

if (checks.failed.length === 0) {
  console.log(`\n✅ Environment ready! (${checks.passed.length}/${checks.passed.length + checks.warnings.length} checks passed)\n`);
  console.log('Next steps:');
  console.log('  1. Run: npm run dev');
  console.log('  2. Open: http://localhost:3000');
  console.log('  3. See: QUICK_DEV.md for common tasks\n');
  process.exit(0);
} else {
  console.log(`\n❌ Environment needs attention (${checks.failed.length} critical issues)\n`);
  console.log('Fix critical issues above and run this script again.\n');
  process.exit(1);
}
