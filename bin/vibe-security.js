#!/usr/bin/env node

import { resolve } from 'path';
import { walkFiles } from '../src/scanner.js';
import { detectStack, stackLabel } from '../src/detector.js';
import { report } from '../src/reporter.js';

// Check modules
import { check as checkSecrets } from '../src/checks/secrets.js';
import { check as checkDatabase } from '../src/checks/database.js';
import { check as checkAuth } from '../src/checks/auth.js';
import { check as checkPayments } from '../src/checks/payments.js';
import { check as checkDeployment } from '../src/checks/deployment.js';
import { check as checkRateLimit } from '../src/checks/rate-limiting.js';
import { check as checkAI } from '../src/checks/ai-integration.js';
import { check as checkDataAccess } from '../src/checks/data-access.js';
import { check as checkMobile } from '../src/checks/mobile.js';
import { check as checkXSS } from '../src/checks/xss.js';
import { check as checkPathTraversal } from '../src/checks/path-traversal.js';
import { check as checkOpenRedirect } from '../src/checks/open-redirect.js';

// ── Parse args ───────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
  vibe-security — Security audit for vibe-coded apps

  Usage:
    vibe-security [path] [options]
    npx vibe-security [path] [options]

  Options:
    --path <dir>   Directory to scan (default: current directory)
    --help, -h     Show this help message

  Examples:
    vibe-security                  # Scan current directory
    vibe-security ./my-app         # Scan a specific path
    vibe-security --path ./my-app  # Same as above

  Exit codes:
    0  No critical or high issues found
    1  Critical or high issues found (useful for CI)
  `);
  process.exit(0);
}

// Resolve scan path: positional arg or --path flag
const pathFlagIdx = args.indexOf('--path');
let rawPath;
if (pathFlagIdx >= 0) {
  rawPath = args[pathFlagIdx + 1];
} else {
  rawPath = args.find((a) => !a.startsWith('--')) ?? './';
}
const scanPath = resolve(rawPath);

// ── Run audit ────────────────────────────────────────────────
const start = Date.now();

let stacks, files;
try {
  stacks = detectStack(scanPath);
  files = walkFiles(scanPath);
} catch (err) {
  console.error(`\nError: Could not read directory "${scanPath}"\n  ${err.message}\n`);
  process.exit(2);
}

const duration = ((Date.now() - start) / 1000).toFixed(1);

// Run all checks, swallow individual check errors to avoid aborting the whole audit
function safeCheck(fn, ...args) {
  try {
    return fn(...args) ?? [];
  } catch (err) {
    return [];
  }
}

const findings = [
  ...safeCheck(checkSecrets, files, scanPath, stacks),
  ...safeCheck(checkDatabase, files, scanPath, stacks),
  ...safeCheck(checkAuth, files, scanPath, stacks),
  ...safeCheck(checkPayments, files, scanPath, stacks),
  ...safeCheck(checkDeployment, files, scanPath, stacks),
  ...safeCheck(checkRateLimit, files, scanPath, stacks),
  ...safeCheck(checkAI, files, scanPath, stacks),
  ...safeCheck(checkDataAccess, files, scanPath, stacks),
  ...safeCheck(checkMobile, files, scanPath, stacks),
  ...safeCheck(checkXSS, files, scanPath, stacks),
  ...safeCheck(checkPathTraversal, files, scanPath, stacks),
  ...safeCheck(checkOpenRedirect, files, scanPath, stacks),
];

// Sort by severity
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
findings.sort(
  (a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
);

// ── Report and exit ──────────────────────────────────────────
const exitCode = report(findings, scanPath, stackLabel(stacks), files.length, duration);
process.exit(exitCode);
