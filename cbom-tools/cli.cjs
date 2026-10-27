#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
/**
 * cbom-tools — one entry point for the two binaries.
 *
 * Why this exists: the package shipped `cbom-scan` and `cbom-diff` as separate
 * bins, so `npx cbom-tools scan` — the thing a first-time reader types — failed
 * with "could not determine executable to run". A package whose name is not a
 * command is a package nobody tries twice.
 *
 *   npx cbom-tools scan --dir ./project --out cbom.json
 *   npx cbom-tools diff cbom-before.json cbom-after.json
 *
 * The old bin names still work; this is an addition, not a rename.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const COMMANDS = {
  scan: 'cbom-scan.cjs',
  diff: 'cbom-diff.js',
};

function usage() {
  console.log(`cbom-tools — Cryptographic Bill of Materials

Usage:
  cbom-tools scan [--dir <path>] [--out <file>]   scan a tree, emit CycloneDX CBOM
  cbom-tools diff <old.json> <new.json> [--json]  diff two CBOMs
  cbom-tools --version
  cbom-tools --help

Aliases installed alongside: cbom-scan, cbom-diff.
Zero external dependencies. Pure Node.js.`);
}

const argv = process.argv.slice(2);
const sub = argv[0];

if (!sub || sub === '--help' || sub === '-h' || sub === 'help') {
  usage();
  process.exit(0);
}

if (sub === '--version' || sub === '-v' || sub === 'version') {
  const pkg = require('./package.json');
  console.log(`cbom-tools ${pkg.version}`);
  process.exit(0);
}

const target = COMMANDS[sub];
if (!target) {
  console.error(`cbom-tools: unknown command "${sub}"`);
  usage();
  process.exit(2);
}

const result = spawnSync(process.execPath, [path.join(__dirname, target), ...argv.slice(1)], {
  stdio: 'inherit',
});

if (result.error) {
  console.error(`cbom-tools: failed to run ${target}: ${result.error.message}`);
  process.exit(2);
}

process.exit(result.status === null ? 1 : result.status);
