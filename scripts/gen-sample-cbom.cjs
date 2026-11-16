#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Regenerate cbom-tools/cbom-cyclonedx.json from a pinned fixture.
//
// Why a fixture and a fixed timestamp: the sample used to be produced from a
// demo project that no longer exists, so nobody could tell whether it still
// matched the scanner. It drifted from 0.2.1 to 0.3.0 unnoticed, and by then
// the confidence values in it described a model the code no longer used.
//
// The scan is reproducible: same fixture, same SOURCE_DATE_EPOCH, same bytes.
// scripts/check-sample-cbom.cjs relies on exactly that.

'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SAMPLE_DIR = path.join(ROOT, 'cbom-tools', 'fixtures', 'sample-project');
const SCAN = path.join(ROOT, 'cbom-tools', 'cbom-scan.cjs');
const OUT = path.join(ROOT, 'cbom-tools', 'cbom-cyclonedx.json');

// 2026-11-16T00:00:00Z - the day the model changed. Fixed, not "now".
const SOURCE_DATE_EPOCH = String(Date.parse('2026-11-16T00:00:00Z') / 1000);

function generate() {
  const r = spawnSync(process.execPath, [SCAN, '--dir', SAMPLE_DIR, '--spec', '1.7'], {
    encoding: 'utf8',
    cwd: path.join(ROOT, 'cbom-tools'),
    env: { ...process.env, SOURCE_DATE_EPOCH },
  });
  if (r.status !== 0) {
    throw new Error(`cbom-scan failed (exit ${r.status}): ${(r.stderr || '').slice(0, 400)}`);
  }
  return r.stdout;
}

module.exports = { generate, OUT, SAMPLE_DIR, SOURCE_DATE_EPOCH, SCAN };

if (require.main === module) {
  const fs = require('node:fs');
  const text = generate();
  fs.writeFileSync(OUT, text, 'utf8');
  const bom = JSON.parse(text);
  console.log(`wrote ${path.relative(ROOT, OUT)}: ${bom.components.length} components, timestamp ${bom.metadata.timestamp}`);
}
