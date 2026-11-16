#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Fail if the committed sample BOM is not what the scanner produces today.
//
// A generated file that is checked in but never regenerated is a liability: it
// silently describes behaviour that no longer exists, and every document that
// quotes it inherits the error. The sample in this repository did exactly that
// (frozen at 0.2.1 through 0.2.9).
//
// Exit 0 when identical, 1 when drifted, 2 when the regeneration itself failed.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { generate, OUT } = require('./gen-sample-cbom.cjs');

function componentMap(bom) {
  const m = new Map();
  for (const c of bom.components || []) {
    const id = (c.evidence && c.evidence.identity && c.evidence.identity[0]) || {};
    m.set(c.name, {
      confidence: id.confidence,
      methods: (id.methods || []).map((x) => `${x.technique}=${x.confidence}`).join('+'),
    });
  }
  return m;
}

function main() {
  let fresh;
  try {
    fresh = generate();
  } catch (err) {
    console.error(`sample-cbom: regeneration failed: ${err.message}`);
    process.exit(2);
  }

  if (!fs.existsSync(OUT)) {
    console.error(`sample-cbom: ${path.basename(OUT)} is missing; run node scripts/gen-sample-cbom.cjs`);
    process.exit(1);
  }

  const committed = fs.readFileSync(OUT, 'utf8');
  if (committed === fresh) {
    console.log(`sample-cbom: up to date (${JSON.parse(fresh).components.length} components)`);
    return;
  }

  // Byte comparison is the gate; the summary below exists so a red build says
  // what changed instead of printing two documents.
  const before = componentMap(JSON.parse(committed));
  const after = componentMap(JSON.parse(fresh));
  const added = [...after.keys()].filter((k) => !before.has(k));
  const removed = [...before.keys()].filter((k) => !after.has(k));
  const changed = [...after.keys()].filter((k) => before.has(k)
    && (before.get(k).confidence !== after.get(k).confidence || before.get(k).methods !== after.get(k).methods));

  console.error('sample-cbom: committed sample does not match a fresh scan');
  if (added.length) console.error('  only in fresh scan : ' + added.join(', '));
  if (removed.length) console.error('  only in committed  : ' + removed.join(', '));
  for (const name of changed) {
    const b = before.get(name);
    const a = after.get(name);
    console.error(`  ${name}: ${b.confidence} [${b.methods}] -> ${a.confidence} [${a.methods}]`);
  }
  const lineDiff = committed.split('\n').length - fresh.split('\n').length;
  console.error(`  ${Math.abs(lineDiff)} line(s) differ in length; run: node scripts/gen-sample-cbom.cjs`);
  process.exit(1);
}

main();
