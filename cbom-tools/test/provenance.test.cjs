// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Provenance merge policy tests — verify detection-origin merge/separate
// logic per Issue #55 and José's clarifications.
//
// Run: node --test test/provenance.test.cjs

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const SCAN = path.join(__dirname, '..', 'cbom-scan.cjs');
const FIX = path.join(__dirname, 'fixtures');

function scan(fixtureName) {
  const dir = path.join(FIX, fixtureName);
  const r = spawnSync('node', [SCAN, '--dir', dir], { encoding: 'utf8' });
  assert.equal(r.status, 0, `exit=${r.status} stderr=${(r.stderr || '').slice(0, 200)}`);
  return JSON.parse(r.stdout);
}

function byName(bom, name) {
  return bom.components.find(c => c.name === name);
}

// ────────────────────────────────────────────────────────────────────
// generic dep + generic source (same family) → merge
// ────────────────────────────────────────────────────────────────────

test('generic-merge: same-family dep+source → merge with 2 methods', () => {
  const bom = scan('provenance-generic-merge');

  // ML-DSA: dep (@noble/post-quantum) + source (ml-dsa) → merge
  const mlDsa = byName(bom, 'ML-DSA');
  assert.ok(mlDsa, 'ML-DSA component present');
  assert.equal(mlDsa.evidence.identity.length, 1,
    'single identity');
  assert.equal(mlDsa.evidence.identity[0].methods.length, 2,
    'two methods (manifest + source)');

  const techs = mlDsa.evidence.identity[0].methods.map(m => m.technique).sort();
  assert.deepEqual(techs, ['manifest-analysis', 'source-code-analysis'],
    'both detection origins preserved');

  // ML-KEM: dep only → 1 method
  const mlKem = byName(bom, 'ML-KEM');
  assert.ok(mlKem, 'ML-KEM component present');
  assert.equal(mlKem.evidence.identity[0].methods.length, 1);
  assert.equal(mlKem.evidence.identity[0].methods[0].technique, 'manifest-analysis');

  // SLH-DSA: dep only → 1 method
  const slh = byName(bom, 'SLH-DSA');
  assert.ok(slh, 'SLH-DSA component present');
  assert.equal(slh.evidence.identity[0].methods.length, 1);
});

// ────────────────────────────────────────────────────────────────────
// generic dep + specific source → separate (different names)
// ────────────────────────────────────────────────────────────────────

test('generic-vs-specific-separate: different names stay separate', () => {
  const bom = scan('provenance-generic-vs-specific-separate');

  // Expect: ML-DSA (dep), ML-KEM (dep), SLH-DSA (dep),
  //         ML-DSA-65 (src), ML-DSA-87 (src)
  assert.equal(bom.components.length, 5, '5 separate components');

  // ML-DSA from dep only
  const mlDsa = byName(bom, 'ML-DSA');
  assert.ok(mlDsa);
  assert.equal(mlDsa.evidence.identity[0].methods.length, 1);
  assert.equal(mlDsa.evidence.identity[0].methods[0].technique, 'manifest-analysis');

  // ML-DSA-65 from source only (ml-dsa-65 marker)
  const mlDsa65 = byName(bom, 'ML-DSA-65');
  assert.ok(mlDsa65);
  assert.equal(mlDsa65.evidence.identity[0].methods.length, 1);
  assert.equal(mlDsa65.evidence.identity[0].methods[0].technique, 'source-code-analysis');

  // ML-DSA-87 from source only (ml-dsa-87 marker)
  const mlDsa87 = byName(bom, 'ML-DSA-87');
  assert.ok(mlDsa87);
  assert.equal(mlDsa87.evidence.identity[0].methods.length, 1);

  // No generic ML-DSA from source — dedup removes it at the
  // (src.js, line 1) position where specific markers fired
  const mlDsaOccs = mlDsa.evidence.occurrences || [];
  const srcOcc = mlDsaOccs.find(o => o.location.endsWith('src.js'));
  assert.equal(srcOcc, undefined,
    'generic ML-DSA source occurrence deduped away from (src.js, line 1)');
});

// ────────────────────────────────────────────────────────────────────
// keccak family: dep Keccak + source Keccak → merge
// ────────────────────────────────────────────────────────────────────

test('keccak-family: dep+source same name → merge', () => {
  const bom = scan('provenance-keccak-family');

  const keccak = byName(bom, 'Keccak');
  assert.ok(keccak, 'Keccak component present');
  assert.equal(keccak.evidence.identity.length, 1);
  assert.equal(keccak.evidence.identity[0].methods.length, 2);
  const techs = keccak.evidence.identity[0].methods.map(m => m.technique).sort();
  assert.deepEqual(techs, ['manifest-analysis', 'source-code-analysis']);

  // Name-level confidence = max of method confidences
  const identityConf = keccak.evidence.identity[0].confidence;
  assert.ok(typeof identityConf === 'number', 'identity confidence present');
});

// ────────────────────────────────────────────────────────────────────
// specific dep + specific source (same name) → merge with both origins
// ────────────────────────────────────────────────────────────────────

test('specific-merge: genuinely specific records merge preserving origins', () => {
  const bom = scan('provenance-specific-merge');

  // Single component
  assert.equal(bom.components.length, 1, 'exactly one component');

  const k256 = byName(bom, 'Keccak-256');
  assert.ok(k256, 'Keccak-256 present');

  // One identity with two methods
  assert.equal(k256.evidence.identity.length, 1);
  assert.equal(k256.evidence.identity[0].methods.length, 2);
  assert.equal(k256.evidence.identity[0].concludedValue, 'Keccak-256');

  const techs = k256.evidence.identity[0].methods.map(m => m.technique).sort();
  assert.deepEqual(techs, ['manifest-analysis', 'source-code-analysis'],
    'both detection origins preserved');

  // Occurrences from both origins
  assert.ok(k256.evidence.occurrences.length >= 2,
    `at least 2 occurrences, got ${k256.evidence.occurrences.length}`);
  const locs = k256.evidence.occurrences.map(o => o.location).sort();
  assert.ok(locs.includes('package.json'),
    'package.json occurrence');
  assert.ok(locs.some(l => l.endsWith('src.js')),
    'src.js occurrence');

  // identity.confidence = max method confidence
  const identityConf = k256.evidence.identity[0].confidence;
  const methodConfs = k256.evidence.identity[0].methods.map(m => m.confidence);
  assert.equal(identityConf, Math.max(...methodConfs),
    'identity confidence = max of method confidences');
});

// ────────────────────────────────────────────────────────────────────
// same-line, independent markers: span-based dedup preserves both
// ────────────────────────────────────────────────────────────────────

test('same-line-two-markers: independent generic+specific on one line', () => {
  const bom = scan('provenance-same-line-two-markers');

  // Both ML-DSA and ML-DSA-65 should survive (different spans)
  const mlDsa = byName(bom, 'ML-DSA');
  assert.ok(mlDsa, 'ML-DSA present (independent marker)');
  const mlDsa65 = byName(bom, 'ML-DSA-65');
  assert.ok(mlDsa65, 'ML-DSA-65 present (independent marker)');

  // Each from source only (no deps)
  assert.equal(mlDsa.evidence.identity[0].methods.length, 1,
    'ML-DSA from source only');
  assert.equal(mlDsa.evidence.identity[0].methods[0].technique,
    'source-code-analysis');
  assert.equal(mlDsa65.evidence.identity[0].methods.length, 1,
    'ML-DSA-65 from source only');

  // Both have exactly one source occurrence
  assert.equal(mlDsa.evidence.occurrences.length, 1,
    'ML-DSA has 1 occurrence');
  assert.equal(mlDsa65.evidence.occurrences.length, 1,
    'ML-DSA-65 has 1 occurrence');
});

// ────────────────────────────────────────────────────────────────────
// multi-dep-origin: same algorithm from different packages → all preserved
// ────────────────────────────────────────────────────────────────────

test('multi-dep-origin: SM2 from sm-crypto+sm2-crypto → 2 methods', () => {
  const bom = scan('provenance-multi-dep-origin');

  // Single SM2 component
  const sm2 = byName(bom, 'SM2');
  assert.ok(sm2, 'SM2 present');

  // One identity with 2 manifest-analysis methods (different origins)
  assert.equal(sm2.evidence.identity.length, 1);
  assert.equal(sm2.evidence.identity[0].methods.length, 2,
    'two manifest-analysis methods from two packages');

  const values = sm2.evidence.identity[0].methods
    .filter(m => m.technique === 'manifest-analysis')
    .map(m => m.value)
    .sort();
  assert.deepEqual(values, ['sm-crypto', 'sm2-crypto'],
    'both package origins preserved');

  // Two package.json occurrences
  const pkgOccs = sm2.evidence.occurrences.filter(o => o.location === 'package.json');
  assert.equal(pkgOccs.length, 2,
    'two package.json occurrences from two dep origins');
  const symbols = pkgOccs.map(o => o.symbol).sort();
  assert.deepEqual(symbols, ['sm-crypto', 'sm2-crypto']);

  // No line field on manifest occurrences
  for (const o of pkgOccs) {
    assert.equal(o.line, undefined,
      'manifest occurrence should not have hardcoded line');
  }
});