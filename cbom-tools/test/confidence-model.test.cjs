// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// ADR-0001: confidence is a claim about how the name was established, not
// about how specific the name is. `params` drives absorption and nothing else.
//
// The last test is the point of the change: mutating `params` must not move a
// single confidence value. Without it, someone can reinstate the old coupling
// and every other test here still passes.
//
// Run: node --test test/confidence-model.test.cjs

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { CONFIDENCE, mergeEvidence } = require('../cbom-scan.cjs');
const { HIERARCHY } = require('../algorithm-hierarchy.cjs');

const ROOT = path.join(__dirname, '..');

function identityOf(components, name) {
  const c = components.find((x) => x.name === name);
  assert.ok(c, `${name} component present`);
  return c.evidence.identity[0];
}

function merge(deps, source) {
  // deps: { algo: pkg } -> the shape matchDeps produces
  const fromDeps = new Map();
  for (const [algo, pkg] of Object.entries(deps)) {
    fromDeps.set(algo, { origins: [{ pkgName: pkg, confidence: CONFIDENCE['manifest-analysis'] }] });
  }
  const fromSource = new Map();
  for (const [algo, symbol] of Object.entries(source)) {
    fromSource.set(algo, [{ location: 'src/x.js', line: 1, symbol, span: { start: 0, end: 1 } }]);
  }
  return mergeEvidence(fromDeps, fromSource, new Map());
}

test('technique names are the ones CycloneDX 1.6 and 1.7 enumerate', () => {
  for (const file of ['test/fixtures/bom-1.6.schema.json', 'test/fixtures/bom-1.7.schema.json']) {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, file), 'utf8'));
    const enumValues = schema.definitions.componentIdentityEvidence
      .properties.methods.items.properties.technique.enum;
    for (const technique of Object.keys(CONFIDENCE)) {
      assert.ok(
        enumValues.includes(technique),
        `${file}: "${technique}" is not in the technique enum (${enumValues.slice(0, 4).join(', ')}...)`,
      );
    }
  }
});

test('manifest-only component concludes 0.7', () => {
  const comps = merge({ 'SLH-DSA': '@noble/post-quantum' }, {});
  const id = identityOf(comps, 'SLH-DSA');
  assert.equal(id.confidence, 0.7);
  assert.equal(id.methods.length, 1);
  assert.equal(id.methods[0].technique, 'manifest-analysis');
});

test('source hit on a family-level name (params: null) concludes 0.9', () => {
  // ML-KEM is `params: null` and is the case the old model scored 0.7.
  assert.equal(HIERARCHY['ML-KEM'].params, null, 'precondition: ML-KEM is family-level');
  const comps = merge({}, { 'ML-KEM': 'ml_kem768' });
  const id = identityOf(comps, 'ML-KEM');
  assert.equal(id.confidence, 0.9);
  assert.equal(id.methods[0].technique, 'source-code-analysis');
});

test('manifest + source merges into one identity at 0.9 with both methods', () => {
  const comps = merge({ 'ML-KEM': '@noble/post-quantum' }, { 'ML-KEM': 'ml_kem768' });
  const id = identityOf(comps, 'ML-KEM');
  assert.equal(id.confidence, 0.9, 'identity confidence is the max of its methods');
  assert.deepEqual(
    id.methods.map((m) => `${m.technique}=${m.confidence}`).sort(),
    ['manifest-analysis=0.7', 'source-code-analysis=0.9'],
  );
});

test('identity confidence always equals the maximum of its methods', () => {
  const comps = merge(
    { 'ML-DSA': '@noble/post-quantum', Keccak: '@noble/hashes' },
    { 'ML-DSA': 'ml_dsa_65', 'SHA-256': 'sha256' },
  );
  for (const c of comps) {
    const id = c.evidence.identity[0];
    const max = Math.max(...id.methods.map((m) => m.confidence));
    assert.equal(id.confidence, max, `${c.name}: identity confidence is not max(methods)`);
  }
});

test('no scoring path reads HIERARCHY[...].params', () => {
  // Static assertion on the source: the ternary is what ADR-0001 removed, and
  // a behavioural test alone would not catch a future call site.
  const src = fs.readFileSync(path.join(ROOT, 'cbom-scan.cjs'), 'utf8');
  assert.equal(/params\s*!==\s*null\s*\)?\s*\?\s*0\.9\s*:\s*0\.7/.test(src), false,
    'params must not decide confidence (ADR-0001)');
  assert.ok(src.includes("CONFIDENCE['source-code-analysis']"), 'source confidence comes from the table');
  assert.ok(src.includes("CONFIDENCE['manifest-analysis']"), 'manifest confidence comes from the table');
});

// ── the mutation guard ──────────────────────────────────────────────
//
// Registered last: it temporarily rewrites a dictionary entry.
test('changing params does not move any confidence value', () => {
  const target = 'ML-KEM';
  const original = HIERARCHY[target].params;
  try {
    for (const params of [original, '768', '1024', 'arbitrary']) {
      HIERARCHY[target].params = params;
      const sourceOnly = identityOf(merge({}, { [target]: 'ml_kem768' }), target);
      assert.equal(sourceOnly.confidence, 0.9, `params="${params}" changed a source hit`);
      const merged = identityOf(merge({ [target]: '@noble/post-quantum' }, { [target]: 'ml_kem768' }), target);
      assert.equal(merged.confidence, 0.9, `params="${params}" changed a merged identity`);
      const manifestOnly = identityOf(merge({ [target]: '@noble/post-quantum' }, {}), target);
      assert.equal(manifestOnly.confidence, 0.7, `params="${params}" changed a manifest-only identity`);
    }
  } finally {
    HIERARCHY[target].params = original;
  }
  assert.equal(HIERARCHY[target].params, original, 'dictionary entry restored');
});
