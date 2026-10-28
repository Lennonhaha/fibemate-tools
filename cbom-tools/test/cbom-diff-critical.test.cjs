// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-diff exit 3 —— 回到 issue #43：代码里有 `diff.exitCode = 3`，但
// `classifyRisk()` 永远不返回 'critical'，所以 3 从来不可达。
//
// 另一个没人写下来的原因：量子等级根本不在 `cryptoProperties` 里。cbom-scan
// 把它写成 `properties[].name === 'fibemate:quantumSecurity:level'`，所以只改
// `classifyRisk` 的返回分支仍然读不到值。这里两件事都测。
//
// 语义取 #43 的「方案 2」：仅当同时有 before 才能说「新引入」，所以单份 CBOM
// 永远不出 3（那条路径标 info），否则首次扫描就会把历史债务变成红门禁。
//
// 运行：node --test test/cbom-diff-critical.test.cjs

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const DIFF = path.join(ROOT, 'cbom-diff.js');
const NODE = process.execPath;

const component = (name, { level, assetType = 'algorithm', viaCryptoProp = false, brokenProp = false } = {}) => {
  const comp = {
    type: 'cryptographic-asset',
    name,
    'bom-ref': `crypto:${name}`,
    cryptoProperties: { assetType, algorithmProperties: { primitive: 'pke' } },
  };
  if (level && viaCryptoProp) comp.cryptoProperties.quantumSecurity = { level };
  if (level && !viaCryptoProp) {
    comp.properties = [{ name: 'fibemate:quantumSecurity:level', value: level }];
  }
  if (brokenProp) comp.properties = [{ name: 'fibemate:quantumSecurity:level' }];
  return comp;
};

const bom = (components) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: { timestamp: '2026-10-28T00:00:00Z' },
  components,
  dependencies: [],
});

function runDiff(oldBom, newBom) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-diff-critical-'));
  try {
    const oldFile = path.join(dir, 'before.json');
    const newFile = path.join(dir, 'after.json');
    fs.writeFileSync(oldFile, JSON.stringify(oldBom), 'utf8');
    fs.writeFileSync(newFile, JSON.stringify(newBom), 'utf8');
    const res = spawnSync(NODE, [DIFF, oldFile, newFile, '--json'], { encoding: 'utf8' });
    let parsed = null;
    try { parsed = JSON.parse(res.stdout); } catch { /* leave null, asserted below */ }
    return { code: res.status, stdout: res.stdout, stderr: res.stderr, diff: parsed };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('exit 3 becomes reachable: a vulnerable algorithm is newly introduced', () => {
  const before = bom([component('AES-256', { level: 'safe', assetType: 'block-cipher' })]);
  const after = bom([
    component('AES-256', { level: 'safe', assetType: 'block-cipher' }),
    component('RSA-2048', { level: 'vulnerable', assetType: 'algorithm' }),
  ]);
  const r = runDiff(before, after);
  assert.equal(r.code, 3, `expected exit 3, got ${r.code}; stderr=${r.stderr}`);
  assert.equal(r.diff.severity, 'critical');
  const added = r.diff.components.added.find((c) => c.name === 'RSA-2048');
  assert.ok(added, 'RSA-2048 must appear in added');
  assert.equal(added.risk, 'critical');
});

test('a vulnerable algorithm that was already there is not a regression', () => {
  const before = bom([component('RSA-2048', { level: 'vulnerable' })]);
  const after = bom([
    component('RSA-2048', { level: 'vulnerable' }),
    component('SHA3-512', { level: 'safe', assetType: 'hash' }),
  ]);
  const r = runDiff(before, after);
  assert.notEqual(r.code, 3, 'unchanged vulnerable algorithm must not exit 3');
  assert.notEqual(r.diff.severity, 'critical');
  assert.equal(r.diff.components.added.length, 1);
  assert.equal(r.diff.components.added[0].name, 'SHA3-512');
});

test('removing a vulnerable algorithm is a warning, not exit 3', () => {
  const before = bom([
    component('RSA-2048', { level: 'vulnerable' }),
    component('SHA3-512', { level: 'safe', assetType: 'hash' }),
  ]);
  const after = bom([component('SHA3-512', { level: 'safe', assetType: 'hash' })]);
  const r = runDiff(before, after);
  assert.equal(r.code, 2, `expected exit 2 for removal, got ${r.code}`);
  assert.equal(r.diff.severity, 'warning');
});

test('without a baseline the exit-3 signal stays off', () => {
  const r = runDiff(null, bom([component('RSA-2048', { level: 'vulnerable' })]));
  assert.equal(r.code, 1, `single-CBOM scan should be informational, got ${r.code}`);
  assert.equal(r.diff.severity, 'info');
  assert.equal(r.diff.components.added[0].risk, 'info');
});

test('quantum level is read from component.properties, where the scanner writes it', () => {
  const after = bom([component('SM2', { level: 'vulnerable', assetType: 'algorithm' })]);
  const r = runDiff(bom([]), after);
  assert.equal(r.code, 3, `expected exit 3 for SM2 introduced, got ${r.code}; stderr=${r.stderr}`);
});

test('a hand-written CBOM may put the level under cryptoProperties instead', () => {
  const after = bom([component('P-256', { level: 'vulnerable', viaCryptoProp: true })]);
  const r = runDiff(bom([]), after);
  assert.equal(r.code, 3, `expected exit 3 via cryptoProperties fallback, got ${r.code}`);
});

test('a property without a value is unknown, not critical', () => {
  const after = bom([component('Mystery-Cipher', { level: 'vulnerable', brokenProp: true })]);
  const r = runDiff(bom([]), after);
  assert.notEqual(r.code, 3, 'a malformed property must not be read as vulnerable');
  assert.equal(r.diff.components.added[0].risk, 'warning');
});

test('an unknown level is not inferred from the algorithm name', () => {
  const after = bom([component('RSA-4096', { assetType: 'algorithm' })]);
  const r = runDiff(bom([]), after);
  assert.notEqual(r.code, 3, 'name-matching RSA must not be enough to exit 3');
});
