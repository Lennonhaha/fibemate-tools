// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// classifyRisk —— 「新算法值不值得警告」的分级。
//
// 回归 issue #183：分级原先只看 `cryptoProperties.assetType`，而 cbom-scan
// 给每个组件都写 `"algorithm"`，这个字符串不匹配任何 info 分支，于是所有新增
// 算法一律落到 `warning`（exit 2）—— `info`（exit 1）对自产 CBOM 不可达。
//
// 这里钉住的是「按算法语义分级」：primitive 优先，assetType / name 兜底，
// 且 `vulnerable` 永远短路成 critical，`weak` 永远是 warning。
//
// 运行：node --test test/classify-risk.test.cjs

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const DIFF = path.join(ROOT, 'cbom-diff.js');
const NODE = process.execPath;

const component = (name, { level, assetType = 'algorithm', primitive } = {}) => {
  const comp = {
    type: 'cryptographic-asset',
    name,
    'bom-ref': `crypto:${name}`,
    cryptoProperties: {
      assetType,
      algorithmProperties: primitive ? { primitive } : {},
    },
  };
  if (level) {
    comp.properties = [{ name: 'fibemate:quantumSecurity:level', value: level }];
  }
  return comp;
};

const bom = (components) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: { timestamp: '2026-11-15T00:00:00Z' },
  components,
  dependencies: [],
});

function runDiff(before, after) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-classify-'));
  try {
    const a = path.join(dir, 'before.json');
    const b = path.join(dir, 'after.json');
    fs.writeFileSync(a, JSON.stringify(before), 'utf8');
    fs.writeFileSync(b, JSON.stringify(after), 'utf8');
    const r = spawnSync(NODE, [DIFF, a, b, '--json'], { encoding: 'utf8', cwd: ROOT });
    let parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch { /* asserted below */ }
    return { code: r.status, diff: parsed, stderr: r.stderr };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The shape cbom-scan actually emits: assetType "algorithm" for everything.
test('a safe hash added to a scanner-produced BOM is info, not warning (exit 1)', () => {
  const r = runDiff(bom([]), bom([component('SHA3-512', { level: 'safe', primitive: 'hash' })]));
  assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}; stderr=${r.stderr}`);
  assert.strictEqual(r.diff.severity, 'info');
  assert.strictEqual(r.diff.components.added[0].risk, 'info');
});

test('a safe KEM added without a primitive still reads as info through its name', () => {
  const r = runDiff(bom([]), bom([component('ML-KEM-768', { level: 'safe', assetType: 'kem' })]));
  assert.strictEqual(r.code, 1);
  assert.strictEqual(r.diff.components.added[0].risk, 'info');
});

test('a safe signature scheme added is info', () => {
  const r = runDiff(bom([]), bom([component('ML-DSA-65', { level: 'safe', primitive: 'signature' })]));
  assert.strictEqual(r.code, 1);
  assert.strictEqual(r.diff.components.added[0].risk, 'info');
});

test('a weak algorithm added is still a warning (exit 2)', () => {
  const r = runDiff(bom([]), bom([component('SHA-256', { level: 'weak', primitive: 'hash' })]));
  assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
  assert.strictEqual(r.diff.components.added[0].risk, 'warning');
});

test('an ungraded algorithm with the ambiguous pke primitive is a warning', () => {
  const r = runDiff(bom([]), bom([component('Mystery-Cipher', { primitive: 'pke' })]));
  assert.strictEqual(r.code, 2);
  assert.strictEqual(r.diff.components.added[0].risk, 'warning');
});

test('pke alone never buys silence: RSA keeps its vulnerable grading', () => {
  const r = runDiff(bom([]), bom([component('RSA-2048', { level: 'vulnerable', primitive: 'pke' })]));
  assert.strictEqual(r.code, 3);
  assert.strictEqual(r.diff.components.added[0].risk, 'critical');
});

test('a key-agreement primitive stays a warning even when graded safe', () => {
  const r = runDiff(bom([]), bom([component('X25519', { level: 'safe', primitive: 'key-agree' })]));
  assert.strictEqual(r.code, 2);
  assert.strictEqual(r.diff.components.added[0].risk, 'warning');
});

test('safe symmetric ciphers are info, weak ones are not', () => {
  const safe = runDiff(bom([]), bom([component('AES-256', { level: 'safe', primitive: 'block-cipher' })]));
  assert.strictEqual(safe.code, 1);
  const weak = runDiff(bom([]), bom([component('AES-GCM', { level: 'weak', primitive: 'aead' })]));
  assert.strictEqual(weak.code, 2);
});
