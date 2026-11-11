'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Omission semantics for `nistQuantumSecurityLevel`.
//
// CycloneDX issue #1175 (wording in PR #1177) settles that an omitted
// `nistQuantumSecurityLevel` is not an implicit 0. These tests pin the two
// places where this tool could quietly break that: the scanner (must never
// emit the field) and the differ (must never treat omitted and 0 as equal).

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const DIFF = path.join(ROOT, 'cbom-diff.js');
const NODE = process.execPath;

let tmp;

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-omission-'));
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(name, content) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

function scan(args) {
  return spawnSync(NODE, [SCAN, ...args], { encoding: 'utf8' });
}

function diffRun(a, b, extra = []) {
  return spawnSync(NODE, [DIFF, a, b, ...extra], { encoding: 'utf8' });
}

function bom(components, version = 1) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version,
    components,
  };
}

function comp(name, algorithmProperties) {
  return {
    type: 'cryptographic-asset',
    'bom-ref': 'crypto:' + name,
    name,
    cryptoProperties: { assetType: 'algorithm', algorithmProperties },
  };
}

// Every place a field name could appear, without assuming a document shape.
function collectKeys(value, key, hits = []) {
  if (Array.isArray(value)) {
    for (const v of value) collectKeys(v, key, hits);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k === key) hits.push(v);
      collectKeys(v, key, hits);
    }
  }
  return hits;
}

// ---------- scanner ----------

test('scan: 输出里没有任何 nistQuantumSecurityLevel 字段（省略，不是 0）', () => {
  const dir = path.join(tmp, 'src');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'app.js'),
    "const crypto = require('crypto');\ncrypto.createHash('sha256');\ncrypto.createHash('sm3');\n",
    'utf8'
  );
  const r = scan(['--dir', dir, '--spec', '1.7']);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  const doc = JSON.parse(r.stdout);
  assert.ok(doc.components.length > 0, 'fixture should produce at least one component');

  const values = collectKeys(doc.components, 'nistQuantumSecurityLevel');
  assert.deepStrictEqual(values, [], 'the scanner must omit the field rather than assert a category');
  assert.ok(!/"nistQuantumSecurityLevel"\s*:/.test(r.stdout), 'raw output must not contain the key');
});

test('scan: 每个 BOM 都带一条机器可读的语义说明', () => {
  const dir = path.join(tmp, 'src2');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'app.js'), "const c = require('crypto'); c.createHash('sha256');\n", 'utf8');
  const doc = JSON.parse(scan(['--dir', dir, '--spec', '1.7']).stdout);
  const note = (doc.properties || []).find((p) => p.name === 'fibemate:nistQuantumSecurityLevel:semantics');
  assert.ok(note, 'missing semantics property');
  assert.strictEqual(note.value, 'omitted means unknown/unassessed, never 0');
});

// ---------- differ ----------

test('diff: 省略 → 显式 0 是一次变更，标注 <absent>，exit 1', () => {
  const a = write('abs-a.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash' })])));
  const b = write('abs-b.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash', nistQuantumSecurityLevel: 0 })], 2)));
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 1, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('nistQuantumSecurityLevel'), r.stdout);
  assert.ok(r.stdout.includes('`<absent>` → `0`'), 'omission must not be rendered as undefined or as 0');
});

test('diff: 显式 0 → 省略 也是一次变更（方向相反同样成立）', () => {
  const a = write('zero-a.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash', nistQuantumSecurityLevel: 0 })])));
  const b = write('zero-b.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash' })], 2)));
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 1, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('`0` → `<absent>`'), r.stdout);
});

test('diff: 0 → 0 不是变更', () => {
  const mk = (n) => write(n, JSON.stringify(bom([comp('SHA-256', { primitive: 'hash', nistQuantumSecurityLevel: 0 })])));
  const r = diffRun(mk('z0-a.json'), mk('z0-b.json'));
  assert.strictEqual(r.status, 0, `exit=${r.status} stdout=${r.stdout}`);
  assert.ok(r.stdout.includes('✅ 无变更'), r.stdout);
});

test('diff: 省略 → 省略 不是变更', () => {
  const mk = (n) => write(n, JSON.stringify(bom([comp('SHA-256', { primitive: 'hash' })])));
  const r = diffRun(mk('ab-a.json'), mk('ab-b.json'));
  assert.strictEqual(r.status, 0, `exit=${r.status} stdout=${r.stdout}`);
  assert.ok(r.stdout.includes('✅ 无变更'), r.stdout);
});

test('diff --json: 省略与 0 的差异保留为结构化事件，不被折叠', () => {
  const a = write('j-a.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash' })])));
  const b = write('j-b.json', JSON.stringify(bom([comp('SHA-256', { primitive: 'hash', nistQuantumSecurityLevel: 0 })], 2)));
  const r = diffRun(a, b, ['--json']);
  assert.strictEqual(r.status, 1, `exit=${r.status} stderr=${r.stderr}`);
  const d = JSON.parse(r.stdout);
  const entry = d.components.changed.find((c) => c.name === 'SHA-256');
  assert.ok(entry, 'expected a changed entry');
  const change = entry.changes.find((c) => c.field === 'nistQuantumSecurityLevel');
  assert.ok(change, 'expected the field to be reported');
  assert.strictEqual(change.new, 0);
  assert.ok(!('old' in change) || change.old === undefined, 'absence must not be materialised as a value');
});
