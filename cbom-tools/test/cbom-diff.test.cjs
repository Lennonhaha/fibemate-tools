// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-diff 版本判定测试 —— 回归「缺失被当成 0」的缺陷。
//
// CycloneDX 的 `bom.version` 可选，schema 为 { minimum: 1, default: 1 }。
// 因此字段缺失 = 默认 1，既不是 0，也不是「没有版本」。
// 修复前：一侧省略、另一侧写 1 时，会误报 bumped / downgraded（后者尤其糟糕——
// 它会让人以为 CBOM 被回滚了）。
//
// 运行：node --test test/cbom-diff.test.cjs

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const DIFF = path.join(ROOT, 'cbom-diff.js');
const NODE = process.execPath;

function writeBom(dir, name, version) {
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    // `version` intentionally absent when `version === undefined`
    ...(version === undefined ? {} : { version }),
    components: [],
    dependencies: [],
  };
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(bom, null, 2), 'utf8');
  return file;
}

function diffJson(oldVersion, newVersion) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-diff-version-'));
  try {
    const a = writeBom(dir, 'old.json', oldVersion);
    const b = writeBom(dir, 'new.json', newVersion);
    const r = spawnSync(NODE, [DIFF, a, b, '--json'], { encoding: 'utf-8', cwd: ROOT });
    assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${(r.stderr || '').slice(0, 300)}`);
    return JSON.parse(r.stdout);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- 核心回归：省略 ≠ 0 ---

test('both sides omit version → same, and the default 1 is recorded', () => {
  const d = diffJson(undefined, undefined);
  assert.strictEqual(d.version, 'same');
  assert.strictEqual(d.meta.oldVersion, 1);
  assert.strictEqual(d.meta.newVersion, 1);
  assert.strictEqual(d.meta.oldVersionExplicit, false);
  assert.strictEqual(d.meta.newVersionExplicit, false);
});

test('old omits version, new writes 1 → same (was "bumped" before the fix)', () => {
  const d = diffJson(undefined, 1);
  assert.strictEqual(d.version, 'same');
  assert.strictEqual(d.meta.oldVersionExplicit, false);
  assert.strictEqual(d.meta.newVersionExplicit, true);
});

test('old writes 1, new omits version → same (was "downgraded" before the fix)', () => {
  const d = diffJson(1, undefined);
  assert.strictEqual(d.version, 'same');
});

// --- 真实版本变化仍然要报出来 ---

test('old omits version, new writes 2 → bumped', () => {
  const d = diffJson(undefined, 2);
  assert.strictEqual(d.version, 'bumped');
  assert.strictEqual(d.meta.oldVersion, 1);
  assert.strictEqual(d.meta.newVersion, 2);
});

test('explicit 3 → explicit 2 → downgraded', () => {
  const d = diffJson(3, 2);
  assert.strictEqual(d.version, 'downgraded');
});

test('explicit 1 → explicit 2 → bumped', () => {
  const d = diffJson(1, 2);
  assert.strictEqual(d.version, 'bumped');
});

// --- schema 非法值：不静默排序 ---

test('version 0 is schema-invalid (minimum 1) → reported as unknown, with a note', () => {
  const d = diffJson(undefined, 0);
  assert.strictEqual(d.version, 'unknown');
  assert.strictEqual(d.meta.newVersionExplicit, true);
  assert.ok(
    d.meta.versionNotes.some((n) => n.startsWith('new:')),
    `expected a note about the new version, got ${JSON.stringify(d.meta.versionNotes)}`
  );
});
