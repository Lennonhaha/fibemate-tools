'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cli.cjs 是 npm 包里 `npx cbom-tools` 指向的入口，此前**没有任何测试跑过它**：
// 全套用例都在直接调 cbom-scan.cjs / cbom-diff.js，入口的分发、用法、版本、
// 未知命令与子进程退出码全在覆盖之外。这里把它当对外契约测。

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli.cjs');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'));

let tmp;

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cli-dispatch-'));
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf-8' });
}

test('无参数：打印用法并 exit 0', () => {
  const r = run([]);
  assert.strictEqual(r.status, 0, `exit=${r.status}`);
  assert.ok(r.stdout.includes('Usage:'), `stdout=${r.stdout.slice(0, 120)}`);
  assert.ok(r.stdout.includes('cbom-tools scan'), '用法里要给出 scan 子命令');
});

test('--help / -h / help：均为 exit 0', () => {
  for (const flag of ['--help', '-h', 'help']) {
    const r = run([flag]);
    assert.strictEqual(r.status, 0, `${flag} exit=${r.status}`);
    assert.ok(r.stdout.includes('cbom-tools diff'), `${flag} 用法不完整`);
  }
});

test('--version / -v / version：打印 package.json 里的版本', () => {
  for (const flag of ['--version', '-v', 'version']) {
    const r = run([flag]);
    assert.strictEqual(r.status, 0, `${flag} exit=${r.status}`);
    assert.strictEqual(r.stdout.trim(), `cbom-tools ${PKG.version}`);
  }
});

test('未知子命令：exit 2，报错并给用法，不抛栈', () => {
  const r = run(['frobnicate']);
  assert.strictEqual(r.status, 2, `exit=${r.status}`);
  assert.ok(r.stderr.includes('unknown command'), `stderr=${r.stderr.slice(0, 120)}`);
  assert.ok(r.stdout.includes('Usage:'), '仍应给出用法');
  assert.ok(!r.stderr.includes('TypeError'), '不应有未捕获异常');
});

test('scan 透传：退出码与 stdout 原样来自 cbom-scan', () => {
  const dir = path.join(tmp, 'proj');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'a.js'), "const c = require('crypto');\nc.createHash('sha-256');\n");
  const r = run(['scan', '--dir', dir]);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  const bom = JSON.parse(r.stdout);
  assert.deepStrictEqual(bom.components.map((c) => c.name), ['SHA-256']);
});

test('scan 透传：子命令的失败退出码不得被吞掉（不存在目录 → 2）', () => {
  const r = run(['scan', '--dir', path.join(tmp, 'nope')]);
  assert.strictEqual(r.status, 2, `exit=${r.status}`);
  assert.ok(r.stderr.includes('--dir not found'));
});

test('diff 透传：相同输入 exit 0', () => {
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    version: 1,
    components: [{ type: 'cryptographic-asset', name: 'SHA-256', 'bom-ref': 'crypto:SHA-256' }],
  };
  const a = path.join(tmp, 'a.json');
  const b = path.join(tmp, 'b.json');
  fs.writeFileSync(a, JSON.stringify(bom));
  fs.writeFileSync(b, JSON.stringify(bom));
  const r = run(['diff', a, b]);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('无变更'), `stdout=${r.stdout.slice(0, 120)}`);
});
