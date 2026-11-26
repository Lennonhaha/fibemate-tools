'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// 调用点参数是**逐字符读**出来的，不是正则匹配出来的。
//
// `.createCipheriv('aes-256-gcm', key, iv)` 的接收者可以是别名、解构、包装对象，
// 唯一稳定的信息是第一个参数。此前的写法用
//   /\.createCipheriv\(\s*['"][^'"]{0,64}aes[^'"]{0,64}gcm[^'"]{0,64}['"]/
// 把边界从「无界」改成「{0,64}」——那只让扫描器闭嘴，回溯结构还在。现在换成
// 手写走字符：读到引号就交给 readQuoted 显式处理转义，读不到闭合引号就地放弃。
//
// 这里同时钉住两件事：
//   1. 正例仍被发现（别名接收者也算）。
//   2. 病态输入是线性时间，不会把 CI 拖死；且在给定的时间预算内必须返回。

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { collectCipherCallSites } = require('../cbom-scan.cjs');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const NODE = process.execPath;

function scanDir(dir) {
  return spawnSync(NODE, [SCAN, '--dir', dir], { encoding: 'utf-8' });
}

function withDir(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-callsite-'));
  try {
    for (const [name, body] of Object.entries(files)) {
      const full = path.join(dir, name);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, body, 'utf-8');
    }
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function algorithms(dir) {
  const r = scanDir(dir);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(!/TypeError|RangeError/.test(r.stderr), '不应出现未捕获异常');
  return JSON.parse(r.stdout).components.map((c) => c.name);
}

// ---------- 正例：接收者不可见，参数可见 ----------

test('aliased receiver: c.createCipheriv("aes-256-gcm", ...) is still AES-GCM', () => {
  withDir(
    {
      'wrap.js': [
        "const c = require('crypto');",
        "function enc(k, iv, data) { const x = c.createCipheriv('aes-256-gcm', k, iv); return x.update(data); }",
        'module.exports = enc;',
      ].join('\n'),
    },
    (dir) => assert.ok(algorithms(dir).includes('AES-GCM'), 'AES-GCM 应被发现'),
  );
});

test('destructured import: createCipheriv(...) with no receiver is still AES-GCM', () => {
  withDir(
    {
      'destructured.js': [
        "const { createCipheriv } = require('crypto');",
        "const cipher = createCipheriv('AES-128-GCM', key, iv);",
      ].join('\n'),
    },
    (dir) => assert.ok(algorithms(dir).includes('AES-GCM')),
  );
});

test('whitespace and newline between the paren and the argument are tolerated', () => {
  withDir(
    {
      'split.js': "const c = require('crypto');\nconst x = c.createCipheriv(\n  'aes-192-gcm',\n  k,\n  iv\n);\n",
    },
    (dir) => assert.ok(algorithms(dir).includes('AES-GCM')),
  );
});

// ---------- 负例：静态分析的边界，写出来而不是假装不存在 ----------

// ---------- 模式覆盖：GCM 之外的五种经典模式 ----------
// 0.3.2 及以前，调用点收集器只接受 gcm，其余模式被静默丢弃，输出名还被
// 无条件写成 AES-GCM。结果是「用 aes-256-cbc 加密的仓库被报成没有 AES」——
// 正是本工具要防的假清白。下列用例把每种模式都钉在调用点路径上。

for (const [literal, expected] of [
  ['aes-256-cbc', 'AES-CBC'],
  ['aes-128-cbc', 'AES-CBC'],
  ['aes-256-ctr', 'AES-CTR'],
  ['aes-192-cfb', 'AES-CFB'],
  ['aes-128-ofb', 'AES-OFB'],
  ['aes-256-ecb', 'AES-ECB'],
]) {
  test(`call site: createCipheriv('${literal}') is ${expected}, not AES-GCM`, () => {
    withDir(
      { 'm.js': `const c = require('crypto');\nconst x = c.createCipheriv('${literal}', k, iv);\n` },
      (dir) => {
        const names = algorithms(dir);
        assert.ok(names.includes(expected), `${literal} 应被发现为 ${expected}`);
        assert.ok(!names.includes('AES-GCM'), `${literal} 不应被误报为 AES-GCM`);
      },
    );
  });
}

test('uppercase and separator-less spellings resolve to one AES-CBC component', () => {
  withDir(
    { 'u.js': "const c = require('crypto');\nc.createCipheriv('AES-256-CBC', k, iv);\nc.createCipheriv('aes256cbc', k, iv);\n" },
    (dir) => {
      const aesNames = algorithms(dir).filter((n) => /^AES/i.test(n)).sort();
      assert.deepStrictEqual(aesNames, ['AES-CBC'], '两种写法应归一到同一个组件名');
    },
  );
});

test('a bare mode identifier outside a call site is reported too', () => {
  withDir(
    { 'config.js': "module.exports = { cipher: 'aes-256-cbc' };\n" },
    (dir) => assert.ok(algorithms(dir).includes('AES-CBC')),
  );
});

test('metadata for the classic modes carries a primitive, not a bare name', () => {
  withDir(
    { 'm.js': "const c = require('crypto');\nc.createCipheriv('aes-256-cbc', k, iv);\n" },
    (dir) => {
      const r = scanDir(dir);
      assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
      const comp = JSON.parse(r.stdout).components.find((c) => c.name === 'AES-CBC');
      assert.ok(comp, 'AES-CBC 组件应存在');
      assert.strictEqual(comp.cryptoProperties.algorithmProperties.primitive, 'block-cipher');
    },
  );
});

test('computed algorithm name is NOT reported, and that is documented', () => {
  withDir(
    { 'computed.js': "const c = require('crypto');\nconst ALGO = process.env.ALGO;\nc.createCipheriv(ALGO, k, iv);\n" },
    (dir) => assert.ok(!algorithms(dir).includes('AES-GCM'), '变量名不应被猜出来'),
  );
});

test('a non-AES-GCM cipher argument is not mislabelled as AES-GCM', () => {
  withDir(
    { 'other.js': "const c = require('crypto');\nc.createCipheriv('chacha20-poly1305', k, iv);\n" },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(!names.includes('AES-GCM'), 'AES-GCM 不应误报');
    },
  );
});

// ---------- ReDoS：病态输入必须线性收场 ----------

test('unterminated literal at every call site terminates in linear time', () => {
  // 5,000 个调用点，每个都缺闭合引号。这正是回溯型正则会指数爆炸的输入。
  const body = "const c = require('crypto');\n" + "c.createCipheriv('aes-256-gcm\n".repeat(5000);
  const started = Date.now();
  const found = collectCipherCallSites(body);
  const elapsed = Date.now() - started;
  assert.deepStrictEqual(found, [], '未闭合的字面量不应产出命中');
  assert.ok(elapsed < 2000, `线性扫描应在 2s 内完成，实测 ${elapsed}ms`);
});

test('pathological quote soup stays linear across the whole CLI scan', () => {
  // 大量引号 + 半截调用，混在一起喂给完整扫描路径（含 deriveLiterals）。
  const junk = "'\"`".repeat(20000) + '\n' + "c.createCipheriv('aes".repeat(2000) + '\n';
  withDir({ 'junk.js': junk }, (dir) => {
    const started = Date.now();
    const r = scanDir(dir);
    const elapsed = Date.now() - started;
    assert.strictEqual(r.status, 0, `exit=${r.status}`);
    assert.ok(elapsed < 20000, `完整扫描应在 20s 内结束，实测 ${elapsed}ms`);
  });
});

test('no bounded-quantifier cipher rule remains in the source', () => {
  const src = fs.readFileSync(path.join(ROOT, 'cbom-scan.cjs'), 'utf-8');
  assert.ok(!/createCipheriv\(\\s\*\[/.test(src), 'DEFAULT_RULES 里不应再有 createCipheriv 正则');
  assert.ok(src.includes('collectCipherCallSites'), '应走词法扫描');
});
