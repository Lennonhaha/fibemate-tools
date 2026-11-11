'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// 负控制与容错测试 — 两件事：
//
// 1. 负控制（negative control）：算法「表面上看不见」的写法，扫描器仍须报出。
//    每个 fixture 都刻意避开直接调用形态：常量别名、数组拼接、模板插值、
//    base64、十六进制转义、require 拆分、解构导入、Python getattr、C 宏、
//    跨行拼接。这条线防的是「假合规」——代码里明明用了弱算法，SBOM 里却没有。
//
// 2. 容错：坏输入要给出**正确的退出码**，而不是崩溃或静默假绿。
//    不存在的目录曾经返回 exit 0 + 空 CBOM，那在流水线里会被读成
//    「这里没有密码学」——正是本工具要防的假象，现已改为 exit 2。
//
// 边界（诚实声明）：运行时才算出来的名字（env / 网络 / 变量拼接）**看不见**，
// 见最后一个 test 与 README「What a static scan cannot see」。

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { deriveLiterals, decodeEscapes, mergeEvidence } = require('../cbom-scan.cjs');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const NODE = process.execPath;
const EVASION = path.join(__dirname, 'fixtures', 'evasion');

let tmp;

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-evasion-test-'));
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function scan(args) {
  return spawnSync(NODE, [SCAN, ...args], { encoding: 'utf-8' });
}

function names(dir) {
  const r = scan(['--dir', dir]);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(!r.stderr.includes('TypeError'), '不应出现未捕获异常');
  return JSON.parse(r.stdout).components;
}

// ---------- 1. 负控制：十种「藏起来」的写法 ----------

const CASES = [
  ['alias-const', 'AES-GCM', '算法名在常量里，调用点不出现 AES'],
  ['array-join', 'SHA-256', "['sh','a256'].join('')"],
  ['template-interpolation', 'ML-KEM-768', '模板字符串 + 字面量插值'],
  ['base64', 'ML-KEM-768', 'base64 载荷'],
  ['hex-escaped', 'SHA-256', '十六进制转义字面量'],
  ['require-concat', 'SHA-512', "require('cry' + 'pto') + 别名接收者"],
  ['destructure-alias', 'Ed25519', '解构导入 + 曲线名作数据'],
  ['python-getattr', 'SHA-256', 'importlib + getattr 拼接'],
  ['macro-alias', 'SHA-256', 'C 宏重命名（对照组）'],
  ['split-lines', 'ML-KEM-768', '字符串被换行拆开'],
];

for (const [dir, expected, why] of CASES) {
  test(`负控制 ${dir}：${why} → 必须报出 ${expected}`, () => {
    const comps = names(path.join(EVASION, dir));
    const hit = comps.find((c) => c.name === expected);
    assert.ok(hit, `${dir} 未报出 ${expected}，实际 ${comps.map((c) => c.name).join(',') || '(空)'}`);
    const methods = hit.evidence.identity[0].methods.map((m) => m.technique);
    assert.ok(methods.includes('source-code-analysis'), '必须来自源码分析');
    assert.ok(hit.evidence.occurrences.length > 0, '必须带 occurrence');
  });
}

test('边界：运行时才确定的算法名，不声称能看见（README 已声明）', () => {
  const comps = names(path.join(EVASION, 'runtime-computed'));
  assert.deepStrictEqual(comps.map((c) => c.name), [],
    'process.env 里的名字属静态分析的盲区；报出来才是假阳性');
});

// ---------- 2. 字面量还原的单元契约 ----------

test('decodeEscapes：\\x / \\u / 常见转义 / 未知转义都按字面处理', () => {
  assert.strictEqual(decodeEscapes('\\x73\\x68\\x61'), 'sha');
  assert.strictEqual(decodeEscapes('\\u0073\\u0068\\u0061'), 'sha');
  assert.strictEqual(decodeEscapes('a\\nb'), 'a\nb');
  assert.strictEqual(decodeEscapes('a\\zb'), 'azb');
});

test('deriveLiterals：只收可还原的拼接，不把普通字面量当发现', () => {
  const plain = deriveLiterals("const a = 'sha256';");
  assert.deepStrictEqual(plain, [], '普通字面量交给正则直接匹配，不重复上报');

  const concat = deriveLiterals("const a = 'sha' + '256';");
  assert.deepStrictEqual(concat.map((l) => l.text), ['sha256']);

  const split = deriveLiterals("const a = 'ml-kem-' +\n  '768';");
  assert.deepStrictEqual(split.map((l) => l.text), ['ml-kem-768']);

  const joined = deriveLiterals("const a = ['ml', '-kem'].join('');");
  assert.deepStrictEqual(joined.map((l) => l.text), ['ml-kem']);

  const numeric = deriveLiterals("const a = ['1', '2', '3'].join('');");
  assert.deepStrictEqual(numeric, [], '不含字母的拼接不产生候选');
});

test('mergeEvidence：没有元数据的算法名也产出组件，但不编造 cryptoProperties', () => {
  const comps = mergeEvidence(new Map(), new Map([
    ['Made-Up-Alg', [{ location: 'x.js', line: 3, symbol: 'Made-Up-Alg', span: { start: 0, end: 11 } }]],
  ]));
  assert.strictEqual(comps.length, 1);
  assert.strictEqual(comps[0].name, 'Made-Up-Alg');
  assert.strictEqual(comps[0].cryptoProperties, undefined, '无元数据时不得虚构资产属性');
  assert.strictEqual(comps[0].evidence.occurrences[0].line, 3);
});

// ---------- 3. 容错：坏输入的正确退出码 ----------

test('容错：--dir 不存在 → exit 2，不静默产出空 CBOM', () => {
  const r = scan(['--dir', path.join(tmp, 'no-such-dir')]);
  assert.strictEqual(r.status, 2, `exit=${r.status}`);
  assert.ok(r.stderr.includes('--dir not found'), `stderr=${r.stderr}`);
  assert.strictEqual(r.stdout.trim(), '', '不得输出看起来合法的空 CBOM');
});

test('容错：--dir 指向文件而不是目录 → exit 2', () => {
  const f = path.join(tmp, 'not-a-dir.js');
  fs.writeFileSync(f, "const x = require('crypto');\n");
  const r = scan(['--dir', f]);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stderr.includes('not a directory'), `stderr=${r.stderr}`);
});

test('容错：超大文件跳过并告警，同目录其它文件照常产出', () => {
  const dir = path.join(tmp, 'huge');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'small.js'), "const c = require('crypto');\nc.createHash('sha-256');\n");
  fs.writeFileSync(path.join(dir, 'bundle.js'), '/*' + 'x'.repeat(8 * 1024 * 1024 + 1024) + '*/\n');
  const r = scan(['--dir', dir]);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(r.stderr.includes('exceeds'), `应有跳过告警，stderr=${r.stderr.slice(0, 200)}`);
  const bom = JSON.parse(r.stdout);
  assert.deepStrictEqual(bom.components.map((c) => c.name), ['SHA-256']);
});

test('容错：package.json 是畸形 JSON → 告警但继续扫源码', () => {
  const dir = path.join(tmp, 'bad-manifest');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "dependencies": { broken');
  fs.writeFileSync(path.join(dir, 'a.js'), "const c = require('crypto');\nc.createHash('sha-512');\n");
  const r = scan(['--dir', dir]);
  assert.strictEqual(r.status, 0, `exit=${r.status}`);
  assert.ok(r.stderr.includes('cannot parse'), `stderr=${r.stderr.slice(0, 200)}`);
  assert.deepStrictEqual(JSON.parse(r.stdout).components.map((c) => c.name), ['SHA-512']);
});

test('容错：不可读文件跳过并告警，其余文件不受影响', (t) => {
  if (process.platform === 'win32') {
    t.skip('Windows 的 chmod 只改只读位，不阻止读取；该路径由 Linux CI 覆盖');
    return;
  }
  const dir = path.join(tmp, 'unreadable');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'ok.js'), "const c = require('crypto');\nc.createHash('sha-256');\n");
  const secret = path.join(dir, 'secret.js');
  fs.writeFileSync(secret, "const c = require('crypto');\nc.createHash('sha-512');\n");
  fs.chmodSync(secret, 0o000);
  try {
    const r = scan(['--dir', dir]);
    assert.strictEqual(r.status, 0, `exit=${r.status}`);
    assert.ok(r.stderr.includes('skipped'), `stderr=${r.stderr.slice(0, 200)}`);
    assert.deepStrictEqual(JSON.parse(r.stdout).components.map((c) => c.name), ['SHA-256']);
  } finally {
    fs.chmodSync(secret, 0o644);
  }
});
