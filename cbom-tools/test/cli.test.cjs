'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// CLI 契约测试 — 以子进程方式运行两个可执行文件，验证「安装后真的能用」：
// 重点是边界输入下不崩（空目录 / 只有依赖 / 只有源码 / 超大目录 / 不可达目录 / 坏参数 / 坏 JSON）。
// 运行：npm test（即 node --test test/，零外部依赖，Node >= 18 自带 node:test）

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
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cli-test-'));
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ---------- helpers ----------

function scan(args) {
  return spawnSync(NODE, [SCAN, ...args], { encoding: 'utf-8' });
}

function scanDir(dir) {
  const r = scan(['--dir', dir]);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  return JSON.parse(r.stdout);
}

// files: { 相对路径: 内容 }；内容为 null 表示建目录
function mk(name, files) {
  const dir = path.join(tmp, name);
  for (const [rel, content] of files ? Object.entries(files) : []) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    if (content === null) fs.mkdirSync(p, { recursive: true });
    else fs.writeFileSync(p, content);
  }
  return dir;
}

function comp(name, extra = {}) {
  return { type: 'cryptographic-asset', name, 'bom-ref': `crypto:${name}`, ...extra };
}

function writeBom(name, obj) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj));
  return p;
}

function diffRun(a, b, extra = []) {
  return spawnSync(NODE, [DIFF, a, b, ...extra], { encoding: 'utf-8' });
}

// ---------- cbom-scan ----------

test('场景 1 空目录：不崩，输出合法的空 CBOM', () => {
  const dir = mk('empty-dir', null);
  const cbom = scanDir(dir);
  assert.strictEqual(cbom.bomFormat, 'CycloneDX');
  assert.strictEqual(cbom.specVersion, '1.6');
  assert.strictEqual(cbom.version, 1);
  assert.deepStrictEqual(cbom.components, []);
});

test('场景 2 有 package.json 无源码：只走依赖检测，无 occurrences', () => {
  const dir = mk('deps-only', {
    'package.json': JSON.stringify({
      dependencies: { '@noble/post-quantum': '^0.9.0' },
      devDependencies: { 'sm-crypto': '^0.3.0' },
    }),
  });
  const cbom = scanDir(dir);
  assert.deepStrictEqual(
    cbom.components.map(c => c.name),
    ['ML-DSA-65', 'ML-KEM-768', 'SLH-DSA', 'SM2', 'SM3', 'SM4']
  );
  for (const c of cbom.components) {
    assert.strictEqual(c['bom-ref'], `crypto:${c.name}`);
    assert.strictEqual(c.evidence, undefined, '依赖来源不应有 occurrences');
  }
  assert.ok(cbom.components.find(c => c.name === 'ML-KEM-768').cryptoProperties,
    'ML-KEM-768 应通过别名表拿到 cryptoProperties');
});

test('场景 3 有源码无 package.json：只走源码扫描，occurrences 带位置与行号', () => {
  const dir = mk('src-only', {
    'src/index.js': [
      "const crypto = require('crypto');",
      "const smc = require('sm-crypto');",
      "crypto.createHash('sha-256').update('x');",
      '// ML-KEM-768 decapsulation here',
      'module.exports = 1;',
    ].join('\n'),
    'lib/deep/a.cjs': "crypto.createHash('sha3-512');",
  });
  const cbom = scanDir(dir);
  const names = cbom.components.map(c => c.name).sort();
  assert.deepStrictEqual(names, ['ML-KEM', 'SHA-256', 'SHA3-512', 'SM2', 'SM3', 'SM4']);
  const sha = cbom.components.find(c => c.name === 'SHA-256');
  assert.strictEqual(sha.evidence.occurrences[0].location, 'src/index.js');
  assert.strictEqual(sha.evidence.occurrences[0].line, 3);
  const kem = cbom.components.find(c => c.name === 'ML-KEM');
  assert.ok(kem.cryptoProperties, 'ML-KEM 应命中元数据表');
  const s3 = cbom.components.find(c => c.name === 'SHA3-512');
  assert.strictEqual(s3.evidence.occurrences[0].location, 'lib/deep/a.cjs');
});

test('场景 4 超大目录：800 个源文件，命中封顶 50 条，node_modules/.git/点文件被跳过', () => {
  const files = {};
  for (let i = 0; i < 800; i++) {
    files[`pkg/m${i % 40}/f${i}.js`] =
      `// f${i}\nconst crypto = require('crypto');\ncrypto.createHash('sha3-256');\n` + 'x'.repeat(2048);
  }
  files['node_modules/leftpad/index.js'] = "const crypto = require('crypto');\ncrypto.createHash('sha-512');";
  files['.git/hooks/x.js'] = "const crypto = require('crypto');\ncrypto.createHash('sha-512');";
  files['.hidden.js'] = "const crypto = require('crypto');\ncrypto.createHash('sha-512');";
  const dir = mk('big-repo', files);

  const t0 = Date.now();
  const cbom = scanDir(dir);
  const ms = Date.now() - t0;

  assert.deepStrictEqual(cbom.components.map(c => c.name), ['SHA3-256'],
    '跳过目录里的 sha-512 不应出现');
  assert.strictEqual(cbom.components[0].evidence.occurrences.length, 50,
    '单算法 occurrences 应封顶在 MAX_OCC_PER_ALGO=50');
  assert.ok(ms < 15000, `800 文件扫描应在 15s 内完成，实际 ${ms}ms`);
});

test('场景 5 不可达目录：优雅跳过，不崩', () => {
  const dir = mk('unreachable', { 'ok.js': "const crypto = require('crypto');\ncrypto.createHash('sha-256');" });
  if (process.platform === 'win32') {
    // junction 指向不存在的目标，无需管理员权限
    fs.symlinkSync(path.join(dir, 'does-not-exist'), path.join(dir, 'broken-junction'), 'junction');
  } else {
    const sub = path.join(dir, 'locked');
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, 's.js'), "const crypto = require('crypto');\ncrypto.createHash('sha-512');");
    fs.chmodSync(sub, 0o000);
  }
  const cbom = scanDir(dir); // exit 0 即不崩
  assert.ok(cbom.components.some(c => c.name === 'SHA-256'), '可达部分正常产出');
  if (process.platform !== 'win32') {
    assert.ok(!cbom.components.some(c => c.name === 'SHA-512'), '无权限目录应被跳过');
    fs.chmodSync(path.join(dir, 'locked'), 0o755); // 恢复以便清理
  }
});

test('场景 5b --dir 指向不存在的路径：当前契约是优雅输出空 CBOM', () => {
  const cbom = scanDir(path.join(tmp, 'no-such-dir'));
  assert.deepStrictEqual(cbom.components, []);
});

test('参数边界：--dir 缺值 → usage 提示，exit 2，无未捕获堆栈', () => {
  const r = scan(['--dir']);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stderr.includes('usage:'), `stderr=${r.stderr}`);
  assert.ok(!r.stderr.includes('TypeError'), '不应抛未捕获异常');
});

test('--out 写文件并在 stderr 汇报算法数', () => {
  const dir = mk('out-dir', { 'a.js': "const crypto = require('crypto');\ncrypto.createHash('sha-256');" });
  const out = path.join(tmp, 'out-cbom.json');
  const r = scan(['--dir', dir, '--out', out]);
  assert.strictEqual(r.status, 0);
  assert.ok(r.stderr.includes('wrote 1 algorithms'), `stderr=${r.stderr}`);
  assert.strictEqual(JSON.parse(fs.readFileSync(out, 'utf-8')).components.length, 1);
});

// ---------- cbom-diff ----------

test('diff 相同输入：severity none，exit 0', () => {
  const c = [comp('SHA-256', { cryptoProperties: { assetType: 'hash' } })];
  const a = writeBom('same-a.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: c });
  const b = writeBom('same-b.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: c });
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 0, `stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('✅ 无变更'));
});

test('diff 新增 PQC（kem）：info，exit 1', () => {
  const a = writeBom('add-a.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] });
  const b = writeBom('add-b.json', {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 2,
    components: [comp('ML-KEM-768', { cryptoProperties: { assetType: 'kem', algorithmProperties: {} } })],
  });
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 1, `stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('➕ 新增算法'));
  assert.ok(r.stdout.includes('info'));
});

test('diff 新增经典算法（sm2）：warning，exit 2', () => {
  const a = writeBom('ecc-a.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] });
  const b = writeBom('ecc-b.json', {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 2,
    components: [comp('SM2', { cryptoProperties: { assetType: 'sm2', algorithmProperties: {} } })],
  });
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stdout.includes('🟡'));
});

test('diff 删除算法：warning，exit 2', () => {
  const a = writeBom('rm-a.json', {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    components: [comp('SHA-256', { cryptoProperties: { assetType: 'hash' } })],
  });
  const b = writeBom('rm-b.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 2, components: [] });
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stdout.includes('➖ 删除算法'));
});

test('diff 属性变更（classicalSecurityLevel）：info，exit 1，Markdown 列出字段', () => {
  const mk2 = lvl => comp('SHA-256', {
    cryptoProperties: { assetType: 'hash', algorithmProperties: { classicalSecurityLevel: lvl } },
  });
  const a = writeBom('ch-a.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [mk2(128)] });
  const b = writeBom('ch-b.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 2, components: [mk2(256)] });
  const r = diffRun(a, b);
  assert.strictEqual(r.status, 1);
  assert.ok(r.stdout.includes('🔄 属性变更'));
  assert.ok(r.stdout.includes('`classicalSecurityLevel`: `128` → `256`'));
});

test('diff --json：输出可直接 JSON.parse，severity/exitCode 字段一致', () => {
  const a = writeBom('js-a.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] });
  const b = writeBom('js-b.json', {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 2,
    components: [comp('ML-KEM-768', { cryptoProperties: { assetType: 'kem', algorithmProperties: {} } })],
  });
  const r = diffRun(a, b, ['--json']);
  assert.strictEqual(r.status, 1);
  const d = JSON.parse(r.stdout);
  assert.strictEqual(d.severity, 'info');
  assert.strictEqual(d.exitCode, 1);
  assert.strictEqual(d.components.added[0].name, 'ML-KEM-768');
});

test('diff 文件不存在：exit 2 + 明确报错，不抛堆栈', () => {
  const a = writeBom('ok.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] });
  const r = diffRun(path.join(tmp, 'missing.json'), a);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stderr.includes('file not found'), `stderr=${r.stderr}`);
});

test('diff 非法 JSON：exit 2 + 明确报错，不抛堆栈（修复后契约）', () => {
  const a = writeBom('ok2.json', { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] });
  const bad = writeBom('broken.json', '{oops');
  const r = diffRun(bad, a);
  assert.strictEqual(r.status, 2);
  assert.ok(r.stderr.includes('invalid JSON'), `stderr=${r.stderr}`);
  assert.ok(!r.stderr.includes('SyntaxError') || r.stderr.includes('cbom-diff:'), '不应是未捕获异常');
});

test('本仓默认冒烟：无参数运行 cbom-diff（本地 cbom-cyclonedx.json 自比）→ exit 0', () => {
  const r = spawnSync(NODE, [DIFF], { encoding: 'utf-8', cwd: ROOT });
  assert.strictEqual(r.status, 0, `stderr=${r.stderr}`);
  assert.ok(r.stdout.includes('✅ 无变更'));
});

test('场景 6 C++ monocypher 源码：5 处调用对应 5 个算法', () => {
  const dir = mk('cxx-mono', {
    'crypto.cpp': [
      '#include "monocypher.h"',
      'void test(void) {',
      '  crypto_lock(mac, cipher, key, nonce, plain, 32);',
      '  crypto_x25519(shared, sk, pk);',
      '  crypto_sign(sig, sk, msg, 16);',
      '  crypto_blake2b(hash, msg, 16);',
      '  crypto_argon2i(hash, 32, pass, 8, salt, 16, NULL, 0, 3);',
      '}',
    ].join('\n'),
  });
  const cbom = scanDir(dir);
  const names = cbom.components.map(c => c.name).sort();
  assert.deepStrictEqual(names, ['Argon2i', 'Blake2b', 'ChaCha20-Poly1305', 'Ed25519', 'X25519']);
  for (const c of cbom.components) {
    assert.ok(c.evidence, c.name + ' should have evidence');
    assert.strictEqual(c.evidence.occurrences[0].location, 'crypto.cpp');
  }
});
