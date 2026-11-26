'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// AES-CBC 的五种日常写法，2026-11-26 的红测里只命中一种。
//
// 逐形态实测（修复前）：
//   createCipheriv('aes-256-cbc')                  → AES-CBC ✓
//   Cipher.getInstance("AES/CBC/PKCS5Padding")     → []      ✗（.java 不在扫描集）
//   cipher.NewCBCEncrypter(block, iv)              → []      ✗（.go 不在扫描集）
//   AES.MODE_CBC                                   → []      ✗（裸模式名无规则）
//   cipher: AES_CBC（yaml）                         → []      ✗（.yaml 不在扫描集）
//   字面量 'AES-CBC'（.js）                         → []      ✗（规则要求带密钥长度）
//
// 前三层原因分开修：扫描集（扩展名）→ 该语言的调用形状（JCE 斜杠式、
// Go 的 block+mode 分离、PyCryptodome 的 MODE_ 常量）→ 名字归一化
// （AES-CBC / AES_CBC 都落到同一个组件名）。
//
// 这里的负例和正例一样重要：`RSA/ECB/PKCS1Padding` 里的 ECB 是填充方案，
// 不是分组模式；只报 RSA 才是对的。`DES.MODE_CBC` 不是 AES。

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');

function withDir(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-forms-'));
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

function scan(dir) {
  const r = spawnSync(process.execPath, [SCAN, '--dir', dir], { encoding: 'utf-8' });
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  assert.ok(!/TypeError|RangeError/.test(r.stderr), `不应出现未捕获异常: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

function algorithms(dir) {
  return scan(dir).components.map((c) => c.name);
}

// ---------- 正例：同一个算法，五种写法 ----------

test('JCE transformation: Cipher.getInstance("AES/CBC/PKCS5Padding") is AES-CBC', () => {
  withDir(
    {
      'Legacy.java': [
        'import javax.crypto.Cipher;',
        'public class Legacy {',
        '  Cipher c() throws Exception { return Cipher.getInstance("AES/CBC/PKCS5Padding"); }',
        '}',
      ].join('\n'),
    },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('AES-CBC'), `AES-CBC 应被发现，实际 ${names.join(',')}`);
      assert.ok(!names.includes('AES'), 'AES/CBC 不应降级成裸 AES');
    },
  );
});

test('JCE transformation: AES/GCM/NoPadding is AES-GCM, not AES-CBC', () => {
  withDir(
    { 'S.java': 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n' },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('AES-GCM'));
      assert.ok(!names.includes('AES-CBC'));
    },
  );
});

test('JCE transformation with a Chinese family: SM4/CBC is SM4-CBC', () => {
  withDir(
    { 'Gm.java': 'Cipher c = Cipher.getInstance("SM4/CBC/PKCS5Padding");\n' },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('SM4-CBC'), `SM4-CBC 应被发现，实际 ${names.join(',')}`);
    },
  );
});

test('Go: cipher.NewCBCEncrypter next to aes.NewCipher is AES-CBC', () => {
  withDir(
    {
      'main.go': [
        'package main',
        'import ("crypto/aes"; "crypto/cipher")',
        'func enc(key, iv, plain []byte) []byte {',
        '  block, _ := aes.NewCipher(key)',
        '  return cipher.NewCBCEncrypter(block, iv).BlockSize(nil)',
        '}',
      ].join('\n'),
    },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('AES-CBC'), `AES-CBC 应被发现，实际 ${names.join(',')}`);
    },
  );
});

test('Go: cipher.NewGCM next to aes.NewCipher is AES-GCM', () => {
  withDir(
    {
      'g.go': 'package main\nimport ("crypto/aes"; "crypto/cipher")\nfunc f(k []byte) { b, _ := aes.NewCipher(k); cipher.NewGCM(b) }\n',
    },
    (dir) => assert.ok(algorithms(dir).includes('AES-GCM')),
  );
});

test('PyCryptodome: AES.MODE_CBC is AES-CBC', () => {
  withDir(
    { 'enc.py': 'from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_CBC, iv)\n' },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('AES-CBC'), `AES-CBC 应被发现，实际 ${names.join(',')}`);
    },
  );
});

test('config data: a yaml value AES_CBC is AES-CBC', () => {
  withDir({ 'policy.yaml': 'cipher: AES_CBC\nkey_size: 256\n' }, (dir) => {
    assert.ok(algorithms(dir).includes('AES-CBC'));
  });
});

test('config data: a json value "AES-CBC" is AES-CBC', () => {
  withDir({ 'conf.json': '{"cipher":"AES-CBC"}\n' }, (dir) => {
    assert.ok(algorithms(dir).includes('AES-CBC'));
  });
});

test('canonical literal without a key size: "AES-CBC" in JavaScript is AES-CBC', () => {
  withDir({ 'm.js': "module.exports = { cipher: 'AES-CBC' };\n" }, (dir) => {
    assert.ok(algorithms(dir).includes('AES-CBC'));
  });
});

test('mode-only spelling keeps working: aes-256-cbc is still exactly AES-CBC', () => {
  withDir(
    { 'm.js': "const c = require('crypto');\nc.createCipheriv('aes-256-cbc', k, iv);\n" },
    (dir) => {
      const aes = algorithms(dir).filter((n) => /^AES/i.test(n));
      assert.deepStrictEqual(aes, ['AES-CBC'], '不应出现第二个 AES 组件');
    },
  );
});

// ---------- 负例：这些不能被算成 AES-CBC ----------

test('RSA/ECB/PKCS1Padding: ECB is padding here, so only RSA is reported', () => {
  withDir(
    { 'R.java': 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n' },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(names.includes('RSA'), 'RSA 应被发现');
      assert.ok(!names.includes('AES-ECB'), 'RSA 的 ECB 不是 AES-ECB');
      assert.ok(!names.some((n) => /^AES/.test(n)), '不应出现任何 AES 组件');
    },
  );
});

test('DES.MODE_CBC is not AES-CBC', () => {
  withDir({ 'd.py': 'from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_CBC, iv)\n' }, (dir) => {
    assert.ok(!algorithms(dir).includes('AES-CBC'), 'DES 的模式常量不应归到 AES');
  });
});

test('a commented-out JCE call is prose, not a call site', () => {
  withDir(
    {
      'C.java': [
        'class C {',
        '  // Cipher.getInstance("AES/CBC/PKCS5Padding");',
        '  /* Cipher.getInstance("AES/ECB/NoPadding"); */',
        '}',
      ].join('\n'),
    },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(!names.some((n) => /^AES/.test(n)), `注释不应产生组件，实际 ${names.join(',')}`);
    },
  );
});

test('a commented-out Go mode call is prose too', () => {
  withDir(
    { 'x.go': 'package x\n// cipher.NewCBCEncrypter(block, iv)\nvar _ = 1\n' },
    (dir) => assert.ok(!algorithms(dir).includes('AES-CBC')),
  );
});

test('a mode call with no block cipher in the file reports nothing rather than guessing AES', () => {
  withDir(
    { 'u.go': 'package x\nfunc f(b cipher.Block, iv []byte) { cipher.NewCBCEncrypter(b, iv) }\n' },
    (dir) => {
      assert.ok(!algorithms(dir).includes('AES-CBC'), '不知道 block 家族时不应假定 AES');
    },
  );
});

test('lockfile integrity hashes are not SHA-512 usage', () => {
  withDir(
    {
      'package-lock.json': '{"lockfileVersion":3,"packages":{"a":{"integrity":"sha512-abc"}}}\n',
    },
    (dir) => {
      const names = algorithms(dir);
      assert.ok(!names.includes('SHA-512'), `锁文件不应产生 SHA-512，实际 ${names.join(',')}`);
    },
  );
});

test('a CycloneDX document is skipped, not scanned as source', () => {
  withDir(
    {
      'cbom.json': '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"SHA-512"}]}\n',
    },
    (dir) => {
      const r = scan(dir);
      assert.deepStrictEqual(r.components, [], 'BOM 文档不应被当源码扫描');
    },
  );
});
