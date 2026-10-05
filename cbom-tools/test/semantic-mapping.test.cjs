// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// 语义映射测试 — 验证每个 detector 产生的 primitive 值是否正确。
// 与 schema-validation.test.cjs 不同，此处不验 schema（因为 kem 和 key-agree
// 都能通过 schema 验证），而是直接断言 emitted component 的 name + primitive。
//
// 运行：node --test test/semantic-mapping.test.cjs

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const FIXTURES = path.join(__dirname, 'fixtures');
const NODE = process.execPath;

function scanFixture(name) {
  const dir = path.join(FIXTURES, name);
  const r = spawnSync(NODE, [SCAN, '--dir', dir], { encoding: 'utf-8', cwd: ROOT });
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr?.slice(0,200)}`);
  return JSON.parse(r.stdout);
}

function comp(bom, name) {
  return bom.components?.find(c => c.name === name);
}

// --- x25519-dh: crypto_x25519() → key-agree ---

test('crypto_x25519 → X25519 → primitive=key-agree', () => {
  const bom = scanFixture('x25519-dh');
  const c = comp(bom, 'X25519');
  assert.ok(c, 'X25519 component not found');
  assert.strictEqual(c.cryptoProperties?.algorithmProperties?.primitive, 'key-agree');
});

// --- ecdh-dh: mbedtls_ecdh_compute_shared() → ECDH → key-agree ---

test('mbedtls_ecdh_compute_shared → ECDH → primitive=key-agree', () => {
  const bom = scanFixture('ecdh-dh');
  const c = comp(bom, 'ECDH');
  assert.ok(c, 'ECDH component not found');
  assert.strictEqual(c.cryptoProperties?.algorithmProperties?.primitive, 'key-agree');
});

// --- mlkem-control: @noble/post-quantum → ML-KEM → primitive=kem (control) ---

test('@noble/post-quantum → ML-KEM-768 → primitive=kem (control)', () => {
  const bom = scanFixture('mlkem-control');
  const c = comp(bom, 'ML-KEM-768');
  assert.ok(c, 'ML-KEM-768 component not found');
  assert.strictEqual(c.cryptoProperties?.algorithmProperties?.primitive, 'kem');
});

// --- dep-only-keccak: @noble/hashes → Keccak → primitive=hash ---

test('@noble/hashes → Keccak → primitive=hash (was other)', () => {
  const bom = scanFixture('dep-only-keccak');
  const c = comp(bom, 'Keccak-256');
  assert.ok(c, 'Keccak-256 component not found');
  assert.strictEqual(c.cryptoProperties?.algorithmProperties?.primitive, 'hash');
});