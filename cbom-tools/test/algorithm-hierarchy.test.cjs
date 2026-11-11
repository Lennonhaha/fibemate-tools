'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// algorithm-hierarchy.cjs 被 cbom-scan.cjs 的 dedup 与置信度打分依赖：
// 有 params 的具体算法（ML-KEM-768）置信度 0.9，族级（ML-KEM）0.7。
// 这里锁住查表的两个分支，避免以后「未知名字静默变 0.9」。

const { test } = require('node:test');
const assert = require('node:assert');
const { HIERARCHY, lookup } = require('../algorithm-hierarchy.cjs');

test('lookup：已知具体算法返回 family + params', () => {
  assert.deepStrictEqual(lookup('ML-KEM-768'), { family: 'ML-KEM', params: '768' });
  assert.deepStrictEqual(lookup('Keccak-256'), { family: 'Keccak', params: '256' });
});

test('lookup：族级算法 params 为 null（不是 0，也不是空串）', () => {
  assert.strictEqual(lookup('ML-KEM').params, null);
  assert.strictEqual(lookup('SLH-DSA').params, null);
});

test('lookup：未知名字返回 null，不构造默认值', () => {
  assert.strictEqual(lookup('Not-An-Algorithm'), null);
  assert.strictEqual(lookup(''), null);
});

test('HIERARCHY：每个条目的 family 非空，params 要么是字符串要么是 null', () => {
  for (const [name, entry] of Object.entries(HIERARCHY)) {
    assert.ok(entry.family, `${name} 缺 family`);
    assert.ok(entry.params === null || typeof entry.params === 'string', `${name} 的 params 类型异常`);
  }
});
