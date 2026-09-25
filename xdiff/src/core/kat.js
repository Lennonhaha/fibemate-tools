// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * NIST .rsp 格式的 ML-KEM KAT 向量解析 + 参考文件卫生检查。
 *
 * 向量字段：count / seed(32B) / m(32B) / ek(1184B) / dk(2400B) / c(1088B) / k(32B)。
 * 解析只做结构校验，不猜语义；dk 的区域含义由 hygiene 检查显式标注。
 */

const U = require('../util');

const FIELD_LEN = { seed: 32, m: 32, ek: 1184, dk: 2400, c: 1088, k: 32 };

/** 解析 .rsp 文本 → 向量数组（值保留 Buffer）。 */
function parseRsp(text) {
  const vectors = [];
  let cur = null;
  const lines = String(text).split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^([A-Za-z]+)\s*=\s*([0-9a-fA-F]+)\s*$/);
    if (!m) continue;
    const field = m[1];
    const hex = m[2].toLowerCase();
    if (field === 'count') {
      if (cur) vectors.push(cur);
      cur = { count: parseInt(hex || '0', 10) };
      continue;
    }
    if (!cur) continue;
    if (!(field in FIELD_LEN)) { cur[field] = hex; continue; }
    const buf = Buffer.from(hex, 'hex');
    cur[field] = buf;
    cur[field + 'LenOk'] = buf.length === FIELD_LEN[field];
  }
  if (cur) vectors.push(cur);
  return vectors;
}

/** 结构完整性：每条向量的必备字段与长度。 */
function checkStructure(vectors) {
  const bad = [];
  for (const v of vectors) {
    for (const f of Object.keys(FIELD_LEN)) {
      if (!v[f]) { bad.push({ count: v.count, field: f, problem: 'missing' }); continue; }
      if (v[f + 'LenOk'] === false) bad.push({ count: v.count, field: f, problem: 'length', got: v[f].length, expect: FIELD_LEN[f] });
    }
  }
  return bad;
}

/**
 * 卫生检查：dk 的分区域分析。
 * FIPS 203 的 compact 布局：d(0:32) ‖ ek(32:1216) ‖ H(ek)(1216:1248) ‖ z(1248:1280)。
 * z 与 1280 之后的尾部都应当由实现确定性写出；发现不可读来源的字节（ASCII 串、
 * 指针模式、非零残留）时如实报告数量——这是信号，不是判决。
 */
function analyzeHygiene(vectors) {
  const compact = { dMatch: 0, ekMatch: 0, hMatch: 0, of: 0 };
  const zStats = { total: 0, asciiReadable: 0, allZero: 0, unique: 0 };
  const tailStats = { total: 0, allZero: 0, nonZero: 0, asciiReadable: 0 };
  const zSeen = new Set();

  for (const v of vectors) {
    if (!v.dk || v.dk.length !== 2400 || !v.seed || !v.ek) continue;
    const dk = v.dk;
    compact.of++;
    if (dk.slice(0, 32).equals(v.seed)) compact.dMatch++;
    if (dk.slice(32, 1216).equals(v.ek)) compact.ekMatch++;
    if (dk.slice(1216, 1248).equals(U.sha3_256(v.ek))) compact.hMatch++;

    const z = dk.slice(1248, 1280);
    zStats.total++;
    zSeen.add(z.toString('hex'));
    if (z.every((b) => b === 0)) zStats.allZero++;
    if (hasAsciiRun(z, 6)) zStats.asciiReadable++;

    const tail = dk.slice(1280);
    tailStats.total++;
    if (tail.every((b) => b === 0)) tailStats.allZero++;
    else {
      tailStats.nonZero++;
      if (hasAsciiRun(tail, 8)) tailStats.asciiReadable++;
    }
  }
  zStats.unique = zSeen.size;
  return { compact, z: zStats, tail: tailStats };
}

function hasAsciiRun(buf, minLen) {
  let run = 0;
  for (const b of buf) {
    if (b >= 0x20 && b <= 0x7e) { run++; if (run >= minLen) return true; }
    else run = 0;
  }
  return false;
}

module.exports = { parseRsp, checkStructure, analyzeHygiene, FIELD_LEN };
