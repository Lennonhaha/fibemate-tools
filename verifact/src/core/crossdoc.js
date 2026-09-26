'use strict';
// SPDX-License-Identifier: Apache-2.0

/**
 * 跨文档互证：同一个键在不同文档里给出了不同的值。
 *
 * 与 drift 的分工：
 *   drift    —— 文档 vs 产出物（有证据可锚）
 *   crossDoc —— 文档 vs 文档（没有任何产出物时，声明之间互相矛盾）
 *
 * 纪律：只聚类、只列值与出处，不判哪份文档错。
 * 量级差 ≥ warnRatio（默认 10 倍）才标 warn——那种差异通常不是口径问题；
 * 其余记 info，交人判断。
 */

const GENERIC_KEYS = new Set([
  'max', 'min', 'total', 'sum', 'n', 'value', 'count', 'score', 'factor', 'cost',
  'time', 'date', 'len', 'size', 'version', 'id', 'name', 'type', 'level'
]);

function shapeOf(v) {
  if (!v) return null;
  if (v.type === 'scalar' && v.number != null) return 'scalar:' + (v.dim || '-');
  return null;
}

function numOf(v) {
  if (v.type !== 'scalar' || v.number == null) return null;
  const x = v.base != null ? v.base : v.number;
  return Math.abs(x);
}

/**
 * @param {Array} claims 已解析完成的声明（含 status）
 * @param {object} opts { warnRatio }
 * @returns {Array} 按量级差降序的不一致簇
 */
function crossDocCheck(claims, opts) {
  const warnRatio = (opts && opts.warnRatio) || 10;
  const groups = new Map();

  for (const c of claims) {
    if (c.kind === 'ref' || c.kind === 'loc' || !c.value) continue;
    const shape = shapeOf(c.value);
    if (!shape) continue;
    if (!c.keyTokens || !c.keyTokens.length) continue;
    if (c.keyTokens.length === 1 && GENERIC_KEYS.has(c.keyTokens[0])) continue;
    // 单 token 且 ≤2 字符（q / k / n / d）：在密码学文档里几乎总是不同对象的参数名，噪音大于信号
    if (c.keyTokens.length === 1 && c.keyTokens[0].length <= 2) continue;
    const sig = (c.module || '-') + '|' + c.keyTokens.join('-') + '|' + shape;
    if (!groups.has(sig)) groups.set(sig, []);
    groups.get(sig).push(c);
  }

  const out = [];
  for (const [sig, list] of groups) {
    // 按值聚合：同值多处出现只占一格
    const byVal = new Map();
    for (const c of list) {
      const k = String(c.value.raw);
      if (!byVal.has(k)) byVal.set(k, []);
      byVal.get(k).push(c);
    }
    if (byVal.size < 2) continue;
    const files = new Set(list.map((c) => c.file));
    if (files.size < 2) continue;

    const nums = list.map((c) => numOf(c.value)).filter((x) => x != null && x > 0);
    let ratio = null;
    if (nums.length >= 2) {
      const mx = Math.max.apply(null, nums);
      const mn = Math.min.apply(null, nums);
      ratio = mn > 0 ? mx / mn : null;
    }
    const severity = ratio != null && ratio >= warnRatio ? 'warn' : 'info';

    out.push({
      sig,
      key: list[0].key,
      module: list[0].module || null,
      dim: list[0].value.dim || null,
      distinctValues: byVal.size,
      files: files.size,
      claims: list.length,
      maxMinRatio: ratio != null ? Number(ratio.toFixed(2)) : null,
      severity,
      values: Array.from(byVal.entries())
        .map(([raw, cs]) => ({ raw, at: cs.slice(0, 4).map((c) => c.file + ':' + c.line), count: cs.length }))
        .slice(0, 8)
    });
  }

  out.sort((a, b) => (b.maxMinRatio || 0) - (a.maxMinRatio || 0));
  return out;
}

module.exports = { crossDocCheck };
