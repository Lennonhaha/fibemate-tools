'use strict';
// SPDX-License-Identifier: Apache-2.0

// 单位表：同一 dim 内可比，base = number * factor。
// 未知单位或未标注单位 → dim=null，仅按裸数值比对（并在报告里标 degradedComparability）。
const UNITS = {
  ns: { dim: 'time', factor: 1 },
  nsec: { dim: 'time', factor: 1 },
  us: { dim: 'time', factor: 1e3 },
  'µs': { dim: 'time', factor: 1e3 },
  'μs': { dim: 'time', factor: 1e3 },
  ms: { dim: 'time', factor: 1e6 },
  msec: { dim: 'time', factor: 1e6 },
  s: { dim: 'time', factor: 1e9 },
  sec: { dim: 'time', factor: 1e9 },
  b: { dim: 'size', factor: 1 },
  byte: { dim: 'size', factor: 1 },
  bytes: { dim: 'size', factor: 1 },
  kb: { dim: 'size', factor: 1024 },
  kib: { dim: 'size', factor: 1024 },
  mb: { dim: 'size', factor: 1048576 },
  mib: { dim: 'size', factor: 1048576 },
  gb: { dim: 'size', factor: 1073741824 },
  gib: { dim: 'size', factor: 1073741824 },
  pct: { dim: 'pct', factor: 1 },
  states: { dim: 'count', factor: 1 },
  cycles: { dim: 'count', factor: 1 },
  x: { dim: 'ratio', factor: 1 }
};

const PCT_TOKEN = '%';

function squash(s) {
  return String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9]+/g, '');
}

// CJK 参与 key 上下文（文档多为中英混排），最大 CJK 连续段算一个 token。
const TOKEN_SPLIT = /[^a-z0-9\u4e00-\u9fff]+/;

function squashTokens(s) {
  return String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g, '');
}

function tokens(s) {
  const parts = String(s == null ? '' : s).toLowerCase().split(TOKEN_SPLIT);
  const out = [];
  for (const p of parts) {
    if (!p) continue;
    // 过长的中文连续段信息量低，丢弃避免污染相似度
    if (/^[\u4e00-\u9fff]+$/.test(p) && p.length > 4) continue;
    out.push(p);
  }
  return out;
}

function normKey(s) {
  return tokens(s).join('-');
}

/** 把 "ML-KEM-768" 变成 "mlkem768"，用于在归一化路径里做包含判断。 */
function dekey(s) {
  const parts = String(s == null ? '' : s).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return parts.join('');
}

function parseNum(raw) {
  if (raw == null) return null;
  const cleaned = String(raw).replace(/[,\s_]/g, '');
  if (!/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(cleaned)) return null;
  const n = Number(cleaned);
  return Number.isFinite(n) ? n : null;
}

function unitInfo(unit) {
  if (!unit) return null;
  const u = String(unit).toLowerCase();
  if (u === PCT_TOKEN) return UNITS.pct;
  return UNITS[u] || null;
}

/**
 * 数值封装。ratio 型单独用 {type:'ratio'} 表示。
 * @returns {{type:string, raw:string, number:number|null, unit:string|null, dim:string|null, base:number|null}}
 */
function mkValue(numberText, unit) {
  const number = parseNum(numberText);
  const info = unitInfo(unit);
  return {
    type: 'scalar',
    raw: String(numberText) + (unit ? String(unit) : ''),
    number,
    unit: unit ? String(unit) : null,
    dim: info ? info.dim : null,
    base: info && number != null ? number * info.factor : null
  };
}

function mkRatio(numeratorText, denominatorText) {
  const a = parseNum(numeratorText);
  const b = parseNum(denominatorText);
  return {
    type: 'ratio',
    raw: numeratorText + '/' + denominatorText,
    numerator: a,
    denominator: b,
    ratio: a != null && b ? a / b : null
  };
}

/**
 * 比对两个值。单位维度一致时按归一化 base 比；维度不一致或缺失时退化为裸数值比。
 * @returns {{equal:boolean, comparable:boolean, reason:string}}
 */
function compareValues(a, b, opts) {
  const rel = (opts && opts.relTolerance != null) ? opts.relTolerance : 0.005;
  const abs = (opts && opts.absTolerance != null) ? opts.absTolerance : 0;
  if (!a || !b) return { equal: false, comparable: false, reason: 'missing_value' };
  if (a.type !== b.type) return { equal: false, comparable: false, reason: 'type_mismatch' };

  if (a.type === 'ratio') {
    if (a.numerator == null || b.numerator == null) return { equal: false, comparable: false, reason: 'unparsable' };
    if (a.denominator != null && b.denominator != null && a.denominator !== b.denominator) {
      return { equal: false, comparable: true, reason: 'denominator_differs' };
    }
    if (a.numerator !== b.numerator) return { equal: false, comparable: true, reason: 'numerator_differs' };
    return { equal: true, comparable: true, reason: 'exact' };
  }

  if (a.number == null || b.number == null) {
    return { equal: String(a.raw) === String(b.raw), comparable: false, reason: 'non_numeric' };
  }

  let comparable = false;
  let x, y;
  if (a.dim && b.dim && a.dim === b.dim && a.base != null && b.base != null) {
    x = a.base; y = b.base; comparable = true;
  } else if (!a.dim && !b.dim) {
    x = a.number; y = b.number; comparable = false;
  } else {
    x = a.number; y = b.number; comparable = false;
  }
  if (x === y) return { equal: true, comparable, reason: 'exact' };
  const tol = Math.max(abs, rel * Math.abs(x), rel * Math.abs(y));
  if (Math.abs(x - y) <= tol) return { equal: true, comparable, reason: 'within_tolerance' };
  return { equal: false, comparable, reason: 'value_differs' };
}

/** 从单个标量字符串里尝试构造出水印条目用的值对象（供 JSON 叶子服务）。 */
function valueFromString(text) {
  const t = String(text).trim();
  let m = t.match(/^(\d[\d,]*)\s*\/\s*(\d[\d,]*)$/);
  if (m) return mkRatio(m[1], m[2]);
  m = t.match(/^(-?\d[\d,]*(?:\.\d+)?)\s*(ns|us|µs|μs|ms|s|sec|%|bytes|byte|b|kb|mb|gb|kib|mib|gib)$/i);
  if (m) return mkValue(m[1], m[2]);
  const maybe = parseNum(t);
  if (maybe != null) return { type: 'scalar', raw: t, number: maybe, unit: null, dim: null, base: null };
  return null;
}

/**
 * 两边都带了「工具不认识的单位」且单位名不同 → 度量的东西多半不是一回事
 * （例：文档 10,000 rounds vs 产出物 6 tests）。这种不做数值比较。
 */
function unknownUnitConflict(a, b) {
  if (a.type !== 'ratio' && b.type === 'ratio') return false;
  if (a.type === 'ratio' || b.type === 'ratio') return false;
  if (!a.unit || !b.unit) return false;
  const ua = String(a.unit).toLowerCase(), ub = String(b.unit).toLowerCase();
  if (ua === ub) return false;
  const ia = unitInfo(ua), ib = unitInfo(ub);
  if (!ia || !ib) return true;            // 至少一边单位未知 → 不可比
  return ia.dim !== ib.dim;               // 两边都已知但量纲不同 → 不可比
}

module.exports = {
  UNITS, tokens, normKey, squash, dekey, parseNum, unitInfo,
  mkValue, mkRatio, compareValues, valueFromString, unknownUnitConflict
};
