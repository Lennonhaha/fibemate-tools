'use strict';
// SPDX-License-Identifier: Apache-2.0

const { compareValues, squash, unknownUnitConflict } = require('./normalize');

/**
 * 声明 ↔ 产出物 解析器。
 *
 * 五级结果，严格遵守「信号 vs 判决分离」：
 *   verified      命中产出物，数值一致
 *   drift         命中同形状产出物，数值不一致 —— 本工具唯一关心的红
 *   ambiguous     形状不同或候选冲突（如 5/5 vs 36/36 是规模不同，不是数值漂移）—— 交人工
 *   unbound       产出物里没有可比条目 —— 可能文档自称，也可能只是没导出
 *   ref-found / ref-missing   引用型产出物的存在性
 *
 * 关键纪律：**不可比的东西不判红**。比率对标量、字节对毫秒、规模不同的比率，
 * 一律降级为 ambiguous / unbound，绝不产出假的 drift。
 */

function overlapCoefficient(a, b) {
  if (!a.length || !b.length) return 0;
  const setB = new Set(b);
  let hit = 0;
  for (const t of a) if (setB.has(t)) hit++;
  return hit / Math.min(a.length, b.length);
}

function candidatesFor(claim, index) {
  const out = [];
  const seen = new Set();
  const consider = (arr) => {
    if (!arr) return;
    for (const e of arr) { if (!seen.has(e)) { seen.add(e); out.push(e); } }
  };
  for (const t of claim.keyTokens) consider(index.byToken.get(t));
  if (claim.primaryToken && claim.keyTokens.indexOf(claim.primaryToken) < 0) {
    consider(index.byToken.get(claim.primaryToken));
  }

  // 模块是一道硬约束：同模块的候选存在时，绝不去碰别的模块
  if (claim.module) {
    const same = out.filter((e) => e.module === claim.module);
    if (same.length) return same;
  }
  return out;
}

function score(claim, entry) {
  const core = overlapCoefficient(claim.keyTokens, entry.keyTokens);
  const specific = entry.keyTokens.indexOf(claim.primaryToken) >= 0 ? 1 : 0;
  const moduleMatch = (claim.module && entry.module && claim.module === entry.module) ? 1 : 0;
  let unitMatch = 0;
  const cv = claim.value, ev = entry.value;
  if (cv && ev && cv.type === ev.type) {
    if (cv.dim && ev.dim && cv.dim === ev.dim) unitMatch = 1;
    else if (!cv.dim && !ev.dim) unitMatch = 0.5;
  }
  return 0.45 * core + 0.25 * specific + 0.2 * moduleMatch + 0.1 * unitMatch;
}

function resolveRefClaim(claim, index) {
  const ref = claim.value.ref.replace(/[^a-z0-9]/g, '');
  if (!ref) return { status: 'unbound', reason: 'empty_ref' };
  if (claim.subtype === 'commit') {
    return { status: 'unbound', reason: 'resolution_disabled', note: 'commit 需对比 git 对象，当前版本不做此判定' };
  }
  if (claim.subtype === 'serial') {
    return { status: 'unbound', reason: 'resolution_disabled', note: 'TSR serial 需解析 DER 并与 TSA 回填比对，当前版本不做此判定' };
  }
  for (const rel of index.presence) {
    if (squash(rel).indexOf(ref) >= 0) {
      return { status: 'ref-found', best: { source: rel, path: 'existence', value: { type: 'ref', raw: claim.value.ref } }, score: 1 };
    }
  }
  return { status: 'ref-missing', reason: 'ref_not_found' };
}

/** 值形状是否可比：类型一致且量纲相容（或都无量纲）。形状不同不许判红。 */
function comparableShape(cmp) {
  return cmp && cmp.reason !== 'type_mismatch' && cmp.reason !== 'non_numeric' && cmp.reason !== 'missing_value' && cmp.reason !== 'unparsable';
}

/**
 * 弱证据过滤：一侧有量纲、另一侧是无单位小整数时，几乎肯定是「键同名但度量不同」
 * （例：文档 `23957ms` 对上 `assessment.ms.usageCount = 1`）。
 * 这种候选不参与绑定，直接丢弃。
 */
function isWeakEvidence(claimValue, entryValue) {
  if (!claimValue || !entryValue) return true;
  if (claimValue.type !== entryValue.type) return true;
  if (claimValue.type === 'ratio') {
    // 比率的一侧分子为小整数、另一侧分子是大数时同样视为弱证据
    const a = claimValue.numerator, b = entryValue.numerator;
    if (a == null || b == null) return false;
    const small = (x) => Number.isInteger(x) && Math.abs(x) <= 50;
    if (small(a) !== small(b)) {
      return claimValue.denominator != null && entryValue.denominator != null &&
        claimValue.denominator !== entryValue.denominator;
    }
    return false;
  }
  const cd = claimValue.dim, ed = entryValue.dim;
  if (cd === ed) return false;
  const smallInt = (v) => v.dim == null && v.number != null && Number.isInteger(v.number) && Math.abs(v.number) <= 50;
  if (smallInt(claimValue) && ed) return true;
  if (smallInt(entryValue) && cd) return true;
  return false;
}

/**
 * 数量级守卫：两侧都是标量、量纲可通约（或都无量纲），但数值相差 1000 倍以上时，
 * 几乎肯定是「键同名但不是同一个量」（文档的 `max=8504497693` 对上 `max_score=100`）。
 * 这种候选丢弃，不参与比对。
 */
const MAGNITUDE_RATIO = 1000;

function magnitudeGuard(claimValue, entryValue) {
  if (!claimValue || !entryValue) return false;
  if (claimValue.type !== 'scalar' || entryValue.type !== 'scalar') return false;
  const a = claimValue.number, b = entryValue.number;
  if (a == null || b == null) return false;
  const cd = claimValue.dim, ed = entryValue.dim;
  if (cd && ed && cd !== ed) return false;          // 量纲不同交给 unknownUnitConflict 处理
  const x = Math.abs(a), y = Math.abs(b);
  if (x === 0 || y === 0) return x !== y;
  const ratio = x > y ? x / y : y / x;
  return ratio > MAGNITUDE_RATIO;
}

/**
 * 行数型声明：「自研纯 JS（654 行）」—— 核验对象是真文件的行数，不是产出物里的数值。
 * 匹配策略：声明所在句子里出现某个已扫描文件的文件名主干（≥6 字符，防误匹配），
 * 该文件的实测行数就是证据。容差默认 ±5%（文档与代码的正常编辑漂移）。
 */
function resolveLocClaim(claim, index, opts) {
  const tolerance = (opts && opts.locTolerance) != null ? opts.locTolerance : 0.05;
  // 只看数字前的窗口（locPrefix），且文件名主干必须出现在窗口尾部 60 字符内：
  // 「文件名（654 行）」可信；「N 行 —— 文件名」或远距离提及不绑。
  const hay = squash(claim.locPrefix != null ? claim.locPrefix : (claim.sentence || ''));
  const cands = [];
  for (const pair of index.fileLines || []) {
    const rel = pair[0], lines = pair[1];
    const base = String(rel).split('/').pop();
    const dot = base.lastIndexOf('.');
    const stem = dot > 0 ? base.slice(0, dot) : base;
    const sq = squash(stem);
    if (sq.length < 6) continue;
    const pos = hay.lastIndexOf(sq);
    if (pos < 0) continue;
    if (pos + sq.length < hay.length - 60) continue;   // 距数字太远，不算指向
    cands.push({ source: rel, lines });
  }
  const mkVal = (n) => ({ type: 'scalar', raw: String(n), number: n, unit: '行', dim: 'loc', base: n });
  if (!cands.length) return { status: 'unbound', reason: 'loc_file_not_in_scope' };
  const num = claim.value.number;
  const near = cands.filter((c) => Math.abs(c.lines - num) / c.lines <= tolerance);
  if (near.length) {
    return {
      status: 'verified',
      best: { source: near[0].source, path: 'line-count', value: mkVal(near[0].lines) },
      score: 1,
      note: '行数容差 ±' + Math.round(tolerance * 100) + '%'
    };
  }
  if (cands.length === 1) {
    return {
      status: 'drift',
      best: { source: cands[0].source, path: 'line-count', value: mkVal(cands[0].lines) },
      score: 1,
      cmp: { equal: false, reason: 'loc_mismatch', expected: num, actual: cands[0].lines }
    };
  }
  return {
    status: 'ambiguous',
    reason: 'loc_candidate_conflict',
    candidates: cands.slice(0, 5).map((c) => ({ source: c.source, path: 'line-count', value: mkVal(c.lines) }))
  };
}

function resolveClaim(claim, index, opts) {
  const cfg = opts || {};
  const minScore = cfg.minScore != null ? cfg.minScore : 0.45;
  const cmpOpts = { relTolerance: cfg.relTolerance, absTolerance: cfg.absTolerance };

  if (claim.kind === 'ref') return resolveRefClaim(claim, index);
  if (claim.kind === 'loc') return resolveLocClaim(claim, index, cfg);

  const all = candidatesFor(claim, index);
  if (!all.length) return { status: 'unbound', reason: 'no_artifact_entry' };

  const belowNotes = [];
  const scored = [];
  let weak = 0;
  for (const e of all) {
    if (isWeakEvidence(claim.value, e.value)) { weak++; continue; }
    if (magnitudeGuard(claim.value, e.value)) { weak++; continue; }
    const s = score(claim, e);
    if (s < minScore) { belowNotes.push(s); continue; }
    if (isWeakEvidence(claim.value, e.value)) { weak++; continue; }
    if (unknownUnitConflict(claim.value, e.value)) continue;   // 10,000 rounds vs 6 tests
    const cmp = compareValues(claim.value, e.value, cmpOpts);
    if (!comparableShape(cmp)) continue;          // 形状不可比 → 直接丢弃候选
    scored.push({ entry: e, score: s, cmp });
  }
  if (!scored.length) {
    return {
      status: 'unbound',
      reason: belowNotes.length ? 'below_score_threshold' : 'no_comparable_shape',
      weakEvidence: weak,
      candidates: all.length
    };
  }

  scored.sort((a, b) => b.score - a.score);
  const best = scored[0];

  // 只要有候选能对上，就算核验通过——其余候选的差异作为待复核备选列出。
  // 只有当「高分候选全都对不上」时，才有意义去谈 conflict / drift。
  const equalHit = scored.find((s) => s.cmp.equal);
  if (equalHit) {
    return {
      status: 'verified',
      best: equalHit.entry,
      score: equalHit.score,
      cmp: equalHit.cmp,
      alternatives: scored.filter((s) => s !== equalHit).slice(0, 3).map((s) => ({
        source: s.entry.source, path: s.entry.path, score: Number(s.score.toFixed(3)), value: s.entry.value
      }))
    };
  }

  // 高分候选给不出一致答案：绑定关系本身存疑 —— 交人工，不判红
  const topBand = scored.filter((s) => s.score >= best.score - 0.08);
  const distinct = new Set(topBand.map((s) => JSON.stringify(s.entry.value)));
  if (distinct.size > 1) {
    return {
      status: 'ambiguous',
      best: best.entry,
      score: best.score,
      cmp: best.cmp,
      reason: 'candidate_conflict',
      alternatives: topBand.slice(0, 5).map((s) => ({
        source: s.entry.source, path: s.entry.path, score: Number(s.score.toFixed(3)), value: s.entry.value
      }))
    };
  }

  // 分母不同 = 测试规模不同，不是数值漂移
  if (best.cmp.reason === 'denominator_differs') {
    return {
      status: 'ambiguous',
      best: best.entry,
      score: best.score,
      cmp: best.cmp,
      reason: 'different_denominator_scope',
      alternatives: scored.slice(1, 4).map((s) => ({
        source: s.entry.source, path: s.entry.path, score: Number(s.score.toFixed(3)), value: s.entry.value
      }))
    };
  }

  const mkAlts = () => scored.slice(1, 4).map((s) => ({
    source: s.entry.source, path: s.entry.path, score: Number(s.score.toFixed(3)), value: s.entry.value
  }));

  // 跨模块绑定（文档说 ML-DSA、产出物条目属于 SM2）：同键不同对象，不作 drift 判决
  if (claim.module && best.entry.module && claim.module !== best.entry.module) {
    return {
      status: 'ambiguous',
      best: best.entry,
      score: best.score,
      cmp: best.cmp,
      reason: 'cross_module_binding',
      alternatives: mkAlts()
    };
  }

  return {
    status: 'drift',
    best: best.entry,
    score: best.score,
    cmp: best.cmp,
    alternatives: mkAlts()
  };
}

function explain(res) {
  switch (res.status) {
    case 'verified': return '产出物中存在同键目且数值一致';
    case 'drift': return '产出物中存在同形状同键目，但数值不一致';
    case 'ambiguous':
      if (res.reason === 'different_denominator_scope') return '分母不同：测试规模不一致，无法判定为数值漂移，需人工确认口径';
      if (res.reason === 'candidate_conflict') return '多个候选产出物给出不同数值，需人工判定绑定关系';
      if (res.reason === 'cross_module_binding') return '文档标的是某个模块，产出物条目属于另一个模块：同键不同对象，需人工确认绑定';
      if (res.reason === 'loc_candidate_conflict') return '多个同名文件候选且行数对不上，需人工确认声明指向哪个文件';
      return '候选存在冲突，需人工判定';
    case 'unbound':
      if (res.reason === 'no_comparable_shape') return '产出物中存在同名条目但值形状不可比（比率 vs 标量 / 量纲不同）';
      if (res.reason === 'loc_file_not_in_scope') return '声明指向的文件不在扫描范围内，无法核实行数';
      return '产出物中未找到可比对条目（可能是文档自称，也可能只是未导出）';
    case 'ref-found': return '引用到的产出物文件确实存在';
    case 'ref-missing': return '引用到的产出物在扫描范围内不存在';
    default: return res.reason || '';
  }
}

module.exports = { resolveClaim, score, overlapCoefficient, candidatesFor, explain, comparableShape };
