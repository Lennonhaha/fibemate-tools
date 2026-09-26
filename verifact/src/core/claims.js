'use strict';
// SPDX-License-Identifier: Apache-2.0

const { tokens, mkValue, mkRatio, parseNum } = require('./normalize');

/**
 * 硬数字声明抽取器。
 *
 * 纪律：
 *  - 只做结构抽取，不做语义判断；抽到的是「待核验的声明」，不是结论。
 *  - 宁可漏报，不可误报：拿捏不准的模式（裸大数字）默认关闭。
 *  - 行号必须准：清洗噪声时用等长空白替换，绝不删字符改变行数。
 */

// 关键前缀词：出现在数字前，直接接管 primaryToken，压过通用上下文猜测。
const DOMINANT_PREFIX = new Set([
  'kat', 'tvla', 'adla', 'wns', 'tns', 'whs', 'p50', 'p95', 'p99', 'p999',
  'score', 'coverage', 'states', 'cycles', 'mutants', 'invariants', 'ndet', 'ser',
  'fps', 'tps', 'qps', 'latency', 'throughput', 'bram', 'dsp', 'lut', 'ff'
]);

const STOPWORDS = new Set([
  'the', 'a', 'an', 'of', 'and', 'or', 'in', 'for', 'with', 'is', 'are', 'was', 'were',
  'to', 'by', 'at', 'on', 'as', 'that', 'this', 'it', 'from', 'be', 'been', 'has', 'have',
  'see', 'seealso', 'note', 'TODO', 'total', 'all', 'up', 'down', 'per', 'over', 'under',
  'http', 'https', 'com', 'org', 'net', 'md', 'html', 'npm', 'git',
  '的', '了', '和', '与', '及', '在', '对', '为', '是', '其', '将', '已', '有', '个', '项',
  '条', '次', '组', '共', '即', '中', '到', '从', '并', '也', '均', '各', '该', '被', '把'
]);

// 形如 "2026"、"1000" 这类无单位整数几乎总是噪音（年份 / 编号），除非前缀词表明是度量。
const METRIC_HINTS = new Set([
  'kat', 'tvla', 'score', 'coverage', 'states', 'cycles', 'count', 'total', 'files', 'deps',
  'samples', 'runs', 'tests', 'invariants', 'traces', 'suites', 'rounds', 'bits', 'throughput'
]);

const PATTERNS = [
  // 引用型：TSR / commit / serial —— 走「产出物是否存在」核验
  { kind: 'ref', subtype: 'tsr', re: /\bTSR\s+([A-Za-z]{1,4}-?\d{2,4})\b/g },
  { kind: 'ref', subtype: 'commit', re: /\bcommit\s+([0-9a-f]{7,40})\b/gi },
  { kind: 'ref', subtype: 'serial', re: /\bserial\s+(0x[0-9a-fA-F]{4,})\b/gi },
  // 比率型：10000/10000、5/5
  { kind: 'ratio', re: /(\d[\d,]{0,12})\s*\/\s*(\d[\d,]{0,12})(?![/\d.])/g, dpi: true },
  // 键值型：p95=78.5ms、score: 77.3
  {
    kind: 'kv',
    re: /([A-Za-z][A-Za-z0-9_.\-]{0,39}|[\u4e00-\u9fff]{1,6})\s*[=＝:：]\s*(-?\d[\d,]*(?:\.\d+)?)\s*(ns|us|µs|μs|ms|s|sec|%|bytes|byte|b|kb|mb|gb|kib|mib|gib|states|cycles)?\b/gi,
    keyGroup: 1, numGroup: 2, unitGroup: 3
  },
  // 度量型：78.5ms、9.755ns、77.3%（键来自上下文）
  // 数字左侧不得是字母数字或连字符，否则 "SLH-DSA-128s" 会被当成 -128秒
  { kind: 'measure', re: /(?<![\w-])(-?\d[\d,]*(?:\.\d+)?)\s*(ns|us|µs|μs|ms|s|%|cycles)\b(?![a-z])/gi, numGroup: 1, unitGroup: 2, ctx: true },
  // 计数型：101,467 states、80 bytes、7 invariants
  { kind: 'count', re: /(\d[\d,]{0,12})\s+(states|cycles|bytes|tests|runs|samples|suites|invariants|traces|files|deps|dimensions|bits|rounds|ciphers)\b/gi, numGroup: 1, unitGroup: 2, ctx: true },
  // 行数型：654 行、800 行代码（「第 45 行」行号引用在提取分支里过滤）
  { kind: 'loc', re: /(?<![\w第])(\d[\d,]{0,8})\s*行(?=[\)）\s，。、；：:]|$)/g, numGroup: 1, ctx: true }
];

const DEEP_BARE = { kind: 'bare', re: /(?:^|[|\s(])(\d[\d,]{3,})(?=[|\s.,;)\]]|$)/g, numGroup: 1, ctx: true };

function blank(match) {
  return match.replace(/[^\n]/g, ' ');
}

/** 用等长空白替换噪声片段，保持行号不变。 */
function stripNoise(text) {
  return String(text)
    .replace(/\r\n?/g, '\n')
    .replace(/```[\s\S]*?```/g, blank)
    .replace(/~~~[\s\S]*?~~~/g, blank)
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/`[^`\n]*`/g, blank)
    .replace(/https?:\/\/[^\s)\]|>]+/g, blank)
    .replace(/<[^>\n]+>/g, blank);
}

function lineModules(line, modules) {
  const lower = String(line).toLowerCase().replace(/[^a-z0-9]+/g, '');
  const hits = [];
  for (const m of modules) {
    if (m.dekey && lower.indexOf(m.dekey) >= 0) hits.push(m.name);
  }
  if (hits.length <= 1) return { module: hits[0] || null, all: hits };
  // 同一个 §.<nospace>串里可能同时命中 "ML-KEM" 与 "ML-KEM-768"，取最长（最具体）者
  hits.sort((a, b) => b.length - a.length);
  return { module: hits[0], all: hits };
}

function cleanTokens(arr) {
  const out = [];
  for (const w of arr) {
    if (!w) continue;
    if (STOPWORDS.has(w)) continue;
    if (/^\d+$/.test(w)) continue;
    if (out.indexOf(w) >= 0) continue;
    out.push(w);
  }
  return out;
}

function contextKey(line, startIdx, endIdx, unitToken) {
  // 表格行的 "|" 会切断上下文，换成空格（等长，安全）
  let prefix = line.slice(Math.max(0, startIdx - 64), startIdx).replace(/\|/g, ' ');
  prefix = prefix.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
  const before = cleanTokens(tokens(prefix));
  if (!before.length) {
    // 数字在行首时（"43/43 cross-validation tests PASS"），用后面的描述词充当键
    let afterRaw0 = '';
    if (endIdx != null) afterRaw0 = line.slice(endIdx, endIdx + 64).replace(/\|/g, ' ');
    const tail = cleanTokens(tokens(afterRaw0)).filter((w) => w !== unitToken).slice(0, 3);
    if (!tail.length) return { keyTokens: [], primaryToken: null, key: '' };
    return { keyTokens: tail.slice(0, 2), primaryToken: tail[0], key: tail[0] };
  }

  let primary = null;
  let keyPart = before;
  for (let i = before.length - 1; i >= 0; i--) {
    if (DOMINANT_PREFIX.has(before[i])) {
      keyPart = before.slice(i);
      primary = keyPart[keyPart.length - 1];
      break;
    }
  }
  if (!primary) {
    primary = before[before.length - 1];
    keyPart = before.slice(-2);
  }

  // 数字后面的描述词同样参与匹配（"43/43 cross-validation tests PASS" 的情况）
  let afterRaw = '';
  if (endIdx != null) afterRaw = line.slice(endIdx, endIdx + 48).replace(/\|/g, ' ');
  const after = cleanTokens(tokens(afterRaw)).filter((w) => w !== unitToken).slice(0, 2);

  const combined = cleanTokens(keyPart.concat(after)).slice(0, 4);
  return { keyTokens: combined, primaryToken: primary, key: keyPart.join('-') };
}

function isNoiseNumber(numText, unit, primaryToken) {
  const n = parseNum(numText);
  if (n == null) return true;
  if (unit) return false;
  if (Number.isInteger(n) && n >= 1000 && n <= 2100 && !(primaryToken && METRIC_HINTS.has(primaryToken))) return true;
  return false;
}

/**
 * @param {string} text       原始文本（会先做等长清洗）
 * @param {string} fileRef    展示用的文件引用
 * @param {object} opts       { modules:[{name,dekey}], deep:boolean, headingHint:string }
 */
function extractClaims(text, fileRef, opts) {
  const options = opts || {};
  const moduleList = options.modules || [];
  const deep = !!options.deep;
  const clean = stripNoise(text);
  const lines = clean.split('\n');
  const baseName = String(fileRef).split('/').pop();
  const out = [];
  let heading = options.headingHint || '';

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.replace(/\|/g, ' ');
    const trimmedRaw = raw.trim();
    if (/^#{1,6}\s+/.test(trimmedRaw)) { heading = trimmedRaw.replace(/^#{1,6}\s+/, ''); }

    const spanish = lineModules(line, moduleList);
    const modRes = lineModules(trimmedRaw, moduleList);
    const sectionRes = lineModules(heading, moduleList);
    const moduleOf = (r) => (r && r.module) || null;
    const lineModule = modRes.module || moduleOf(spanish) || sectionRes.module;

    const taken = [];
    const overlaps = (s, e) => taken.some((t) => !(e <= t[0] || s >= t[1]));

    const patterns = deep ? PATTERNS.concat([DEEP_BARE]) : PATTERNS;
    for (const p of patterns) {
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(line)) !== null) {
        if (m[0].length === 0) { p.re.lastIndex++; continue; }
        const start = m.index;
        const end = start + m[0].length;
        if (overlaps(start, end)) continue;

        let claim = null;
        if (p.kind === 'ref') {
          claim = {
            kind: 'ref', subtype: p.subtype,
            key: p.subtype, keyTokens: [p.subtype], primaryToken: p.subtype,
            value: { type: 'ref', raw: m[0], ref: String(m[1]).toLowerCase() }
          };
        } else if (p.kind === 'ratio') {
          const ctxRaw = contextKey(line, start, end, null);
          const keyTokens = ctxRaw.keyTokens;
          const primaryToken = ctxRaw.primaryToken;
          const numerator = m[1], denominator = m[2];
          if (isNoiseNumber(numerator, null, primaryToken) && keyTokens.length === 0) { continue; }
          claim = {
            kind: 'ratio',
            key: keyTokens.length ? ctxRaw.key : 'ratio',
            keyTokens: keyTokens.length ? keyTokens : ['ratio'],
            primaryToken: primaryToken || 'ratio',
            value: mkRatio(numerator, denominator)
          };
        } else if (p.kind === 'loc') {
          // 行号引用（第 45 行）不是规模声明，丢弃
          if (/第\s*$/.test(line.slice(Math.max(0, start - 4), start))) { continue; }
          const num = parseNum(m[1]);
          // 行数的合理区间：太小的几乎是行号，太大的几乎不是单文件
          if (num == null || num < 10 || num > 200000) { continue; }
          const c = contextKey(line, start, end, 'loc');
          if (!c.keyTokens.length) { continue; }
          claim = {
            kind: 'loc',
            key: c.key, keyTokens: c.keyTokens, primaryToken: c.primaryToken,
            value: { type: 'scalar', raw: m[0], number: num, unit: '行', dim: 'loc', base: num },
            // 数字前的 80 字符：LOC 核验只在这个窗口里找文件名主干，
            // 防止「句子里远远提到某文件」被当成该行数声明的指向
            locPrefix: line.slice(Math.max(0, start - 80), start)
          };
        } else {
          const keyText = p.keyGroup ? m[p.keyGroup] : null;
          const numText = m[p.numGroup];
          const unit = p.unitGroup ? m[p.unitGroup] : null;
          let keyTokens, primaryToken, key;
          if (keyText) {
            keyTokens = tokens(keyText);
            // 单个 "\" 或 "v" 之类前缀不接受
            primaryToken = keyTokens.length ? keyTokens[keyTokens.length - 1] : null;
            key = keyTokens.join('-');
          } else {
            const unitToken = unit ? String(unit).toLowerCase() : null;
            const c = contextKey(line, start, end, unitToken);
            keyTokens = c.keyTokens; primaryToken = c.primaryToken; key = c.key;
          }
          if (!keyTokens.length) { continue; }
          if (isNoiseNumber(numText, unit, primaryToken)) { continue; }
          // 版本号类数字（1.2.3 / v3.3）：前一个字符是 "." 或 key 为 "v" 时丢弃
          if (start > 0 && line[start - 1] === '.') { continue; }
          if (keyTokens.length === 1 && keyTokens[0] === 'v') { continue; }
          claim = {
            kind: p.kind,
            key, keyTokens, primaryToken,
            value: mkValue(numText, unit)
          };
        }

        if (!claim) continue;
        claim.id = baseName + ':L' + (i + 1) + ':' + claim.kind + ':' + claim.key;
        claim.file = fileRef;
        claim.line = i + 1;
        claim.module = lineModule;
        claim.modulesAll = modRes.all.length ? modRes.all : (sectionRes.all || []);
        claim.heading = heading.slice(0, 120);
        claim.sentence = trimmedRaw.slice(0, 240);
        out.push(claim);
        taken.push([start, end]);
      }
    }
  }
  return out;
}

module.exports = { extractClaims, stripNoise, contextKey, lineModules, PATTERNS };
