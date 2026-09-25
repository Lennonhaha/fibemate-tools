'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const { iterate } = require('./walk');
const { tokens, valueFromString, squash } = require('./normalize');
const { extractClaims } = require('./claims');

/**
 * 产出物收集器：把 JSON / 文本报告 / 日志里的数字摊平成
 * `{source, path, keyTokens, primaryToken, module, value}` 条目，供解析器比对。
 *
 * 关键设计：JSON 的字符串叶子会再走一次声明抽取器，于是
 * `"verification": "KAT 10000/10000 Noble cross-validated, TVLA 3/3 PASS"`
 * 会变成两条独立可比对条目 `…verification#kat` 与 `…verification#tvla`。
 * 这样文档里写的「KAT 10,000/10,000」就能直接对上，不需要人工写绑定表。
 */

const TEXT_EXT = new Set(['.md', '.log', '.txt', '.csv', '.rpt', '.twr', '.out', '.yaml', '.yml']);
const PRESENCE_EXT = new Set(['.tsr', '.pdf', '.json', '.md', '.bin', '.hex', '.bit']);
// 代码文件：只数行数（供「N 行」声明核验），不抽取声明
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.py', '.c', '.h', '.cc', '.cpp', '.rs', '.go', '.java']);
const CODE_LINE_MAX_BYTES = 4 * 1024 * 1024;
const MAX_LEAVES_PER_FILE = 4000;

function extOf(rel) {
  const i = rel.lastIndexOf('.');
  return i < 0 ? '' : rel.slice(i).toLowerCase();
}

function moduleOf(str, modules) {
  const s = squash(str);
  let best = null;
  for (const m of modules) {
    if (m.dekey && s.indexOf(m.dekey) >= 0) {
      if (!best || m.name.length > best.length) best = m.name;
    }
  }
  return best;
}

function leafEntry(source, pathStr, value, raw, modules) {
  const combo = source + ' ' + pathStr;
  const keyTokens = tokens(pathStr.replace(/#/g, ' '));
  return {
    source,
    path: pathStr,
    keyTokens,
    primaryToken: keyTokens.length ? keyTokens[keyTokens.length - 1] : null,
    module: moduleOf(combo, modules),
    value,
    raw: raw == null ? null : String(raw).slice(0, 300)
  };
}

function walkJson(node, basePath, sink, modules, source) {
  const seen = [];

  (function rec(val, p) {
    if (sink.length >= MAX_LEAVES_PER_FILE) return;
    if (val == null) { sink.push(leafEntry(source, p, null, null, modules)); return; }
    const t = typeof val;
    if (t === 'number' || t === 'boolean') {
      sink.push(leafEntry(source, p, valueFromString(String(val)), val, modules));
      return;
    }
    if (t === 'string') {
      const v = valueFromString(val);
      if (v) sink.push(leafEntry(source, p, v, val, modules));
      // 字符串里嵌着多个度量时，逐个拆出来
      if (/[\d]/.test(val)) {
        const sub = extractClaims(val, source, { modules });
        for (const c of sub) {
          sink.push(leafEntry(source, p + '#' + c.key, c.value, c.value.raw, modules));
        }
      }
      return;
    }
    if (Array.isArray(val)) {
      const cap = Math.min(val.length, 200);
      for (let i = 0; i < cap; i++) rec(val[i], p + '[' + i + ']');
      return;
    }
    if (t === 'object') {
      if (seen.indexOf(val) >= 0) return; // 环保护
      seen.push(val);
      for (const k of Object.keys(val)) rec(val[k], p ? p + '.' + k : k);
    }
  })(node, basePath);
}

function countLines(text) {
  // 与 wc -l 一致：统计换行符数；末行无换行时补 1
  if (!text.length) return 0;
  let n = 0;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return text.charCodeAt(text.length - 1) === 10 ? n : n + 1;
}

function collectFile(file, roots, modules, maxBytes, fileLines) {
  const rel = roots.relLabel(file);
  const ext = extOf(rel);
  const out = [];
  try {
    if (ext === '.json') {
      const text = fs.readFileSync(file, 'utf8');
      if (maxBytes && Buffer.byteLength(text) > maxBytes) return out;
      let data;
      try { data = JSON.parse(text); } catch (_) { return out; }
      walkJson(data, '', out, modules, rel);
      return out;
    }
    if (TEXT_EXT.has(ext)) {
      const text = fs.readFileSync(file, 'utf8');
      if (maxBytes && Buffer.byteLength(text) > maxBytes) return out;
      if (fileLines) fileLines.set(rel, countLines(text));
      const claims = extractClaims(text, rel, { modules });
      for (const c of claims) {
        out.push({
          source: rel,
          path: rel + '#L' + c.line + '#' + c.key,
          keyTokens: c.keyTokens,
          primaryToken: c.primaryToken,
          module: c.module || moduleOf(rel, modules),
          value: c.value,
          raw: c.sentence
        });
      }
      return out;
    }
  } catch (_) {
    return out;
  }
  return out;
}

/**
 * @returns {{entries:Array, presence:Array<string>, scanned:number, skipped:number}}
 */
function collectArtifacts(cfg, modules) {
  const entries = [];
  const presence = [];
  const fileLines = new Map();        // 文本文件 rel → 行数（供「N 行」声明核验）
  let scanned = 0;
  let skipped = 0;
  const maxBytes = cfg.artifacts.maxFileBytes;
  const seen = new Set();               // 根目录互相嵌套时去重，否则会产生「双候选→ambiguous」
  const seenPresence = new Set();
  const relRoot = path;

  const matchInclude = (rel) => {
    const ext = extOf(rel);
    return ext === '.json' || TEXT_EXT.has(ext);
  };

  const handleDir = (root) => {
    const rootLabel = path.basename(root) || root;
    for (const f of iterate(root, {
      exclude: cfg.artifacts.exclude,
      matchInclude,
      maxFileBytes: maxBytes,
      maxFiles: cfg.artifacts.maxFiles,
      maxDepth: cfg.artifacts.maxDepth
    })) {
      const key = relRoot.resolve(f.full);
      if (seen.has(key)) continue;
      seen.add(key);
      const got = collectFile(f.full, { relLabel: () => rootLabel + '/' + f.rel }, modules, maxBytes, fileLines);
      if (!got.length) skipped++; else scanned++;
      for (const e of got) { e.abs = key; entries.push(e); }
    }
    // 存在性名录（供 TSR 这类引用型声明核验）：只记名字不读内容
    for (const f of iterate(root, {
      exclude: cfg.artifacts.exclude,
      matchInclude: () => true,
      maxFiles: 20000,
      maxDepth: cfg.artifacts.maxDepth
    })) {
      const key = 'p:' + relRoot.resolve(f.full);
      if (seenPresence.has(key)) continue;
      seenPresence.add(key);
      presence.push(rootLabel + '/' + f.rel);
      // 代码文件顺带数行数（「N 行」声明的证据），不抽取声明
      if (CODE_EXT.has(extOf(f.rel)) && (!f.size || f.size <= CODE_LINE_MAX_BYTES)) {
        try {
          const text = fs.readFileSync(f.full, 'utf8');
          fileLines.set(rootLabel + '/' + f.rel, countLines(text));
        } catch (_) { /* 读失败就跳过，行数证据不是必须的 */ }
      }
    }
  };

  for (const rootInput of cfg.artifacts.roots) {
    const abs = path.resolve(cfg.__cwd || process.cwd(), rootInput);
    let st = null;
    try { st = fs.statSync(abs); } catch (_) { continue; }
    if (st.isDirectory()) { handleDir(abs); continue; }
    if (!st.isFile()) continue;
    const base = path.basename(abs);
    const parent = path.basename(path.dirname(abs));
    const rel = base;
    const label = parent ? parent + '/' + base : base;
    const key = relRoot.resolve(abs);
    if (seen.has(key)) continue;
    seen.add(key);
    seenPresence.add('p:' + key);
    presence.push(label);
    const got = collectFile(abs, { relLabel: () => label }, modules, maxBytes, fileLines);
    if (!got.length) skipped++; else scanned++;
    for (const e of got) { e.abs = key; entries.push(e); }
  }

  // 存在性专用根：只读文件名，不读内容（TSR / TSQ / 哈希清单）
  for (const rootInput of (cfg.artifacts.presenceRoots || [])) {
    const abs = path.resolve(cfg.__cwd || process.cwd(), rootInput);
    let st = null;
    try { st = fs.statSync(abs); } catch (_) { continue; }
    const rootLabel = st.isDirectory() ? (path.basename(abs) || '') : path.basename(path.dirname(abs));
    const emit = (full, rel) => {
      const key = 'p:' + path.resolve(full);
      if (seenPresence.has(key)) return;
      seenPresence.add(key);
      presence.push(rootLabel ? rootLabel + '/' + rel : rel);
    };
    if (st.isFile()) { emit(abs, path.basename(abs)); continue; }
    for (const f of iterate(abs, {
      exclude: cfg.artifacts.exclude,
      matchInclude: () => true,
      maxFiles: 40000,
      maxDepth: cfg.artifacts.maxDepth
    })) emit(f.full, f.rel);
  }

  const denyRe = require('./walk').compilePatterns(cfg.artifacts.deny || []);
  const denied = (e) => denyRe.some((re) => re.test(e.source + '::' + e.path) || re.test(e.source));
  const keep = [];
  for (const e of entries) { if (!denied(e)) keep.push(e); }

  return { entries: keep, presence, scanned, skipped, denied: entries.length - keep.length, fileLines: Array.from(fileLines.entries()) };
}

// 过于通用的 token 不进倒排索引，否则候选集会爆炸（"count" 之类几乎命中一切）。
const STOP_TOKENS = new Set([
  'id', 'name', 'type', 'file', 'files', 'list', 'index', 'value', 'values', 'data', 'note', 'notes',
  'title', 'version', 'status', 'state', 'path', 'source', 'key', 'keys', 'level', 'size', 'number',
  'result', 'results', 'date', 'time', 'ts', 'msg', 'level0', 'text', 'item', 'items', 'ref', 'desc'
]);

/** primaryToken → 条目数组 + 全部 token → 条目数组。粒度放宽是为了 recall，质量由评分把关。 */
function buildIndex(artifacts) {
  const byToken = new Map();
  const push = (k, e) => {
    if (!byToken.has(k)) byToken.set(k, []);
    byToken.get(k).push(e);
  };
  for (const e of artifacts.entries) {
    const withPrimary = new Set(e.keyTokens);
    if (e.primaryToken) withPrimary.add(e.primaryToken);
    for (const k of withPrimary) {
      if (STOP_TOKENS.has(k)) continue;
      if (k.length < 2 && !/^\d+$/.test(k)) continue;
      push(k, e);
    }
  }
  const presenceSquash = new Map();
  for (const p of artifacts.presence) {
    const sq = squash(p);
    if (!presenceSquash.has(sq)) presenceSquash.set(sq, []);
    presenceSquash.get(sq).push(p);
  }
  return { byToken, presence: artifacts.presence, presenceSquash, entries: artifacts.entries, fileLines: new Map(artifacts.fileLines || []) };
}

module.exports = { collectArtifacts, buildIndex, collectFile, extOf, moduleOf, TEXT_EXT, PRESENCE_EXT };
