'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * 增量缓存：以「文件集合的 mtime+size 指纹」为 key。
 * 命中则完全跳过产出物解析（扫描阶段最贵的一段），这是性能的主要来源。
 */

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function fileSignature(roots, cfg) {
  const list = [];
  const walkDir = (dir, rootAbs, depth) => {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const e of ents) {
      const full = path.join(dir, e.name);
      const rel = path.relative(rootAbs, full).split(path.sep).join('/');
      if (e.isDirectory()) {
        if (cfg.exclude.some((p) => new RegExp('^' + p.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*') + '/?$').test(rel + '/'))) continue;
        if (cfg.maxDepth && rel.split('/').length > cfg.maxDepth) continue;
        walkDir(full, rootAbs, depth + 1);
        continue;
      }
      let st = null;
      try { st = fs.statSync(full); } catch (_) { continue; }
      list.push([rel, st.mtimeMs, st.size]);
    }
  };
  for (const r of roots) {
    const abs = path.resolve(r);
    let st = null;
    try { st = fs.statSync(abs); } catch (_) { continue; }
    if (st.isDirectory()) walkDir(abs, abs, 0);
    else list.push([path.basename(abs), st.mtimeMs, st.size]);
  }
  list.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return crypto.createHash('sha256').update(JSON.stringify(list)).digest('hex').slice(0, 32);
}

function cachePaths(cfg, cwd) {
  const dir = path.resolve(cwd, cfg.cache.dir || '.verifact');
  return { dir, file: path.join(dir, 'artifact-cache.json'), history: path.join(dir, 'history.jsonl') };
}

function readArtifactCache(cfg, cwd, roots) {
  if (!cfg.cache.enabled) return { hit: false, reason: 'disabled' };
  const p = cachePaths(cfg, cwd);
  if (!fs.existsSync(p.file)) return { hit: false, reason: 'no_cache_file' };
  try {
    const raw = JSON.parse(fs.readFileSync(p.file, 'utf8'));
    const sig = fileSignature(roots, { exclude: cfg.artifacts.exclude, maxDepth: cfg.artifacts.maxDepth });
    if (raw.signature !== sig) return { hit: false, reason: 'stale', staged: raw };
    return { hit: true, entries: raw.entries || [], presence: raw.presence || [], scanned: raw.scanned || 0, skipped: raw.skipped || 0, fileLines: raw.fileLines || [], signature: sig };
  } catch (_) {
    return { hit: false, reason: 'corrupt' };
  }
}

function writeArtifactCache(cfg, cwd, roots, artifacts) {
  if (!cfg.cache.enabled) return false;
  const p = cachePaths(cfg, cwd);
  try {
    ensureDir(p.dir);
    const payload = {
      version: 1,
      signature: fileSignature(roots, { exclude: cfg.artifacts.exclude, maxDepth: cfg.artifacts.maxDepth }),
      entries: artifacts.entries,
      presence: artifacts.presence,
      scanned: artifacts.scanned,
      skipped: artifacts.skipped,
      fileLines: artifacts.fileLines || []
    };
    fs.writeFileSync(p.file, JSON.stringify(payload));
    return true;
  } catch (_) {
    return false;
  }
}

module.exports = { readArtifactCache, writeArtifactCache, fileSignature, cachePaths, ensureDir };
