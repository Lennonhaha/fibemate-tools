'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const { cachePaths, ensureDir } = require('./core/cache');

/**
 * 追加式历史记录（JSONL）。用途：看某个声明的状态是否在两次运行之间发生变化，
 * 让 drift 能被追溯「什么时候开始漂的」。
 */

function appendRun(cfg, cwd, summary) {
  if (!cfg.cache.enabled) return false;
  try {
    const p = cachePaths(cfg, cwd);
    ensureDir(p.dir);
    fs.appendFileSync(p.history, JSON.stringify(summary) + '\n', 'utf8');
    trim(p.history, cfg.cache.maxHistory || 200);
    return true;
  } catch (_) {
    return false;
  }
}

function trim(file, keep) {
  try {
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    if (lines.length <= keep) return;
    fs.writeFileSync(file, lines.slice(-keep).join('\n') + '\n', 'utf8');
  } catch (_) { /* noop */ }
}

function readRuns(cfg, cwd, limit) {
  try {
    const p = cachePaths(cfg, cwd);
    if (!fs.existsSync(p.history)) return [];
    const lines = fs.readFileSync(p.history, 'utf8').split('\n').filter(Boolean);
    const out = [];
    for (const l of lines.slice(-(limit || 50))) {
      try { out.push(JSON.parse(l)); } catch (_) { /* skip broken line */ }
    }
    return out;
  } catch (_) {
    return [];
  }
}

/**
 * 两次运行之间的状态迁移。
 * state map 只收录非 unbound 的声明（unbound 数量级太大，且没有迁移信息量），
 * 因此「缺席」一律按 unbound 解释。
 */
function diffRuns(prev, curr) {
  const a = (prev && prev.states) || {};
  const b = (curr && curr.states) || {};
  const ids = new Set(Object.keys(a).concat(Object.keys(b)));
  const changes = [];
  for (const id of ids) {
    const from = a[id] || 'unbound';
    const to = b[id] || 'unbound';
    if (from === to) continue;
    changes.push({ id, from, to });
  }

  const pick = (fn) => changes.filter(fn);
  return {
    all: changes,
    newDrift: pick((c) => c.to === 'drift' && c.from !== 'drift'),
    resolvedDrift: pick((c) => c.from === 'drift' && c.to !== 'drift'),
    newVerified: pick((c) => c.to === 'verified' && c.from !== 'verified'),
    lostVerified: pick((c) => c.from === 'verified' && c.to !== 'verified'),
    newMissingRef: pick((c) => c.to === 'ref-missing' && c.from !== 'ref-missing')
  };
}

module.exports = { appendRun, readRuns, diffRuns };
