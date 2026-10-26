'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const { cachePaths, ensureDir } = require('./core/cache');

/**
 * 追加式历史记录（JSONL）。用途：看某个声明的状态是否在两次运行之间发生变化，
 * 让 drift 能被追溯「什么时候开始漂的」。
 *
 * schema 2（#96）：state map 的键从行号 id 换成内容寻址的 stableKey。
 * 旧 schema 1 的记录不迁移、不猜：行号制的记录里没保存上下文，任何
 * 「file + kind + key 相同就算同一条」的启发式都会在多条声明共用 key 时误判，
 * 而且会把「插了一行」读成迁移。宁可让比较基准断一次，也不制造假迁移。
 */

const HISTORY_SCHEMA = 2;

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
  const out = [];
  let legacy = 0;
  try {
    const p = cachePaths(cfg, cwd);
    if (!fs.existsSync(p.history)) return out;
    const lines = fs.readFileSync(p.history, 'utf8').split('\n').filter(Boolean);
    for (const l of lines) {
      let r;
      try { r = JSON.parse(l); } catch (_) { continue; }
      if (!r || r.schema !== HISTORY_SCHEMA) { legacy++; continue; }
      out.push(r);
    }
    // 读取侧的 legacyDropped 让调用方能说明「这次比较的基准为什么变短了」。
    // 注意必须挂在 slice 之后的数组上：slice 会丢掉原数组上的自定义属性。
    const kept = out.slice(-(limit || 50));
    if (legacy) Object.defineProperty(kept, 'legacyDropped', { value: legacy, enumerable: false });
    return kept;
  } catch (_) {
    return out;
  }
}

/**
 * 两次运行之间的状态迁移（键为 stableKey，见 src/core/stable-key.js）。
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
    changes.push({ key: id, from, to });
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

module.exports = { appendRun, readRuns, diffRuns, HISTORY_SCHEMA };
