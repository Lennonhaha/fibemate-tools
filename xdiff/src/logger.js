// SPDX-License-Identifier: Apache-2.0
'use strict';

/** 结构化 JSON 日志，一行一条，带请求/运行 ID。不记录密钥材料。 */

function create(opts) {
  const o = opts || {};
  const quiet = !!o.quiet;
  const level = o.level || 'info';
  const runId = o.runId || Math.random().toString(36).slice(2, 10);
  const ORDER = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
  const min = ORDER[level] || 20;

  function emit(lvl, event, fields) {
    if (quiet) return;
    if (ORDER[lvl] < min) return;
    const rec = { ts: new Date().toISOString(), level: lvl, runId, event };
    if (fields && typeof fields === 'object') {
      for (const k of Object.keys(fields)) {
        const v = fields[k];
        if (v === undefined || typeof v === 'function') continue;
        rec[k] = v;
      }
    }
    process.stderr.write(JSON.stringify(rec) + '\n');
  }

  return {
    runId,
    debug: (e, f) => emit('debug', e, f),
    info: (e, f) => emit('info', e, f),
    warn: (e, f) => emit('warn', e, f),
    error: (e, f) => emit('error', e, f)
  };
}

module.exports = { create };
