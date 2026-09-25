'use strict';
// SPDX-License-Identifier: Apache-2.0

let seq = 0;
function requestId() {
  seq = (seq + 1) % 1000000;
  return Date.now().toString(36) + '-' + seq.toString(36);
}

/** 结构化 JSON 日志。禁止记录令牌、密钥、隐私正文。 */
function emit(level, msg, fields) {
  const rec = { ts: new Date().toISOString(), level, msg };
  if (fields && typeof fields === 'object') Object.assign(rec, fields);
  process.stderr.write(JSON.stringify(rec) + '\n');
}

function create(opts) {
  const quiet = !!(opts && opts.quiet);
  const base = (opts && opts.base) || {};
  return {
    requestId,
    debug: (m, f) => { if (!quiet) emit('debug', m, Object.assign({}, base, f)); },
    info: (m, f) => { if (!quiet) emit('info', m, Object.assign({}, base, f)); },
    warn: (m, f) => emit('warn', m, Object.assign({}, base, f)),
    error: (m, f) => emit('error', m, Object.assign({}, base, f))
  };
}

module.exports = { create, requestId, emit };
