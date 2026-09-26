// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('fs');
const { spawn } = require('child_process');
const { ImplUnavailable, ImplError } = require('../errors');
const U = require('../util');

/**
 * liboqs 桥接：一个长期进程，stdin 写命令、stdout 读结果。
 * 批协议见 tools/oqsbridge.c。
 *
 * 现状：D:\FIBEMATE\liboqs-build 是算法全禁用的空壳构建，OQS_KEM_new 会返回 NULL，
 * 适配器因此标记 unavailable —— 不假装它能当参考实现。
 * 用户若编出完整 liboqs，把 config 里的 path 指过去即可自动启用。
 */
function create(spec) {
  if (!fs.existsSync(spec.path)) {
    throw new ImplUnavailable('桥接可执行文件不存在', { path: spec.path });
  }

  let proc = null;
  let queue = [];
  let buf = '';
  let dead = false;
  let deadReason = null;

  function ensure() {
    if (proc) return proc;
    proc = spawn(spec.path, [], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    proc.stdout.setEncoding('utf8');
    proc.stdout.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        const wait = queue.shift();
        if (wait) wait(line);
      }
    });
    proc.stderr.on('data', () => { /* 静默，避免污染 stdout 协议 */ });
    proc.on('exit', (code) => {
      dead = true;
      deadReason = 'bridge exited: code=' + code;
      while (queue.length) { const w = queue.shift(); w('ERR bridge_exit'); }
    });
    proc.on('error', (e) => {
      dead = true;
      deadReason = e.message;
      while (queue.length) { const w = queue.shift(); w('ERR spawn_error'); }
    });
    return proc;
  }

  function send(line) {
    return new Promise((resolve) => {
      if (dead) return resolve({ ok: false, err: deadReason || 'bridge dead' });
      const p = ensure();
      queue.push(resolve);
      try { p.stdin.write(line + '\n'); } catch (_) { return resolve({ ok: false, err: 'stdin write failed' }); }
      setTimeout(() => {
        const i = queue.indexOf(resolve);
        if (i >= 0) { queue.splice(i, 1); resolve({ ok: false, err: 'timeout' }); }
      }, 15000);
    }).then((line2) => {
      if (typeof line2 !== 'string') return { ok: false, err: 'no response' };
      const parts = line2.split(/\s+/);
      if (parts[0] !== 'OK') return { ok: false, err: parts.slice(1).join(' ') || 'unknown' };
      return { ok: true, args: parts.slice(1) };
    });
  }

  return {
    spec,
    kind: 'liboqs-bridge',
    async probe() {
      const r = await send('sizes');
      if (!r.ok) return { available: false, reason: r.err };
      return { available: true, sizes: r.args.map(Number) };
    },
    async keygen() {
      const r = await send('keygen');
      if (!r.ok) throw new ImplError('liboqs keygen 失败', { err: r.err });
      return { pk: U.fromHex(r.args[0]), sk: U.fromHex(r.args[1]) };
    },
    async encaps(pk) {
      const r = await send('encaps ' + U.toHex(pk));
      if (!r.ok) throw new ImplError('liboqs encaps 失败', { err: r.err });
      return { ct: U.fromHex(r.args[0]), ss: U.fromHex(r.args[1]) };
    },
    async decaps(sk, ct) {
      const r = await send('decaps ' + U.toHex(sk) + ' ' + U.toHex(ct));
      if (!r.ok) throw new ImplError('liboqs decaps 失败', { err: r.err });
      return U.fromHex(r.args[0]);
    },
    close() { if (proc) { try { proc.kill(); } catch (_) { /* noop */ } proc = null; } }
  };
}

module.exports = { create };
