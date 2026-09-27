// SPDX-License-Identifier: Apache-2.0
'use strict';

const { installRng } = require('../rng');
const { ImplUnavailable } = require('../errors');

const FACTORIES = {
  'js-mlkem': () => require('./jsMlkem'),
  'noble-mlkem': () => require('./noble'),
  'liboqs-bridge': () => require('./liboqs')
};

/**
 * 用确定性随机源执行一次操作。
 * 会在执行期间替换 globalThis.crypto，结束后还原，并记录 RNG 调用序列。
 *
 * @returns {{result: *, rngProfile: number[], seed: string}}
 */
async function withSeed({ masterSeed, caseIndex, purpose }, fn) {
  const { subSeed } = require('../rng');
  const seed = subSeed(Buffer.from(String(masterSeed), 'utf8'), caseIndex, purpose);
  const label = purpose + '#' + caseIndex;
  const h = installRng({ seed, label });
  try {
    const result = await fn();
    return { result, rngProfile: h.drbg.calls.slice(), seed: seed.toString('hex').slice(0, 16) };
  } finally {
    h.restore();
  }
}

async function loadOne(spec, log, opts) {
  const o = opts || {};
  const rec = { id: spec.id, label: spec.label || spec.id, type: spec.type, path: spec.path, note: spec.note || null };
  if (spec.enabled === false) {
    rec.status = 'disabled';
    rec.reason = '配置中已禁用';
    return rec;
  }
  const factory = FACTORIES[spec.type];
  if (!factory) {
    rec.status = 'unavailable';
    rec.reason = '未知实现类型: ' + spec.type;
    return rec;
  }
  try {
    const impl = await factory().create(spec);
    if (typeof impl.probe === 'function') {
      const p = await impl.probe();
      if (!p.available) {
        rec.status = 'unavailable';
        rec.reason = p.reason;
        if (impl.close) impl.close();
        return rec;
      }
      rec.sizes = p.sizes || null;
    }
    rec.impl = impl;
    rec.status = 'ready';
    if (o.skipProbe) return rec;
    // 顺带测一次最小操作，确认真的能算（不是只加载成功）
    const t0 = Date.now();
    try {
      const k = await withSeed({ masterSeed: 'probe', caseIndex: 0, purpose: 'probe' }, () => impl.keygen());
      rec.readyMs = Date.now() - t0;
      rec.rngProfileKeygen = k.rngProfile;
      rec.probeOk = true;
    } catch (e) {
      rec.probeOk = false;
      rec.reason = '探测性 keygen 失败: ' + (e && e.message ? e.message : String(e));
      rec.status = 'unavailable';
      if (impl.close) impl.close();
      rec.impl = null;
    }
  } catch (e) {
    rec.status = 'unavailable';
    rec.reason = (e instanceof ImplUnavailable)
      ? e.message
      : ('加载失败: ' + (e && e.message ? e.message : String(e)));
    rec.detail = e && e.detail ? e.detail : null;
  }
  return rec;
}

async function loadAll(cfg, log) {
  const out = [];
  for (const spec of cfg.implementations) {
    const rec = await loadOne(spec, log);
    if (log) {
      log.info('impl_loaded', { id: rec.id, status: rec.status, reason: rec.reason || null });
    }
    out.push(rec);
  }
  return out;
}

module.exports = { loadAll, loadOne, withSeed, FACTORIES };
