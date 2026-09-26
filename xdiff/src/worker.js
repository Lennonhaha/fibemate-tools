// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * 样本级 worker：常驻进程，加载全部实现一次，之后反复执行单次密码学操作。
 * 只返回可序列化的观测值（hex），判定逻辑一律留在主线程。
 */

const { parentPort, workerData } = require('worker_threads');
const { loadOne } = require('./impls/registry');
const { withSeed } = require('./impls/registry');
const U = require('./util');

const loaded = new Map();
let cfg = null;
let ready = false;
let readyErr = null;

async function init(config) {
  cfg = config;
  for (const spec of cfg.implementations) {
    if (spec.enabled === false) continue;
    try {
      const rec = await loadOne(spec, null, { skipProbe: true });
      if (rec.status === 'ready') loaded.set(spec.id, rec.impl);
    } catch (_) { /* 主线程已报告过 */ }
  }
  ready = true;
}

function getImpl(id) {
  const im = loaded.get(id);
  if (!im) throw new Error('worker 内未加载实现: ' + id);
  return im;
}

async function exec(task) {
  const impl = getImpl(task.implId);
  const seedCtx = { masterSeed: cfg.masterSeed, caseIndex: task.caseIndex || 0, purpose: task.purpose || task.op };
  const t0 = U.nowMs();

  const { result, rngProfile } = await withSeed(seedCtx, async () => {
    switch (task.op) {
      case 'keygen': {
        const k = await impl.keygen();
        return { pk: U.toHex(k.pk), sk: U.toHex(k.sk) };
      }
      case 'encaps': {
        const e = await impl.encaps(U.fromHex(task.pk));
        return { ct: U.toHex(e.ct), ss: U.toHex(e.ss) };
      }
      case 'decaps': {
        const ss = await impl.decaps(U.fromHex(task.sk), U.fromHex(task.ct));
        return { ss: U.toHex(ss) };
      }
      case 'flipdecaps': {
        // 失败性解密：翻转一位后解封装。异常要被捕获，因为「抛异常」本身就是一种实现缺陷
        const ct = U.flipBit(U.fromHex(task.ct), task.bit || 0);
        let threw = null;
        let ss = null;
        try {
          ss = U.toHex(await impl.decaps(U.fromHex(task.sk), ct));
        } catch (e) {
          threw = String(e && e.message ? e.message : e);
        }
        return { ss, threw, flippedCt: U.toHex(ct) };
      }
      default:
        throw new Error('未知操作: ' + task.op);
    }
  });

  return { result, rngProfile, ms: Number((U.nowMs() - t0).toFixed(3)) };
}

if (parentPort) {
  parentPort.on('message', async (msg) => {
    if (msg.type === 'init') {
      try { await init(msg.cfg); parentPort.postMessage({ type: 'ready' }); }
      catch (e) { readyErr = String(e && e.message ? e.message : e); parentPort.postMessage({ type: 'ready', error: readyErr }); }
      return;
    }
    if (msg.type === 'exec') {
      if (!ready) { try { await init(msg.cfg || cfg); } catch (_) { /* noop */ } }
      try {
        const out = await exec(msg.task);
        parentPort.postMessage({ type: 'result', id: msg.id, ok: true, ...out });
      } catch (e) {
        parentPort.postMessage({ type: 'result', id: msg.id, ok: false, error: String(e && e.message ? e.message : e) });
      }
      return;
    }
    if (msg.type === 'shutdown') {
      for (const im of loaded.values()) if (im.close) { try { im.close(); } catch (_) { /* noop */ } }
      process.exit(0);
    }
  });
}

module.exports = { init, exec };
