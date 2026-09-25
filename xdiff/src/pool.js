// SPDX-License-Identifier: Apache-2.0
'use strict';

const path = require('path');
const { Worker } = require('worker_threads');
const { cpuCount } = require('./config');

/**
 * 常驻 worker 池。每个 worker 启动时加载全部实现一次，
 * 之后只接收 {op, implId, ...} 这类小任务，避免重复 import / spawn 的开销。
 */
class Pool {
  constructor(cfg, opts) {
    const o = opts || {};
    this.cfg = cfg;
    const configured = (cfg.pool && cfg.pool.workers) || 0;
    const auto = Math.max(2, Math.min(6, cpuCount() - 1));
    this.size = o.workers || (configured > 0 ? Math.min(configured, 12) : auto);
    this.timeoutMs = (cfg.pool && cfg.pool.timeoutMs) || 120000;
    this.workers = [];
    this.next = 0;
    this.seq = 0;
    this.stats = { tasks: 0, retries: 0, errors: 0 };
  }

  async init(log) {
    const cfgForWorker = {
      masterSeed: this.cfg.masterSeed,
      implementations: this.cfg.implementations.map((i) => ({
        id: i.id, label: i.label, type: i.type, path: i.path, enabled: i.enabled
      }))
    };
    const inits = [];
    for (let i = 0; i < this.size; i++) {
      const w = new Worker(path.join(__dirname, 'worker.js'), { workerData: {} });
      const slot = { worker: w, busy: false, id: i };
      this.workers.push(slot);
      inits.push(new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('worker init timeout')), 30000);
        w.once('message', (m) => {
          if (m.type === 'ready') { clearTimeout(timer); if (m.error) reject(new Error(m.error)); else resolve(); }
        });
        w.on('error', (e) => { clearTimeout(timer); reject(e); });
        w.postMessage({ type: 'init', cfg: cfgForWorker });
      }));
    }
    await Promise.all(inits);
    if (log) log.info('pool_ready', { workers: this.size });
  }

  _take() {
    // 找空闲 slot，没有就轮转（任务会排队在 worker 内部）
    for (const s of this.workers) if (!s.busy) return s;
    const s = this.workers[this.next % this.workers.length];
    this.next++;
    return s;
  }

  exec(task) {
    return new Promise((resolve, reject) => {
      const slot = this._take();
      const id = ++this.seq;
      slot.busy = true;
      const timer = setTimeout(() => {
        slot.busy = false;
        reject(new Error('task timeout: ' + task.op));
      }, this.timeoutMs);
      const onMsg = (m) => {
        if (m.type !== 'result' || m.id !== id) return;
        clearTimeout(timer);
        slot.worker.off('message', onMsg);
        slot.busy = false;
        this.stats.tasks++;
        if (!m.ok) { this.stats.errors++; return reject(new Error(m.error || 'worker error')); }
        resolve(m);
      };
      slot.worker.on('message', onMsg);
      slot.worker.postMessage({ type: 'exec', id, task });
    });
  }

  /** 批量执行，保持输入顺序。单个任务失败不炸整批。 */
  async runAll(tasks) {
    const settled = await Promise.all(tasks.map((t) =>
      this.exec(t).then((r) => ({ ok: true, task: t, r }), (e) => ({ ok: false, task: t, error: String(e.message || e) }))
    ));
    return settled;
  }

  shutdown() {
    for (const s of this.workers) {
      try { s.worker.postMessage({ type: 'shutdown' }); } catch (_) { /* noop */ }
      setTimeout(() => { try { s.worker.terminate(); } catch (_) { /* noop */ } }, 200);
    }
    this.workers = [];
  }
}

module.exports = { Pool };
