'use strict';
// SPDX-License-Identifier: Apache-2.0

const os = require('os');
const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const { extractClaims } = require('./core/claims');
const { lintDoc } = require('./core/lint');

/**
 * worker_threads 池。文档扫描是 CPU 密集且与 IO 交错的活，
 * 单进程串行在大仓（数千 md）上会明显拖尾，这里按 CPU 数切片并行。
 * worker_threads 不可用时自动退化为串行，不改变结果。
 */

function chunk(items, n) {
  const out = Array.from({ length: n }, () => []);
  let i = 0;
  for (const it of items) { out[i % n].push(it); i++; }
  return out.filter((c) => c.length);
}

function runInline(files, opts) {
  const results = [];
  const errors = [];
  for (const f of files) {
    try {
      let text = fs.readFileSync(f.full, 'utf8');
      if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
      if (opts.maxBytes && Buffer.byteLength(text) > opts.maxBytes) {
        errors.push({ rel: f.rel, reason: 'too_large' });
        continue;
      }
      const claims = extractClaims(text, f.rel, { modules: opts.modules, deep: !!opts.deep });
      const lint = opts.doLint ? lintDoc(text, f.rel, opts.lintOpts) : [];
      results.push({ rel: f.rel, claims, lint });
    } catch (e) {
      errors.push({ rel: f.rel, reason: e && e.message ? e.message : 'read_error' });
    }
  }
  return Promise.resolve({ results, errors, workers: 0 });
}

function defaultWorkers(files, max) {
  const cpu = os.cpus ? Math.max(1, os.cpus().length - 1) : 2;
  const cap = max || Math.min(6, cpu);
  return Math.max(1, Math.min(cap, files.length));
}

function scanFiles(files, opts) {
  const options = opts || {};
  if (!files.length) return Promise.resolve({ results: [], errors: [], workers: 0 });
  let WorkerCtor = Worker;
  try {
    if (!WorkerCtor) throw new Error('no_worker_threads');
  } catch (_) {
    WorkerCtor = null;
  }
  if (!WorkerCtor || files.length < 8) return runInline(files, options);

  const n = defaultWorkers(files, options.concurrency);
  const groups = chunk(files, n);
  const workerPath = path.join(__dirname, 'worker.js');

  return Promise.all(groups.map((group) => new Promise((resolve) => {
    let w;
    try {
      w = new WorkerCtor(workerPath, {
        workerData: {
          files: group,
          modules: options.modules || [],
          deep: !!options.deep,
          maxBytes: options.maxBytes || 0,
          doLint: !!options.doLint,
          lintOpts: options.lintOpts || {}
        }
      });
    } catch (_) {
      return resolve({ results: [], errors: group.map((f) => ({ rel: f.rel, reason: 'worker_spawn_failed' })), pool: true });
    }

    let settled = false;
    const finish = (payload) => { if (!settled) { settled = true; w.terminate().catch(() => {}); resolve(payload); } };
    w.on('message', (msg) => finish({ results: msg.results || [], errors: msg.errors || [], pool: true }));
    w.on('error', () => finish({ results: [], errors: group.map((f) => ({ rel: f.rel, reason: 'worker_error' })), pool: true }));
    w.on('exit', (code) => { if (code !== 0) finish({ results: [], errors: group.map((f) => ({ rel: f.rel, reason: 'worker_exit_' + code })), pool: true }); });
  }))).then((all) => {
    const results = [];
    const errors = [];
    let pooled = true;
    for (const a of all) {
      for (const r of a.results) results.push(r);
      for (const e of a.errors) errors.push(e);
      if (!a.pool) pooled = false;
    }
    return { results, errors, workers: groups.length, pooled };
  });
}

module.exports = { scanFiles, defaultWorkers, chunk };
