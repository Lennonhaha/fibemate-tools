'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const { parentPort, workerData } = require('worker_threads');
const { extractClaims } = require('./core/claims');
const { lintDoc } = require('./core/lint');

const { files, modules, deep, maxBytes, doLint, lintOpts } = workerData;
const results = [];
const errors = [];

for (const f of files) {
  try {
    let text = fs.readFileSync(f.full, 'utf8');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    if (maxBytes && Buffer.byteLength(text) > maxBytes) {
      errors.push({ rel: f.rel, reason: 'too_large' });
      continue;
    }
    const claims = extractClaims(text, f.rel, { modules, deep: !!deep });
    const lint = doLint ? lintDoc(text, f.rel, lintOpts) : [];
    results.push({ rel: f.rel, claims, lint });
  } catch (e) {
    if (e && e.name === 'DispositionError') {
      // 与 runInline 同一条规则：声明写错 = 整次运行失败，不允许静默丢文档。
      errors.push({ rel: f.rel, reason: 'disposition_error', detail: e.message, fatal: true });
      continue;
    }
    errors.push({ rel: f.rel, reason: e && e.message ? e.message : 'read_error' });
  }
}

parentPort.postMessage({ results, errors });
