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
    errors.push({ rel: f.rel, reason: e && e.message ? e.message : 'read_error' });
  }
}

parentPort.postMessage({ results, errors });
