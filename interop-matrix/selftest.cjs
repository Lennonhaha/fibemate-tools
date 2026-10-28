#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Self-test for the interop matrix: proves the harness can fail, by running it three times.
//
//   1. baseline                     -> verdict PASS,    exit 0
//   2. mutation n-kyber-kdf         -> verdict FAIL,    exit 1 (self-consistent end, wrong secret)
//   3. mutation n-encap-ss          -> verdict INVALID, exit 3 (a baseline is broken)
//   4. mutation p-decap-ss          -> verdict INVALID, exit 3 (a baseline is broken)
//
// Usage:
//   node interop-matrix/selftest.cjs --pqc-kem <dir> --noble <dir>
//
// Exit 0 only if all three runs behave as described.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
if (!args['pqc-kem'] || !args.noble) {
  console.error('usage: selftest.cjs --pqc-kem <dir> --noble <dir>');
  process.exit(2);
}

const runner = path.join(__dirname, 'run.cjs');
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'interop-matrix-selftest-'));

let failed = 0;
function row(name, pass, detail) {
  if (!pass) failed += 1;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name.padEnd(46)}  ${detail || ''}`);
}

function runOnce(tag, mutate) {
  const out = path.join(tmpRoot, tag);
  const argv = [runner, '--pqc-kem', args['pqc-kem'], '--noble', args.noble, '--out', out];
  if (mutate) argv.push('--mutate', mutate);
  const r = spawnSync(process.execPath, argv, { encoding: 'utf8' });
  const jsonPath = path.join(out, 'matrix.json');
  const json = fs.existsSync(jsonPath) ? JSON.parse(fs.readFileSync(jsonPath, 'utf8')) : null;
  return { status: r.status, json, stderr: (r.stderr || '').trim() };
}

console.log('=== interop matrix self-test ===\n');

const base = runOnce('baseline', null);
row('baseline verdict PASS', base.json && base.json.verdict === 'PASS', `verdict=${base.json && base.json.verdict} exit=${base.status}`);
row('baseline exit 0', base.status === 0, `exit=${base.status}`);
row('baseline has no FAIL checks', base.json && base.json.summary.failed === 0, `failed=${base.json && base.json.summary.failed}`);
row('baseline counts 4 cells x 3 seeds', base.json && base.json.cells.length === 12, `cells=${base.json && base.json.cells.length}`);

const m1 = runOnce('mut-n-kyber-kdf', 'n-kyber-kdf');
row('mutation n-kyber-kdf verdict FAIL', m1.json && m1.json.verdict === 'FAIL', `verdict=${m1.json && m1.json.verdict} exit=${m1.status}`);
row('mutation n-kyber-kdf exit 1', m1.status === 1, `exit=${m1.status}`);
const m1Broken = m1.json ? m1.json.cells.filter((c) => c.checks.some((k) => k.status === 'FAIL')) : [];
row('mutation caught in PN, NP and NN, PP untouched',
  m1Broken.length > 0 && m1Broken.every((c) => c.cell !== 'PP')
    && ['PN', 'NP', 'NN'].every((id) => m1Broken.some((c) => c.cell === id)),
  `broken cells: ${[...new Set(m1Broken.map((c) => c.cell))].join(',')}`);
row('divergence is FAIL, not INVALID (end is self-consistent)',
  m1.json && m1.json.verdict === 'FAIL'
    && m1.json.cells.filter((c) => c.baseline).every((c) => c.roundTrip === true),
  'NN and PP still round-trip; only the shared secret differs');

const m2 = runOnce('mut-n-encap-ss', 'n-encap-ss');
row('mutation n-encap-ss verdict INVALID', m2.json && m2.json.verdict === 'INVALID', `verdict=${m2.json && m2.json.verdict} exit=${m2.status}`);
row('mutation n-encap-ss exit 3', m2.status === 3, `exit=${m2.status}`);

const m3 = runOnce('mut-p-decap-ss', 'p-decap-ss');
row('mutation p-decap-ss verdict INVALID', m3.json && m3.json.verdict === 'INVALID', `verdict=${m3.json && m3.json.verdict} exit=${m3.status}`);
row('mutation p-decap-ss exit 3', m3.status === 3, `exit=${m3.status}`);

console.log(`\nRESULT: ${failed === 0 ? 'harness can fail in all four expected ways' : failed + ' self-test checks failed'}`);
fs.rmSync(tmpRoot, { recursive: true, force: true });
process.exit(failed === 0 ? 0 : 1);
