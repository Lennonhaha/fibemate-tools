#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// print-pdfs.cjs
// Prints both HTML files to PDF with headless Edge.
// See README.md in this directory for inputs and usage.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const os = require('os');

const argOf = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const inDir = path.resolve(argOf('in-dir', path.join(__dirname, 'out')));
const outDir = path.resolve(argOf('out-dir', inDir));
const EDGE = process.env.EDGE_BIN || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
if (!fs.existsSync(EDGE)) {
  console.error('Edge not found at ' + EDGE + '; set EDGE_BIN');
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const jobs = [
  { html: path.join(inDir, 'verifact-sample-report.html'), out: path.join(outDir, 'verifact-sample-report.pdf') },
  { html: path.join(inDir, 'fibemate-intro.html'), out: path.join(outDir, 'fibemate-intro.pdf') },
];

for (const j of jobs) {
  if (fs.existsSync(j.out)) fs.rmSync(j.out);
  const url = 'file:///' + j.html.replace(/\\/g, '/');
  const r = spawnSync(EDGE, [
    '--headless=new',
    '--disable-gpu',
    '--no-pdf-header-footer',
    '--run-all-compositor-stages-before-draw',
    '--virtual-time-budget=4000',
    '--user-data-dir=' + path.join(os.tmpdir(), 'fibemate-pdf-profile'),
    '--print-to-pdf=' + j.out.replace(/\\/g, '/'),
    url,
  ], { encoding: 'utf8', timeout: 120000 });
  const ok = fs.existsSync(j.out);
  console.log(`${path.basename(j.out)} -> ${ok ? 'OK ' + fs.statSync(j.out).size + ' bytes' : 'MISSING'} (exit=${r.status})`);
  if (!ok) console.log((r.stderr || '').slice(0, 300));
}
