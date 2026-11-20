#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

/**
 * falcon-gate — two questions, one exit code.
 *
 *   1. Does this tree actually contain cryptographic assets? (cbom-tools scan)
 *   2. Do the numbers the documentation claims match the artefacts? (verifact)
 *
 * It is a chain, not a new analyser. Every judgement it makes is made by one of
 * the two tools; this file only decides what "both said yes" means.
 *
 * Two modes, because "should this block a merge" and "should this tell me
 * something" are different questions:
 *
 *   safe (default)  a finding is a warning: drift, a short scan, a timeout.
 *                   Exit 0. Printed as ADVISORY. This is a report, not a gate.
 *   strict          any finding blocks. Exit 1. This is what CI runs.
 *
 * One verdict is fatal in both modes: `error`, meaning a stage could not run at
 * all (missing tool, crash, unreadable output). A check that did not run is not
 * a check that passed, and no mode may turn that into green.
 *
 * What it is not: a side-channel claim. Nothing here measures timing, power, or
 * memory access. The name refers to the project, not to an analysis of Falcon.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const HERE = __dirname;
const DEFAULT_CBOM = path.join(HERE, '..', 'cbom-tools', 'cbom-scan.cjs');
const DEFAULT_VERIFACT = path.join(HERE, '..', 'verifact', 'bin', 'verifact.js');
const DEFAULT_TIMEOUT_S = 300;

const USAGE = [
  'usage: falcon-gate --cbom-dir <path> [options]',
  '',
  '  --cbom-dir <path>        tree to inventory for cryptographic assets (required)',
  '  --min-assets <n>         fail when fewer than n algorithms are found (default 1)',
  '  --require-source-evidence  fail unless at least one asset is seen at a call site',
  '  --docs <path>            documentation root to check for numeric claims',
  '  --artifacts <path>       artefact root that backs those claims',
  '  --require-claims         fail when the docs contain zero claims',
  '  --timeout <seconds>      per-stage budget (default ' + DEFAULT_TIMEOUT_S + ')',
  '  --strict                 findings block: exit 1 (use this in CI)',
  '  --safe                   findings warn only: exit 0 (default)',
  '  --json                   machine-readable result on stdout',
  '  --keep                   keep the temporary CBOM and print its path',
  '',
  'Exit codes: 0 no blocking stage; 1 a stage failed or could not run; 2 usage error.',
  'A stage that cannot run (missing tool, crash, unreadable output) is always',
  'blocking. A timeout is a finding: it warns in safe mode and blocks in strict.',
].join('\n');

function parseArgs(argv) {
  const args = { minAssets: 1, strict: false, timeoutMs: DEFAULT_TIMEOUT_S * 1000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const needs = (name) => {
      const v = argv[++i];
      if (v === undefined) throw new Error(name + ' needs a value');
      return v;
    };
    switch (a) {
      case '--cbom-dir': args.cbomDir = needs(a); break;
      case '--min-assets': args.minAssets = Number(needs(a)); break;
      case '--docs': args.docs = needs(a); break;
      case '--artifacts': args.artifacts = needs(a); break;
      case '--require-source-evidence': args.requireSourceEvidence = true; break;
      case '--require-claims': args.requireClaims = true; break;
      case '--timeout': args.timeoutMs = Number(needs(a)) * 1000; break;
      case '--strict': args.strict = true; break;
      case '--safe': args.strict = false; break;
      case '--json': args.json = true; break;
      case '--keep': args.keep = true; break;
      case '--help': case '-h': args.help = true; break;
      default: throw new Error('unknown argument ' + a);
    }
  }
  if (!args.help && !args.cbomDir) throw new Error('--cbom-dir is required');
  if (!args.help && args.docs && !args.artifacts) throw new Error('--docs requires --artifacts');
  if (!args.help && args.artifacts && !args.docs) throw new Error('--artifacts requires --docs');
  if (!args.help && !Number.isFinite(args.minAssets)) throw new Error('--min-assets must be a number');
  if (!args.help && !(Number.isFinite(args.timeoutMs) && args.timeoutMs > 0)) throw new Error('--timeout must be a positive number of seconds');
  return args;
}

function runTool(script, argv, timeoutMs) {
  if (!fs.existsSync(script)) {
    return { status: 'error', code: null, stdout: '', stderr: 'tool not found: ' + script };
  }
  const r = spawnSync(process.execPath, [script, ...argv], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: timeoutMs,
  });
  if (r.error) {
    const timedOut = r.error.code === 'ETIMEDOUT' || r.signal === 'SIGTERM';
    return {
      status: timedOut ? 'timeout' : 'error',
      code: null,
      stdout: r.stdout || '',
      stderr: timedOut ? 'exceeded the ' + Math.round(timeoutMs / 1000) + 's budget' : String(r.error.message),
    };
  }
  return { status: 'ran', code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/**
 * Stage 1: inventory.
 * A scan that finds nothing is a failure, not a clean bill of health. That is
 * the whole point of running it in a gate.
 */
function stageAssets(opts, tmpDir) {
  const out = path.join(tmpDir, 'cbom.json');
  const r = runTool(opts.cbomScript || DEFAULT_CBOM, ['--dir', opts.cbomDir, '--out', out], opts.timeoutMs);
  if (r.status === 'timeout') {
    return { name: 'assets', verdict: 'timeout', detail: 'scan ' + r.stderr, components: 0 };
  }
  if (r.status === 'error') {
    return { name: 'assets', verdict: 'error', detail: r.stderr.trim(), components: 0 };
  }
  if (r.code !== 0) {
    return { name: 'assets', verdict: 'fail', detail: 'scan exited ' + r.code + ': ' + (r.stderr.trim().split('\n').slice(-1)[0] || ''), components: 0 };
  }
  let bom;
  try {
    bom = JSON.parse(fs.readFileSync(out, 'utf-8'));
  } catch (err) {
    return { name: 'assets', verdict: 'error', detail: 'cannot read scan output (' + (err.code || err.message) + ')', components: 0 };
  }
  const components = Array.isArray(bom.components) ? bom.components : [];
  let source = 0;
  let manifest = 0;
  for (const c of components) {
    const methods = ((c.evidence && c.evidence.identity) || []).flatMap((i) => i.methods || []);
    if (methods.some((m) => m.technique === 'source-code-analysis')) source++;
    else if (methods.some((m) => m.technique === 'manifest-analysis')) manifest++;
  }
  const base = { name: 'assets', components: components.length, source, manifest, minAssets: opts.minAssets };
  if (components.length < opts.minAssets) {
    return Object.assign(base, {
      verdict: 'fail',
      detail: 'found ' + components.length + ' cryptographic asset(s), below the minimum of ' + opts.minAssets,
    });
  }
  if (opts.requireSourceEvidence && source === 0) {
    return Object.assign(base, {
      verdict: 'fail',
      detail: 'every asset is manifest-only: a dependency, not a call site',
    });
  }
  return Object.assign(base, {
    verdict: 'pass',
    detail: components.length + ' asset(s), ' + source + ' at a call site, ' + manifest + ' manifest-only',
  });
}

/**
 * Stage 2: claims.
 * verifact owns the judgement; this reads its exit code and its counts.
 */
function stageClaims(opts) {
  const r = runTool(opts.verifactScript || DEFAULT_VERIFACT,
    ['verify', '--docs', opts.docs, '--artifacts', opts.artifacts, '--no-cache', '--format', 'json'],
    opts.timeoutMs);
  if (r.status === 'timeout') {
    return { name: 'claims', verdict: 'timeout', detail: 'verify ' + r.stderr };
  }
  if (r.status === 'error') {
    return { name: 'claims', verdict: 'error', detail: r.stderr.trim() };
  }
  let report = null;
  try { report = JSON.parse(r.stdout); } catch (err) { report = null; }
  const counts = (report && report.counts) || {};
  // claimsTotal is the number of claims considered; summing every counter would
  // add docs, artifacts and refs to the claim count and produce a number with no
  // meaning.
  const claims = Number.isFinite(Number(counts.claimsTotal))
    ? Number(counts.claimsTotal)
    : Number(counts.claims) || 0;
  const wanted = ['claims', 'verified', 'drift', 'ambiguous', 'unbound', 'refFound', 'refMissing', 'lint'];
  const shown = wanted.filter((k) => Number.isFinite(Number(counts[k]))).map((k) => k + '=' + counts[k]);
  const detailCounts = shown.length ? shown.join(' ') : 'counts unavailable';
  const base = { name: 'claims', claims, counts, exitCode: r.code };
  if (r.code !== 0) {
    return Object.assign(base, { verdict: 'fail', detail: 'verifact exited ' + r.code + ' (' + detailCounts + ')' });
  }
  if (claims === 0) {
    // Zero claims is not a pass: it means the document does not bind numbers to
    // artefacts, which may be fine (prose) or may be an empty scan.
    if (opts.requireClaims) {
      return Object.assign(base, { verdict: 'fail', detail: 'no numeric claims found, and --require-claims was given' });
    }
    return Object.assign(base, { verdict: 'advisory', detail: 'no numeric claims to check (' + detailCounts + ') - empty check, not a clean one' });
  }
  return Object.assign(base, { verdict: 'pass', detail: 'claims agree (' + detailCounts + ')' });
}

/**
 * Decide what a stage verdict means for this run.
 * `error` blocks in every mode; findings block only in strict.
 */
function classify(stage, strict) {
  if (stage.verdict === 'pass') return 'pass';
  if (stage.verdict === 'advisory') return 'advisory';
  if (stage.verdict === 'error') return 'blocking';
  return strict ? 'blocking' : 'advisory';
}

function evaluate(stages, strict) {
  const rows = stages.map((s) => ({ stage: s, effect: classify(s, strict) }));
  const blocking = rows.filter((r) => r.effect === 'blocking').length;
  const advisory = rows.filter((r) => r.effect === 'advisory').length;
  return { rows, blocking, advisory, ok: blocking === 0 };
}

function render(result) {
  const L = [];
  L.push('falcon-gate  ' + result.at + '  cbom-dir=' + result.cbomDir
    + '  mode=' + (result.strict ? 'strict' : 'safe') + '  timeout=' + Math.round(result.timeoutMs / 1000) + 's');
  for (const row of result.rows) {
    const s = row.stage;
    const mark = row.effect === 'pass' ? 'PASS'
      : (row.effect === 'blocking' ? (s.verdict === 'error' ? 'ERROR' : 'FAIL') : 'WARN');
    L.push('  [' + mark + '] ' + s.name.padEnd(6) + '  ' + s.detail);
  }
  L.push('  verdict: ' + (result.ok ? (result.advisory ? 'PASS WITH WARNINGS' : 'PASS') : 'FAIL')
    + ' (' + result.blocking + ' blocking, ' + result.advisory + ' advisory)');
  if (!result.strict && result.advisory) {
    L.push('  note: safe mode does not block. A green run here is a report, not evidence.');
    L.push('        run with --strict to make these findings fail.');
  }
  return L.join('\n');
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(USAGE);
    console.error('\n  ' + err.message);
    process.exit(2);
  }
  if (args.help) { console.log(USAGE); process.exit(0); }

  if (!fs.existsSync(args.cbomDir) || !fs.statSync(args.cbomDir).isDirectory()) {
    console.error(USAGE);
    console.error('\n  --cbom-dir is not a directory: ' + args.cbomDir);
    process.exit(2);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'falcon-gate-'));
  const stages = [];
  try {
    stages.push(stageAssets(args, tmpDir));
    if (args.docs) stages.push(stageClaims(args));
  } finally {
    if (args.keep) console.error('falcon-gate: kept ' + tmpDir);
    else fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  const evaluated = evaluate(stages, args.strict);
  const result = {
    at: new Date().toISOString(),
    cbomDir: path.resolve(args.cbomDir),
    strict: args.strict,
    timeoutMs: args.timeoutMs,
    ok: evaluated.ok,
    blocking: evaluated.blocking,
    advisory: evaluated.advisory,
    rows: evaluated.rows,
    stages,
  };

  if (args.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  else console.log(render(result));
  process.exit(result.ok ? 0 : 1);
}

if (require.main === module) {
  main();
}

module.exports = { parseArgs, stageAssets, stageClaims, classify, evaluate, render };
