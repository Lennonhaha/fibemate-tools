#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * check-docs-sync — README numbers must come from a run, not from memory.
 *
 * What it gates:
 *   1. Completeness: every tool directory that carries a test entry point appears
 *      in README's tool table.
 *   2. Counts: for each gated tool, the "N 项" this README claims equals what the
 *      test run actually reports.
 *   3. Cross-repo numbers (verifact): docs / claims / verified / drift are compared
 *      only when the sibling repositories exist. Otherwise the check prints SKIP
 *      and is *not* counted as a pass.
 *
 * Exit codes: 0 = every gated check passed; 1 = at least one mismatch;
 *             2 = the checker itself could not run (usage / IO).
 *
 * A gate that cannot go red is decoration. `--selftest` feeds the comparator a
 * deliberately stale README and asserts it reports FAIL.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const README = path.join(ROOT, 'README.md');
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

function decode(buf, label) {
  try {
    return utf8Strict.decode(buf);
  } catch (e) {
    console.error(`FAIL [${label}] output is not valid UTF-8: ${e.message}`);
    process.exit(1);
  }
}

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  const out = decode(r.stdout || Buffer.alloc(0), `${cmd} stdout`) +
    decode(r.stderr || Buffer.alloc(0), `${cmd} stderr`);
  return { status: r.status, out };
}

// ---------------------------------------------------------------- README table

function toolRows(markdown) {
  const rows = new Map();
  for (const line of markdown.split(/\r?\n/)) {
    const m = /^\|\s*`([A-Za-z0-9._-]+)`\s*\|/.exec(line);
    if (m) rows.set(m[1], line);
  }
  return rows;
}

function declaredCount(row) {
  const m = /(\d+)\s*项/.exec(row);
  return m ? Number(m[1]) : null;
}

// ---------------------------------------------------------------- detection

const TEST_ENTRY_HINTS = ['package.json', 'Cargo.toml', 'pyproject.toml', 'selftest.cjs', 'run.cjs', 'c2-tlc-nightly.sh'];

function detectedTools() {
  const found = new Set();
  for (const entry of fs.readdirSync(ROOT, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(ROOT, entry.name);
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    for (const hint of TEST_ENTRY_HINTS) {
      if (fs.existsSync(path.join(dir, hint))) {
        found.add(entry.name);
        break;
      }
    }
    if (fs.existsSync(path.join(dir, 'test'))) found.add(entry.name);
  }
  // Directories that are not tools.
  for (const skip of ['scripts', 'templates', 'docs', 'data', 'bench']) found.delete(skip);
  return [...found].sort();
}

// ---------------------------------------------------------------- gated tools

const GATED = [
  {
    name: 'verifact',
    cwd: 'verifact',
    cmd: ['node', ['test/run.js']],
    measure: (out) => {
      const m = /(\d+)\/(\d+) passed/.exec(out);
      return m ? { value: Number(m[1]), total: Number(m[2]), unit: '项' } : null;
    },
    expectSameAsTotal: true,
  },
  {
    name: 'xdiff',
    cwd: 'xdiff',
    cmd: ['node', ['test/run.js']],
    measure: (out) => {
      const m = /(\d+)\s*通过/.exec(out);
      return m ? { value: Number(m[1]), unit: '项' } : null;
    },
  },
  {
    name: 'cbom-tools',
    cwd: 'cbom-tools',
    cmd: ['node', ['--test']],
    measure: (out) => {
      const m = /# tests (\d+)/.exec(out);
      return m ? { value: Number(m[1]), unit: '项' } : null;
    },
  },
  {
    name: 'falcon',
    cwd: 'falcon',
    cmd: ['node', ['test/falcon-gate.test.cjs']],
    measure: (out) => {
      const m = /# tests (\d+)/.exec(out);
      return m ? { value: Number(m[1]), unit: '项' } : null;
    },
  },
  {
    name: 'hallucination-detector',
    cwd: 'hallucination-detector',
    cmd: ['node', ['test/sample.test.js']],
    measure: (out) => {
      const pass = (out.match(/^PASS /gm) || []).length;
      return pass ? { value: pass, unit: '项' } : null;
    },
  },
];

// ---------------------------------------------------------------- cross-repo

const MAIN_REPO = path.resolve(ROOT, '..', 'fibemate');

function crossRepoNumbers() {
  if (!fs.existsSync(path.join(MAIN_REPO, 'docs'))) {
    return { skipped: 'sibling fibemate repository not present (cross-repo numbers not verified here)' };
  }
  const outFile = path.join(ROOT, 'verifact', '.docs-sync-report.md');
  const r = run('node', ['bin/verifact.js', 'verify', '--format', 'md', '--out', outFile], path.join(ROOT, 'verifact'));
  if (!fs.existsSync(outFile)) {
    return { error: `verifact produced no report (exit ${r.status})`, tail: r.out.slice(-400) };
  }
  const md = fs.readFileSync(outFile, 'utf8');
  fs.unlinkSync(outFile);
  const docs = /文档 ([\d,]+) 份 \/ 产出物条目 ([\d,]+) 条 \/ 声明 ([\d,]+) 条/.exec(md);
  const tally = /已核验 ([\d,]+) · 漂移 ([\d,]+)/.exec(md);
  if (!docs || !tally) return { error: 'could not parse the verifact report summary' };
  const n = (s) => Number(s.replace(/,/g, ''));
  return {
    docs: n(docs[1]),
    artifacts: n(docs[2]),
    claims: n(docs[3]),
    verified: n(tally[1]),
    drift: n(tally[2]),
  };
}

function checkCrossRepo(row) {
  const r = crossRepoNumbers();
  if (r.skipped) return { status: 'SKIP', detail: r.skipped };
  if (r.error) return { status: 'FAIL', detail: `${r.error} — ${r.tail || ''}`.trim() };

  // README claim, e.g. "416 份文档 / 2307 条声明 / verified 142 · drift 1"
  const claim = /([\d,]+)\s*份文档\s*\/\s*([\d,]+)\s*条声明\s*\/\s*verified\s*([\d,]+)\s*·\s*drift\s*([\d,]+)/.exec(row);
  if (!claim) {
    return { status: 'FAIL', detail: 'README row has no machine-readable "N 份文档 / N 条声明 / verified N · drift N" claim' };
  }
  const want = { docs: claim[1], claims: claim[2], verified: claim[3], drift: claim[4] };
  const got = { docs: String(r.docs), claims: String(r.claims), verified: String(r.verified), drift: String(r.drift) };
  const diffs = Object.keys(want)
    .filter((k) => want[k].replace(/,/g, '') !== got[k])
    .map((k) => `${k}: README ${want[k]} != measured ${got[k]}`);
  if (diffs.length) return { status: 'FAIL', detail: diffs.join('; ') };
  return { status: 'OK', detail: `${got.docs} 份 / ${got.claims} 条 / verified ${got.verified} / drift ${got.drift}` };
}

// ---------------------------------------------------------------- comparator

function compare(markdown, measurements, opts = {}) {
  const rows = toolRows(markdown);
  const results = [];

  const declaredTools = detectedTools();
  const missing = declaredTools.filter((t) => !rows.has(t));
  results.push({
    name: 'tool-list',
    status: missing.length ? 'FAIL' : 'OK',
    detail: missing.length
      ? `README table does not list: ${missing.join(', ')}`
      : `${declaredTools.length} tool directories all listed`,
  });

  for (const tool of GATED) {
    const row = rows.get(tool.name);
    if (!row) {
      results.push({ name: tool.name, status: 'FAIL', detail: 'not in README tool table' });
      continue;
    }
    const claimed = declaredCount(row);
    if (claimed === null) {
      results.push({ name: tool.name, status: 'FAIL', detail: 'README row has no "N 项" claim to compare against' });
      continue;
    }
    const measured = measurements[tool.name];
    if (!measured) {
      results.push({ name: tool.name, status: 'FAIL', detail: 'no measurement (test run failed?)' });
      continue;
    }
    const diffs = [];
    if (claimed !== measured.value) diffs.push(`README ${claimed} 项 != measured ${measured.value} 项`);
    if (tool.expectSameAsTotal && measured.total !== undefined && measured.value !== measured.total) {
      diffs.push(`measured ${measured.value}/${measured.total}: not every test passed`);
    }
    results.push({
      name: tool.name,
      status: diffs.length ? 'FAIL' : 'OK',
      detail: diffs.length ? diffs.join('; ') : `${measured.value} 项`,
    });
  }

  if (rows.has('verifact')) {
    const cross = checkCrossRepo(rows.get('verifact'));
    // A SKIP is honest, but it is not coverage. Callers that know the sibling
    // repository is present (CI checks it out) require it to be a real check.
    if (cross.status === 'SKIP' && opts.requireCrossRepo) {
      results.push({ name: 'verifact:cross-repo', status: 'FAIL', detail: `required but skipped: ${cross.detail}` });
    } else {
      results.push({ name: 'verifact:cross-repo', ...cross });
    }
  }
  return results;
}

// ---------------------------------------------------------------- main

function measureAll() {
  const out = {};
  for (const tool of GATED) {
    const r = run(tool.cmd[0], tool.cmd[1], path.join(ROOT, tool.cwd));
    if (r.status !== 0) {
      console.error(`FAIL [${tool.name}] test command exited ${r.status}\n${r.out.slice(-600)}`);
      continue;
    }
    const m = tool.measure(r.out);
    if (!m) {
      console.error(`FAIL [${tool.name}] could not parse a test count from the output`);
      continue;
    }
    out[tool.name] = m;
  }
  return out;
}

function report(results) {
  let fail = 0, ok = 0, skip = 0;
  for (const r of results) {
    if (r.status === 'FAIL') fail++;
    else if (r.status === 'SKIP') skip++;
    else ok++;
    console.log(`${r.status.padEnd(4)} ${r.name.padEnd(24)} ${r.detail}`);
  }
  console.log(`\nsummary: ok=${ok} fail=${fail} skipped=${skip} (skipped is not counted as a pass)`);
  return fail;
}

function main() {
  const markdown = fs.readFileSync(README, 'utf8');

  if (process.argv.includes('--selftest')) {
    // Three ways this gate must be able to go red, each using the real README text
    // with exactly one thing broken. A comparator that cannot fail is decoration.
    const fake = {};
    for (const tool of GATED) fake[tool.name] = { value: 2, unit: '项' };

    const cases = [];
    const doctored = markdown.replace(/(\|\s*`xdiff`\s*\|[^\n]*?)(\d+)(\s*项)/, (m, a, n, b) => a + (Number(n) + 1) + b);
    cases.push({
      what: 'a stale xdiff count',
      results: compare(doctored, fake).filter((r) => r.name === 'xdiff'),
      want: (r) => r.status === 'FAIL' && /README \d+ 项 != measured 2 项/.test(r.detail),
    });

    const dropped = markdown.replace(/^\|\s*`cbom-tools`[^\n]*\n/m, '');
    cases.push({
      what: 'a tool missing from the table',
      results: compare(dropped, fake).filter((r) => r.name === 'tool-list'),
      want: (r) => r.status === 'FAIL' && r.detail.includes('cbom-tools'),
    });

    const noClaim = markdown.replace(/(\|\s*`verifact`\s*\|[^\n]*?)\d+\s*项/, (m, a) => a);
    cases.push({
      what: 'a row with no machine-readable count',
      results: compare(noClaim, fake).filter((r) => r.name === 'verifact'),
      want: (r) => r.status === 'FAIL' && /no "N 项" claim/.test(r.detail),
    });

    let bad = 0;
    for (const c of cases) {
      const caught = c.results.length === 1 && c.want(c.results[0]);
      if (!caught) bad++;
      console.log(`${caught ? 'OK  ' : 'FAIL'} selftest: ${c.what} ${caught ? 'is rejected' : 'was NOT rejected — ' + JSON.stringify(c.results)}`);
    }
    if (bad) {
      console.log('      the comparator cannot fail on the cases above, so it is not a gate');
      process.exit(1);
    }
    console.log('selftest passed: the comparator goes red on every broken README it was given');
    return;
  }

  const results = compare(markdown, measureAll(), { requireCrossRepo: process.argv.includes('--require-cross-repo') });
  process.exit(report(results) === 0 ? 0 : 1);
}

if (require.main === module) main();
module.exports = { toolRows, declaredCount, compare, detectedTools };
