// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

// Tests for falcon-gate.cjs.
//
// The gate's value is entirely in what it refuses to call a pass. So the cases
// that matter here are the failures: an empty tree, a document whose numbers
// disagree with its artefacts, a tool that is not there, and a tool that never
// comes back. A gate that only gets tested on the happy path is a gate that will
// one day be green because it stopped running.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { parseArgs, stageAssets, stageClaims, classify, evaluate, render } = require('../falcon-gate.cjs');

const HERE = __dirname;
const GATE = path.join(HERE, '..', 'falcon-gate.cjs');
const REPO = path.join(HERE, '..', '..');
const CBOM_DIR = path.join(REPO, 'cbom-tools');
const FIXTURE_DOCS = path.join(REPO, 'verifact', 'test', 'fixtures', 'docs');
const FIXTURE_ARTIFACTS = path.join(REPO, 'verifact', 'test', 'fixtures', 'artifacts');

function tmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('parseArgs rejects the cases where a typo would weaken the gate', () => {
  assert.throws(() => parseArgs([]), /--cbom-dir is required/);
  assert.throws(() => parseArgs(['--cbom-dir', 'x', '--docs', 'd']), /--docs requires --artifacts/);
  assert.throws(() => parseArgs(['--cbom-dir', 'x', '--artifacts', 'a']), /--artifacts requires --docs/);
  assert.throws(() => parseArgs(['--cbom-dir', 'x', '--nope']), /unknown argument/);
  assert.throws(() => parseArgs(['--cbom-dir']), /needs a value/);
  assert.throws(() => parseArgs(['--cbom-dir', 'x', '--timeout', '0']), /positive number of seconds/);
  assert.throws(() => parseArgs(['--cbom-dir', 'x', '--timeout', 'soon']), /positive number of seconds/);
  const a = parseArgs(['--cbom-dir', 'x']);
  assert.equal(a.minAssets, 1);
  assert.equal(a.strict, false, 'default must not block: a warning is not a gate');
  assert.equal(a.timeoutMs, 300000);
  assert.equal(parseArgs(['--cbom-dir', 'x', '--strict']).strict, true);
  assert.equal(parseArgs(['--cbom-dir', 'x', '--strict', '--safe']).strict, false);
  assert.equal(parseArgs(['--cbom-dir', 'x', '--timeout', '5']).timeoutMs, 5000);
});

test('an empty tree fails: no assets is not a clean bill of health', () => {
  const dir = tmp('gate-empty-');
  try {
    const r = stageAssets({ cbomDir: dir, minAssets: 1, timeoutMs: 120000 }, tmp('gate-out-'));
    assert.equal(r.verdict, 'fail');
    assert.match(r.detail, /found 0 cryptographic asset/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a real tree passes and counts call sites', () => {
  const out = tmp('gate-out-');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 1, timeoutMs: 120000 }, out);
    assert.equal(r.verdict, 'pass');
    assert.ok(r.components >= 1, 'expected at least one component, got ' + r.components);
    assert.ok(r.source >= 1, 'expected call-site evidence in cbom-tools');
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('--min-assets is enforced', () => {
  const out = tmp('gate-out-');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 100000, timeoutMs: 120000 }, out);
    assert.equal(r.verdict, 'fail');
    assert.match(r.detail, /below the minimum/);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('a missing tool is an error, not a skip', () => {
  const out = tmp('gate-out-');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 1, cbomScript: path.join(out, 'nope.cjs'), timeoutMs: 120000 }, out);
    assert.equal(r.verdict, 'error');
    assert.match(r.detail, /tool not found/);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('a tool that never returns is a timeout, not a pass', () => {
  const out = tmp('gate-out-');
  const slow = path.join(out, 'slow.cjs');
  // 5s of silence against a 400ms budget: the shape of a scan that hangs on a
  // large tree, which is the failure this budget exists for.
  fs.writeFileSync(slow, 'setTimeout(() => {}, 5000);\n');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 1, cbomScript: slow, timeoutMs: 400 }, out);
    assert.equal(r.verdict, 'timeout');
    assert.match(r.detail, /budget/);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('documentation that disagrees with its artefacts fails', () => {
  const r = stageClaims({ docs: FIXTURE_DOCS, artifacts: FIXTURE_ARTIFACTS, timeoutMs: 120000 });
  assert.equal(r.verdict, 'fail', 'fixture doc claims 78.5ms while the artefact says 81.2');
  assert.equal(r.counts.drift, 2);
  assert.match(r.detail, /drift=2/);
});

test('zero claims is advisory: an empty check is not a clean one', () => {
  const dir = tmp('gate-prose-');
  try {
    fs.writeFileSync(path.join(dir, 'notes.md'), '# Notes\n\nThis prose carries no numbers a machine can bind.\n');
    const quiet = stageClaims({ docs: dir, artifacts: FIXTURE_ARTIFACTS, timeoutMs: 120000 });
    assert.equal(quiet.verdict, 'advisory');
    assert.equal(quiet.claims, 0);
    assert.match(quiet.detail, /empty check, not a clean one/);
    assert.equal(classify(quiet, true), 'advisory', 'prose is allowed to be prose even in strict mode');

    const demanded = stageClaims({ docs: dir, artifacts: FIXTURE_ARTIFACTS, requireClaims: true, timeoutMs: 120000 });
    assert.equal(demanded.verdict, 'fail');
    assert.match(demanded.detail, /--require-claims/);
    assert.equal(classify(demanded, false), 'advisory');
    assert.equal(classify(demanded, true), 'blocking');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the two modes differ on findings and agree on errors', () => {
  const fail = { name: 'assets', verdict: 'fail', detail: '' };
  const timeout = { name: 'claims', verdict: 'timeout', detail: '' };
  const error = { name: 'assets', verdict: 'error', detail: '' };
  const pass = { name: 'assets', verdict: 'pass', detail: '' };

  assert.equal(classify(pass, true), 'pass');
  assert.equal(classify(fail, false), 'advisory', 'safe mode reports, it does not block');
  assert.equal(classify(fail, true), 'blocking');
  assert.equal(classify(timeout, false), 'advisory');
  assert.equal(classify(timeout, true), 'blocking');
  assert.equal(classify(error, false), 'blocking', 'nothing ran: no mode may call that green');
  assert.equal(classify(error, true), 'blocking');

  const safe = evaluate([fail, timeout], false);
  assert.equal(safe.ok, true);
  assert.equal(safe.advisory, 2);
  const strict = evaluate([fail, timeout], true);
  assert.equal(strict.ok, false);
  assert.equal(strict.blocking, 2);
});

test('render states the verdict, the mode, and why a green safe run is not evidence', () => {
  const strict = evaluate([{ name: 'assets', verdict: 'fail', detail: 'found 0' }], true);
  const text = render({
    at: '2026-01-01T00:00:00.000Z',
    cbomDir: 'x',
    strict: true,
    timeoutMs: 300000,
    ok: strict.ok,
    blocking: strict.blocking,
    advisory: strict.advisory,
    rows: strict.rows,
  });
  assert.match(text, /mode=strict/);
  assert.match(text, /\[FAIL\] assets/);
  assert.match(text, /verdict: FAIL \(1 blocking, 0 advisory\)/);

  const safe = evaluate([{ name: 'assets', verdict: 'fail', detail: 'found 0' }], false);
  const advisoryText = render({
    at: '2026-01-01T00:00:00.000Z',
    cbomDir: 'x',
    strict: false,
    timeoutMs: 300000,
    ok: safe.ok,
    blocking: safe.blocking,
    advisory: safe.advisory,
    rows: safe.rows,
  });
  assert.match(advisoryText, /\[WARN\] assets/);
  assert.match(advisoryText, /PASS WITH WARNINGS/);
  assert.match(advisoryText, /not evidence/);
});

test('the process contract: strict blocks, safe reports, errors block in both', () => {
  const dir = tmp('gate-cli-');
  try {
    const strict = spawnSync(process.execPath, [GATE, '--cbom-dir', dir, '--strict'], { encoding: 'utf8' });
    assert.equal(strict.status, 1);
    assert.match(strict.stdout, /verdict: FAIL/);

    const safe = spawnSync(process.execPath, [GATE, '--cbom-dir', dir], { encoding: 'utf8' });
    assert.equal(safe.status, 0, 'safe mode must not block on a finding');
    assert.match(safe.stdout, /\[WARN\] assets/);
    assert.match(safe.stdout, /not evidence/);

    const missing = spawnSync(process.execPath, [GATE, '--cbom-dir', dir, '--safe'], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, { PATH: process.env.PATH }),
    });
    assert.equal(missing.status, 0, 'the empty tree is a finding, not an error');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the process contract is exit 2 on usage error', () => {
  const r = spawnSync(process.execPath, [GATE, '--docs', 'x', '--artifacts', 'y'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--cbom-dir is required/);
});
