// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

// Tests for falcon-gate.cjs.
//
// The gate's value is entirely in what it refuses to call a pass. So the cases
// that matter here are the failures: an empty tree, a document whose numbers
// disagree with its artefacts, and a tool that is not there. A gate that only
// gets tested on the happy path is a gate that will one day be green because it
// stopped running.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { parseArgs, stageAssets, stageClaims, render } = require('../falcon-gate.cjs');

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
  const a = parseArgs(['--cbom-dir', 'x']);
  assert.equal(a.minAssets, 1);
});

test('an empty tree fails: no assets is not a clean bill of health', () => {
  const dir = tmp('gate-empty-');
  try {
    const r = stageAssets({ cbomDir: dir, minAssets: 1 }, tmp('gate-out-'));
    assert.equal(r.verdict, 'fail');
    assert.match(r.detail, /found 0 cryptographic asset/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a real tree passes and counts call sites', () => {
  const out = tmp('gate-out-');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 1 }, out);
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
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 100000 }, out);
    assert.equal(r.verdict, 'fail');
    assert.match(r.detail, /below the minimum/);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('a missing tool is an error, not a skip', () => {
  const out = tmp('gate-out-');
  try {
    const r = stageAssets({ cbomDir: CBOM_DIR, minAssets: 1, cbomScript: path.join(out, 'nope.cjs') }, out);
    assert.equal(r.verdict, 'error');
    assert.match(r.detail, /tool not found/);
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('documentation that disagrees with its artefacts fails', () => {
  const r = stageClaims({ docs: FIXTURE_DOCS, artifacts: FIXTURE_ARTIFACTS });
  assert.equal(r.verdict, 'fail', 'fixture doc claims 78.5ms while the artefact says 81.2');
  assert.equal(r.counts.drift, 2);
  assert.match(r.detail, /drift=2/);
});

test('zero claims passes but says it checked nothing', () => {
  const dir = tmp('gate-prose-');
  try {
    fs.writeFileSync(path.join(dir, 'notes.md'), '# Notes\n\nThis prose carries no numbers a machine can bind.\n');
    const pass = stageClaims({ docs: dir, artifacts: FIXTURE_ARTIFACTS });
    assert.equal(pass.verdict, 'pass');
    assert.equal(pass.claims, 0);
    assert.match(pass.detail, /empty check, not a clean one/);

    const strict = stageClaims({ docs: dir, artifacts: FIXTURE_ARTIFACTS, requireClaims: true });
    assert.equal(strict.verdict, 'fail');
    assert.match(strict.detail, /--require-claims/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('render states the verdict and the failing stage', () => {
  const text = render({
    at: '2026-01-01T00:00:00.000Z',
    cbomDir: 'x',
    ok: false,
    stages: [{ name: 'assets', verdict: 'fail', detail: 'found 0' }],
  });
  assert.match(text, /\[FAIL\] assets/);
  assert.match(text, /verdict: FAIL \(1 of 1/);
});

test('the process contract is exit 1 when a stage fails', () => {
  const dir = tmp('gate-cli-');
  try {
    const r = spawnSync(process.execPath, [GATE, '--cbom-dir', dir], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /verdict: FAIL/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the process contract is exit 2 on usage error', () => {
  const r = spawnSync(process.execPath, [GATE, '--docs', 'x', '--artifacts', 'y'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--cbom-dir is required/);
});
