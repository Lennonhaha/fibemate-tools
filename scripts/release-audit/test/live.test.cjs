'use strict';
// End-to-end smoke test. Hits the real registry and GitHub, so it is opt-in:
//   AUDIT_LIVE=1 node --test scripts/release-audit/test/live.test.cjs
//
// This proves "the network path still works today". It deliberately does NOT carry
// the grading coverage - that lives in classify.test.cjs, which runs offline on
// every PR. A gate whose only test needs the internet is a gate that gets skipped.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const enabled = process.env.AUDIT_LIVE === '1';
const ROOT = path.join(__dirname, '..', '..', '..');
const CLI = path.join(__dirname, '..', 'verify-one.cjs');

test('live: cbom-tools@0.2.9 still resolves to PASS / A', { skip: enabled ? false : 'set AUDIT_LIVE=1 to run' }, () => {
  const r = spawnSync(process.execPath, [
    CLI, 'cbom-tools', '0.2.9',
    '--git-dir', ROOT,
    '--pkg-dir', 'cbom-tools',
  ], { encoding: 'utf8', env: process.env });
  const line = (r.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop();
  assert.ok(line, `no output; stderr: ${r.stderr}`);
  const rec = JSON.parse(line);
  assert.equal(rec.verdict, 'PASS');
  assert.equal(rec.level, 'A');
  assert.ok(rec.builder, 'builder must be filled from runDetails.builder.id');
  assert.equal(rec.subject_match, true);
});
