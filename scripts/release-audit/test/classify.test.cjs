'use strict';
// Offline tests for the grading logic. No network, no registry, no git.
//
// The fixture is a real record captured from cbom-tools@0.2.9 (the release that
// passed end to end); the negative cases mutate copies of it, so the failures are
// the ones a real chain would produce, not invented shapes.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const { classify } = require('../lib/classify.cjs');

const FIXTURE = path.join(__dirname, 'fixtures', 'cbom-tools-0.2.9.json');
const base = () => JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));

test('a fully aligned release is PASS / A', () => {
  const rec = base();
  const g = classify(rec);
  assert.equal(g.verdict, 'PASS');
  assert.equal(g.level, 'A');
  // the fields the audit table depends on must be real values, not empty strings
  assert.ok(rec.builder && rec.builder.length > 0, 'builder must not be empty');
  assert.equal(rec.subject_match, true);
  assert.equal(rec.prov_commit_match, true);
  assert.equal(rec.reasons.filter(r => r.startsWith('FAIL')).length, 0);
});

test('published from a branch is FAIL / B, and says so', () => {
  const rec = base();
  rec.workflow_ref = 'refs/heads/main';
  rec.prov_commit_match = false;
  rec.tag_is_ancestor_of_built = true;
  rec.pkg_dir_diff_empty = true;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'B');
  assert.ok(g.reasons.some(r => r === 'FAIL: provenance ref matches tag'));
  // content equivalence is recorded as a note, never as a reason to pass
  assert.ok(g.reasons.some(r => r.startsWith('NOTE: built from a branch')));
});

test('a branch build whose package dir differs is still FAIL / B without the equivalence note', () => {
  const rec = base();
  rec.workflow_ref = 'refs/heads/main';
  rec.prov_commit_match = false;
  rec.tag_is_ancestor_of_built = true;
  rec.pkg_dir_diff_empty = false;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'B');
  assert.ok(!g.reasons.some(r => r.startsWith('NOTE:')));
});

test('no provenance at all is FAIL / C', () => {
  const rec = base();
  rec.provenance = false;
  rec.workflow_ref = null;
  rec.workflow_path = null;
  rec.subject_match = null;
  rec.prov_commit_match = null;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'C');
  assert.ok(g.reasons.includes('FAIL: provenance'));
});

test('a version published without a tag is FAIL / D', () => {
  const rec = base();
  rec.tag_exists = false;
  rec.tag_type = null;
  rec.tag_commit = null;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'D');
  assert.ok(g.reasons.includes('FAIL: tag exists'));
});

test('tag commit disagreeing with the Release target is FAIL / D', () => {
  const rec = base();
  rec.tag_commit_match = false;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'D');
  assert.ok(g.reasons.includes('FAIL: tag commit vs Release target'));
});

test('a lightweight tag or missing DCO downgrades to B but does not fail', () => {
  const light = base();
  light.tag_type = 'lightweight';
  let g = classify(light);
  assert.equal(g.verdict, 'PASS');
  assert.equal(g.level, 'B');
  assert.ok(g.reasons.includes('WARN: tag is lightweight (not annotated)'));

  const noDco = base();
  noDco.dco = false;
  g = classify(noDco);
  assert.equal(g.verdict, 'PASS');
  assert.equal(g.level, 'B');
  assert.ok(g.reasons.includes('WARN: no DCO sign-off on tag commit'));
});

test('a tarball hash mismatch is FAIL regardless of everything else', () => {
  const rec = base();
  rec.sha512_match = false;
  const g = classify(rec);
  assert.equal(g.verdict, 'FAIL');
  assert.ok(g.reasons.includes('FAIL: sha512 match'));
});

test('unknown is not pass: an unreachable registry yields UNKNOWN', () => {
  const rec = base();
  rec.registry_exists = null;
  const g = classify(rec);
  assert.equal(g.verdict, 'UNKNOWN');
  assert.ok(g.reasons.some(r => r.startsWith('UNKNOWN:')));
});

test('--ignore-latest removes the latest gate for historical versions', () => {
  const rec = base();
  rec.latest_matches = null;
  let g = classify(rec);
  assert.equal(g.verdict, 'UNKNOWN', 'without the flag a null latest is a gap, not a pass');
  g = classify(rec, { ignoreLatest: true });
  assert.equal(g.verdict, 'PASS');
  assert.equal(g.level, 'A');
});

test('the fixture itself is a real PASS record, not a hand-written one', () => {
  const rec = base();
  assert.equal(rec.pkg, 'cbom-tools');
  assert.equal(rec.version, '0.2.9');
  assert.equal(rec.verdict, 'PASS');
  assert.equal(rec.level, 'A');
  assert.match(rec.workflow_ref, /^refs\/tags\/cbom-tools-v0\.2\.9$/);
});
