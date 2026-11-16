'use strict';
// Offline tests for the tag-lookup distinction. No network.
//
// The failure these guard against is not hypothetical: on 2026-11-16 a run of
// verify-one recorded `tag_exists: false` for cbom-tools@0.3.0 while the tag was
// present in the same checkout, and classify() graded FAIL / D on it. The fix is
// only worth anything if "git could not answer" can be provoked on demand, which
// is what the local-repository cases below do.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { classifyGitResult, lookupTag, countTagRefs } = require('../lib/git-tag.cjs');
const { classify } = require('../lib/classify.cjs');

const FIXTURE = path.join(__dirname, 'fixtures', 'cbom-tools-0.2.9.json');
const base = () => JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));

// Build a throwaway repository instead of leaning on the checkout.
// A PR checkout has no tags (actions/checkout fetches the one commit), so a test
// that asks this repository for a release tag passes locally and fails in CI.
// That is the same mistake the audit tool made: trusting an answer whose
// precondition was never established.
function makeRepo({ annotated = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-repo-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' } });
  git('init', '-q', '-b', 'main');
  git('config', 'user.name', 'Audit Test');
  git('config', 'user.email', 'audit@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'tag.gpgsign', 'false');
  fs.writeFileSync(path.join(dir, 'file.txt'), 'x\n', 'utf8');
  git('add', 'file.txt');
  git('commit', '-q', '-m', 'init');
  if (annotated) git('tag', '-a', 'v-test-1.0.0', '-m', 'annotated test tag');
  else git('tag', 'v-test-1.0.0');
  return dir;
}

test('exit 0 is a present tag', () => {
  assert.equal(classifyGitResult({ status: 0, stdout: 'tag\n' }).state, 'present');
});

test('exit 1 with "Not a valid object name" is an absent tag', () => {
  const r = classifyGitResult({ status: 1, stderr: 'fatal: Not a valid object name refs/tags/nope\n' });
  assert.equal(r.state, 'absent');
  assert.match(r.why, /Not a valid object name/);
});

test('exit 128 from a non-repository is an error, not an absent tag', () => {
  const r = classifyGitResult({ status: 128, stderr: 'fatal: not a git repository (or any of the parent directories): .git\n' });
  assert.equal(r.state, 'error');
  assert.match(r.why, /exited 128/);
});

test('a missing git binary is an error, not an absent tag', () => {
  const r = classifyGitResult({ error: new Error('spawnSync git ENOENT') });
  assert.equal(r.state, 'error');
  assert.match(r.why, /could not be started/);
});

test('a killed git is an error, not an absent tag', () => {
  assert.equal(classifyGitResult({ signal: 'SIGTERM', status: null }).state, 'error');
});

test('an annotated tag in a real repository comes back present and typed', () => {
  const dir = makeRepo();
  try {
    const r = lookupTag(dir, 'v-test-1.0.0');
    assert.equal(r.state, 'present');
    assert.equal(r.type, 'tag'); // annotated
    assert.equal(r.status, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a lightweight tag is present but typed differently', () => {
  const dir = makeRepo({ annotated: false });
  try {
    const r = lookupTag(dir, 'v-test-1.0.0');
    assert.equal(r.state, 'present');
    assert.equal(r.type, 'commit');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a tag that does not exist is reported absent with the git message', () => {
  const dir = makeRepo();
  try {
    const r = lookupTag(dir, 'v-test-0.0.0-does-not-exist');
    assert.equal(r.state, 'absent');
    // git uses 128 (not 1) for a missing object, which is exactly why the exit code
    // alone cannot be used to tell "absent" from "could not look".
    assert.notEqual(r.status, 0);
    assert.match(r.why, /Not a valid object name/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a directory that is not a repository is reported as an error', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-norepo-'));
  try {
    const r = lookupTag(tmp, 'cbom-tools-v0.3.0');
    assert.equal(r.state, 'error');
    assert.ok(r.stderr && /not a git repository/i.test(r.stderr), `stderr was: ${r.stderr}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a path that does not exist is reported as an error', () => {
  const r = lookupTag(path.join(os.tmpdir(), 'audit-no-such-dir-' + process.pid), 'x');
  assert.equal(r.state, 'error');
});

test('classify declines to grade when the tag lookup failed', () => {
  const rec = base();
  rec.tag_lookup = 'error';
  rec.tag_exists = null;
  rec.tag_lookup_error = { why: 'git exited 128: fatal: not a git repository', status: 128 };
  const g = classify(rec, { tagExplicit: true }); // explicit tag used to force FAIL / D
  assert.equal(g.verdict, 'UNKNOWN');
  assert.equal(g.level, null);
  assert.ok(g.reasons.some(r => /could not determine whether it exists/.test(r)), 'must say the lookup failed');
  assert.ok(!g.reasons.some(r => r === 'FAIL: tag exists'), 'must not claim the tag is missing');
});

test('an absent, explicitly named tag still fails as before', () => {
  const rec = base();
  rec.tag_lookup = 'absent';
  rec.tag_exists = false;
  const g = classify(rec, { tagExplicit: true });
  assert.equal(g.verdict, 'FAIL');
  assert.equal(g.level, 'D');
  assert.ok(g.reasons.includes('FAIL: tag exists'));
});

// The regression itself: the record shape that produced the false FAIL.
test('the 0.3.0 incident record no longer grades FAIL / D', () => {
  const rec = base();
  rec.version = '0.3.0';
  rec.tag = 'cbom-tools-v0.3.0';
  rec.latest = '0.3.0';
  rec.latest_matches = true;
  rec.tag_lookup = 'error';
  rec.tag_exists = null;
  rec.tag_lookup_error = { why: 'git exited 128: fatal: unable to read current working directory', status: 128 };
  const g = classify(rec, { tagExplicit: true });
  assert.notEqual(g.verdict, 'FAIL');
  assert.equal(g.level, null);
});

// ---- absence has a precondition ----
//
// Second false-FAIL of the same day, from the other direction: a checkout with no
// tag refs at all (actions/checkout without fetch-depth: 0). git answers "not a
// valid object name" for every tag, and the tool believed it. A repository that
// carries no tags cannot testify that a tag does not exist.

test('a repository with no tag refs reports an error, not an absent tag', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-notags-'));
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' } });
    git('init', '-q', '-b', 'main');
    git('config', 'user.name', 'Audit Test');
    git('config', 'user.email', 'audit@example.invalid');
    git('config', 'commit.gpgsign', 'false');
    fs.writeFileSync(path.join(dir, 'file.txt'), 'x\n', 'utf8');
    git('add', 'file.txt');
    git('commit', '-q', '-m', 'init');

    assert.equal(countTagRefs(dir).count, 0);
    const r = lookupTag(dir, 'cbom-tools-v0.3.0');
    assert.equal(r.state, 'error');
    assert.match(r.why, /no tag refs/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a repository WITH tags keeps the absent verdict for a tag it does not have', () => {
  const dir = makeRepo();
  try {
    assert.ok(countTagRefs(dir).count > 0);
    const r = lookupTag(dir, 'cbom-tools-v0.3.0');
    assert.equal(r.state, 'absent');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the no-tags record grades UNKNOWN, not FAIL / D', () => {
  const rec = base();
  rec.tag_lookup = 'error';
  rec.tag_exists = null;
  rec.latest_matches = true;
  rec.tag_lookup_error = { why: 'repository carries no tag refs (shallow or --no-tags checkout)', status: null };
  const g = classify(rec, { tagExplicit: true });
  assert.equal(g.verdict, 'UNKNOWN');
  assert.equal(g.level, null);
  assert.ok(!g.reasons.some((x) => x === 'FAIL: tag exists'));
});
