'use strict';
// Distinguish "the tag is not there" from "git could not answer".
//
// On 2026-11-16 an audit run of cbom-tools@0.3.0 recorded `tag_exists: false`
// while the tag demonstrably existed in the same checkout: `git cat-file -t` in a
// shell resolved it, and the next instrumented run did too. verify-one collapsed
// every non-zero exit into `null`, so a transient git failure became
// "tag does not exist" - and classify() then graded the release FAIL / D on a
// claim the tool had never established.
//
// The distinction is mechanical, not a heuristic: git exits 1 with
// "Not a valid object name" when the object is genuinely absent, and something
// else (128, ENOENT, a signal) when it never got to look. Only the first may be
// reported as an absent tag.
const { spawnSync } = require('child_process');

// Messages git prints when the lookup itself succeeded and the answer is "no such object".
const ABSENT = [
  /Not a valid object name/i,
  /bad object/i,
  /unknown revision or path not in the working tree/i,
];

/**
 * Map a finished git process to present / absent / error.
 * Pure: takes the same shape spawnSync returns, adds no I/O, so it can be tested
 * against captured stderr instead of hoping the failure happens again.
 */
function classifyGitResult(res) {
  const r = res || {};
  if (r.error) return { state: 'error', why: `git could not be started: ${r.error.message}` };
  if (r.signal) return { state: 'error', why: `git was killed by ${r.signal}` };
  if (r.status === 0) return { state: 'present', why: null };
  const lines = String(r.stderr || '').trim().split('\n').map((l) => l.trim()).filter(Boolean);
  const last = lines.length ? lines[lines.length - 1] : '';
  // The message is the discriminator, not the exit code: git exits 128 for a
  // missing object ("fatal: Not a valid object name") as well as for "not a git
  // repository". Only the first means git ran and answered "no such tag".
  if (r.status !== 0 && ABSENT.some((p) => p.test(last))) return { state: 'absent', why: last };
  return {
    state: 'error',
    why: `git exited ${r.status == null ? '(no status)' : r.status}${last ? `: ${last}` : ''}`,
  };
}

/** Look up refs/tags/<tag> and say whether it exists, or why we do not know. */
function lookupTag(gitDir, tag) {
  const args = ['cat-file', '-t', `refs/tags/${tag}`];
  const res = spawnSync('git', args, { cwd: gitDir, encoding: 'utf8' });
  const verdict = classifyGitResult(res);
  const out = {
    ...verdict,
    status: res.status == null ? null : res.status,
    argv: ['git', ...args],
    cwd: gitDir,
  };
  if (verdict.state === 'present') out.type = String(res.stdout || '').trim();
  if (verdict.state === 'error') out.stderr = String(res.stderr || '').trim().split('\n').slice(0, 3).join(' | ');
  return out;
}

/** Where did git think it was? Recorded only when a lookup fails, for diagnosis. */
function describeRepo(gitDir) {
  const run = (args) => {
    const r = spawnSync('git', args, { cwd: gitDir, encoding: 'utf8' });
    return r.status === 0 ? String(r.stdout || '').trim() : null;
  };
  return { toplevel: run(['rev-parse', '--show-toplevel']), remote: run(['remote', 'get-url', 'origin']) };
}

module.exports = { classifyGitResult, lookupTag, describeRepo, ABSENT };
