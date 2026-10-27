#!/usr/bin/env node
'use strict';
/*
 * Contract test for .github/workflows/scorecard.yml
 *
 * The point of this workflow is that the score is computed somewhere we do not
 * control and published where anyone can check it. So the checks are about
 * those two properties: it must run on GitHub's runners, and its result must be
 * published (publish_results) and uploaded (SARIF), not just printed.
 *
 * Exit codes: 0 ok, 1 a check failed, 2 usage.
 * `--self-test` mutates the workflow in memory and requires the matching check
 * to go red.
 */

const fs = require('node:fs');
const path = require('node:path');

const WF = path.resolve(__dirname, '../.github/workflows/scorecard.yml');
if (!fs.existsSync(WF)) {
  console.log('FAIL workflow_exists  [.github/workflows/scorecard.yml does not exist]');
  console.log('\n0/1 checks passed');
  process.exit(1);
}
const src = fs.readFileSync(WF, 'utf8');
const code = src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

const results = [];
function check(name, fn) {
  try {
    const detail = fn(code);
    results.push({ name, ok: true });
    console.log(`PASS ${name}  [${detail || 'ok'}]`);
  } catch (err) {
    results.push({ name, ok: false });
    console.log(`FAIL ${name}  [${err.message}]`);
  }
}
function must(cond, msg) { if (!cond) throw new Error(msg); }

const checks = {
  runs_on_a_github_hosted_runner: (s) => {
    must(/runs-on:\s*ubuntu-latest/.test(s), 'not on ubuntu-latest; a self-hosted runner would recreate the local-tool blindness');
    return 'ubuntu-latest';
  },
  the_action_is_the_official_one_and_pinned: (s) => {
    const m = s.match(/uses:\s*ossf\/scorecard-action@([0-9a-f]{40})/);
    must(m, 'ossf/scorecard-action missing or not pinned to a 40-hex commit');
    return 'ossf/scorecard-action@' + m[1].slice(0, 7);
  },
  the_result_is_published_not_just_printed: (s) => {
    must(/publish_results:\s*true/.test(s), 'publish_results is not true, so the score never reaches securityscorecards.dev');
    return 'publish_results: true';
  },
  it_emits_a_sarif_file: (s) => {
    must(/results_file:\s*results\.sarif/.test(s), 'results_file is not results.sarif');
    must(/results_format:\s*sarif/.test(s), 'results_format is not sarif');
    return 'results.sarif';
  },
  the_job_can_publish_and_upload: (s) => {
    must(/id-token:\s*write/.test(s), 'id-token: write is required to publish results (OIDC)');
    must(/security-events:\s*write/.test(s), 'security-events: write is required to upload SARIF');
    must(/contents:\s*read/.test(s), 'contents should stay read-only');
    return 'id-token + security-events write, contents read';
  },
  the_sarif_is_uploaded_to_code_scanning: (s) => {
    must(/uses:\s*github\/codeql-action\/upload-sarif@[0-9a-f]{40}/.test(s), 'upload-sarif missing or not pinned');
    must(/sarif_file:\s*results\.sarif/.test(s), 'upload-sarif does not point at results.sarif');
    return 'upload-sarif pinned';
  },
  credentials_are_not_persisted: (s) => {
    must(/persist-credentials:\s*false/.test(s), 'checkout persists the token into .git/config');
    return 'persist-credentials: false';
  },
  it_runs_on_a_schedule_and_on_main: (s) => {
    must(/schedule:/.test(s), 'no schedule; a score that never refreshes goes stale');
    must(/branches:\s*\n?\s*-?\s*\[?"?main"?\]?/.test(s) || /- main/.test(s), 'does not run on pushes to main');
    return 'schedule + push to main';
  },
  every_action_is_commit_pinned: (s) => {
    const uses = [...s.matchAll(/uses:\s*([^\s#]+)/g)].map((m) => m[1]);
    must(uses.length >= 3, 'expected at least three actions');
    const floating = uses.filter((u) => !/@[0-9a-f]{40}$/.test(u));
    must(floating.length === 0, 'floating refs: ' + floating.join(', '));
    return uses.length + ' pinned';
  },
  no_silent_failure_switches: (s) => {
    must(!/continue-on-error:\s*true/.test(s), 'continue-on-error: true would let a failed scan look green');
    return 'none';
  },
};

for (const [name, fn] of Object.entries(checks)) check(name, fn);

if (process.argv.includes('--self-test')) {
  const mutations = [
    ['M1 results are not published', /publish_results:\s*true/, 'publish_results: false', 'the_result_is_published_not_just_printed'],
    ['M2 no id-token permission', /      id-token:\s*write\n/, '', 'the_job_can_publish_and_upload'],
    ['M3 action left floating', /ossf\/scorecard-action@[0-9a-f]{40}/, 'ossf/scorecard-action@v2', 'the_action_is_the_official_one_and_pinned'],
    ['M4 sarif upload removed', /      - name: Upload to code scanning\n[\s\S]*?sarif_file: results\.sarif\n/, '', 'the_sarif_is_uploaded_to_code_scanning'],
    ['M5 silent failures allowed', /permissions:\s*read-all/, 'permissions: read-all  # injected', 'no_silent_failure_switches'],
    ['M6 schedule removed', /  schedule:\n[\s\S]*?\n\n/, '\n', 'it_runs_on_a_schedule_and_on_main'],
    ['M7 runs on a self-hosted runner', /runs-on:\s*ubuntu-latest/, 'runs-on: self-hosted', 'runs_on_a_github_hosted_runner'],
  ];
  let broken = 0;
  for (const [label, from, to, target] of mutations) {
    if (!from.test(src)) { console.log(`SELF-TEST BROKEN ${label}  [pattern not found]`); broken++; continue; }
    let mutated = src.replace(from, to);
    if (label === 'M5 silent failures allowed') mutated = mutated.replace('permissions: read-all', 'permissions: read-all\n  continue-on-error: true');
    if (mutated === src) { console.log(`SELF-TEST BROKEN ${label}  [no change]`); broken++; continue; }
    // Strip comments exactly as the main run does. Without this, a comment that
    // merely mentions `id-token: write` satisfies the check and the mutation
    // survives - which is what happened on the first attempt.
    mutated = mutated.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    try {
      checks[target](mutated);
      console.log(`SELF-TEST BROKEN ${label}  [gate stayed green]`);
      broken++;
    } catch { console.log(`RED-OK ${label}`); }
  }
  if (broken) { console.log(`\nself-test failures: ${broken}`); process.exit(1); }
  console.log(`\nself-test: ${mutations.length}/${mutations.length} mutations detected`);
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
