#!/usr/bin/env node
'use strict';
/*
 * Contract test for .github/workflows/prover-binaries.yml
 *
 * The rule this file enforces is narrow and non-negotiable: a binary that is
 * built but never executed proves nothing. Every check below is about evidence,
 * not about YAML shape.
 *
 * Exit codes: 0 ok, 1 a check failed, 2 usage.
 * `--self-test` mutates the workflow in memory six ways and requires the
 * matching check to fail, so a check that cannot go red is reported as a bug.
 */

const fs = require('node:fs');
const path = require('node:path');

const WF = path.resolve(__dirname, '../.github/workflows/prover-binaries.yml');
const src = fs.readFileSync(WF, 'utf8');
const code = src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

const results = [];
function check(name, fn) {
  try {
    const detail = fn(code);
    results.push({ name, ok: true });
    console.log(`PASS ${name}  [${detail || 'ok'}]`);
  } catch (err) {
    results.push({ name, ok: false, message: err.message });
    console.log(`FAIL ${name}  [${err.message}]`);
  }
}

function must(cond, msg) { if (!cond) throw new Error(msg); }

const checks = {
  matrix_covers_linux_and_windows: (s) => {
    must(/os:\s*ubuntu-latest/.test(s), 'no ubuntu-latest runner');
    must(/os:\s*windows-latest/.test(s), 'no windows-latest runner');
    must(/\.exe/.test(s), 'no .exe handling for the windows binary');
    return 'ubuntu + windows, exe suffix';
  },
  tests_run_before_the_binary_is_executed: (s) => {
    const tests = s.indexOf('cargo test');
    const run = s.indexOf('Run the built binary');
    must(tests > 0, 'cargo test missing');
    must(run > 0, 'run step missing');
    must(tests < run, 'the binary is executed before the tests run');
    return 'cargo test precedes execution';
  },
  tests_use_the_release_profile: (s) => {
    must(/cargo test --release/.test(s), 'tests run on the debug profile, where DCE cannot hide the bug');
    return 'cargo test --release';
  },
  the_binary_is_actually_executed_with_fixed_arguments: (s) => {
    must(/"\$BIN"\s+--len 32 --rounds 3/.test(s), 'the built binary is never invoked with fixed arguments');
    return 'binary invoked with --len 32 --rounds 3';
  },
  execution_output_is_asserted: (s) => {
    must(/grep -q 'final: buffer is all-zero after 3 rounds'/.test(s), 'the evidence line is not asserted');
    must(/grep -q 'evidence only, not a proof'/.test(s), 'the honesty caveat is not asserted');
    must(/test -f evidence\.json/.test(s), 'evidence.json presence is not asserted');
    return 'output + evidence.json asserted';
  },
  artifact_upload_fails_loudly: (s) => {
    must(/uses:\s*actions\/upload-artifact@[0-9a-f]{40}/.test(s), 'no pinned upload-artifact');
    must(/if-no-files-found:\s*error/.test(s), 'a missing artifact would pass silently');
    return 'upload pinned, if-no-files-found: error';
  },
  release_consumes_the_built_artifacts: (s) => {
    must(/needs:\s*build/.test(s), 'release job does not depend on the build job');
    must(/download-artifact@[0-9a-f]{40}/.test(s), 'release job does not download the artifacts');
    must(/gh release (create|upload)/.test(s), 'release job does not publish anything');
    must(/sha256sum undecryptable-prover-\*/.test(s), 'no checksum file for the binaries');
    return 'downloads both, writes SHA256SUMS, uploads';
  },
  all_actions_are_commit_pinned: (s) => {
    const uses = [...s.matchAll(/uses:\s*([^\s#]+)/g)].map((m) => m[1]);
    must(uses.length > 0, 'no uses: lines');
    const floating = uses.filter((u) => !/@[0-9a-f]{40}$/.test(u));
    must(floating.length === 0, 'floating refs: ' + floating.join(', '));
    return uses.length + ' pinned';
  },
  manual_runs_default_to_dry_run: (s) => {
    must(/dry_run:[\s\S]{0,200}?default:\s*true/.test(s), 'workflow_dispatch dry_run does not default to true');
    must(/if:\s*\$\{\{\s*github\.event\.inputs\.dry_run != 'true'\s*\}\}/.test(s), 'release job is not gated on dry_run');
    return 'dry_run defaults true and gates the release';
  },
  no_silent_failure_switches: (s) => {
    must(!/continue-on-error:\s*true/.test(s), 'continue-on-error: true would let a failed run look green');
    return 'none';
  },
};

for (const [name, fn] of Object.entries(checks)) check(name, fn);

// ---- self-test: the gate must be able to go red ---------------------------
if (process.argv.includes('--self-test')) {
  const mutations = [
    ['M1 evidence line no longer asserted', /echo "\$OUT" \| grep -q 'final: buffer is all-zero after 3 rounds'\n/, '', 'execution_output_is_asserted'],
    ['M2 windows dropped from the matrix', /          - os: windows-latest\n            artifact: windows-x86_64\n            exe: '\.exe'\n/, '', 'matrix_covers_linux_and_windows'],
    ['M3 tests on the debug profile', /cargo test --release --locked/, 'cargo test --locked', 'tests_use_the_release_profile'],
    ['M4 checkout unpinned', /actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@v4', 'all_actions_are_commit_pinned'],
    ['M5 release no longer gated', /if: \$\{\{ github\.event\.inputs\.dry_run != 'true' \}\}\n/, '', 'manual_runs_default_to_dry_run'],
    ['M6 silent failures allowed', /permissions:\n/, 'permissions:\n  # injected\n', 'no_silent_failure_switches'],
  ];

  let selfFailed = 0;
  for (const [label, from, to, target] of mutations) {
    if (!from.test(src)) { console.log(`SELF-TEST BROKEN ${label}  [pattern not found]`); selfFailed++; continue; }
    const mutated = src.replace(from, to);
    if (mutated === src) { console.log(`SELF-TEST BROKEN ${label}  [mutation did not change the file]`); selfFailed++; continue; }
    if (label === 'M6 silent failures allowed') {
      // this mutation only makes sense if it introduces the forbidden switch
      const withSwitch = mutated.replace('permissions:\n', 'permissions:\n  continue-on-error: true\n');
      try { checks.no_silent_failure_switches(withSwitch); console.log(`SELF-TEST BROKEN ${label}  [gate stayed green]`); selfFailed++; }
      catch { console.log(`RED-OK ${label}`); }
      continue;
    }
    try {
      checks[target](mutated);
      console.log(`SELF-TEST BROKEN ${label}  [gate stayed green]`);
      selfFailed++;
    } catch {
      console.log(`RED-OK ${label}`);
    }
  }
  if (selfFailed) { console.log(`\nself-test failures: ${selfFailed}`); process.exit(1); }
  console.log(`\nself-test: ${mutations.length}/${mutations.length} mutations detected`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
