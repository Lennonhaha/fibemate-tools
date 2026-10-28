#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Gate: the Lean toolchain must be fetched with a bounded retry before
// lean-action runs.
//
// Why this exists: releases.lean-lang.org intermittently drops the TLS
// handshake for the pinned toolchain tarball. lean-action installs elan and
// then resolves lean-toolchain, and that resolution is where the download
// happens, so a transient refusal fails build-and-run on PRs that do not
// touch Lean at all. Observed on 2026-10-28: four refusals and one 22 minute
// hang, across two documentation-only PRs.
//
// The fix is a pre-install step with a bounded retry, placed before the action
// so the action finds the toolchain already present and never downloads it.
// This gate makes sure that step cannot be quietly deleted, reordered, or
// defused, because the failure it prevents looks exactly like "CI is flaky".
//
// Exit codes: 0 gate passed, 1 a check failed, 2 usage/IO error,
//             3 mutation self-test found a check that cannot fail.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const args = process.argv.slice(2);
const selfTest = args.includes('--self-test');
const fileArg = args.find((a) => a.startsWith('--file='));
const workflowPath = path.resolve(
  fileArg ? fileArg.slice('--file='.length) : path.join(__dirname, '..', '.github', 'workflows', 'prover-ci.yml'),
);

const STEP_START = /^ {6}- (?:name|uses):/;

function splitSteps(src) {
  const lines = src.split('\n');
  const steps = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (STEP_START.test(line)) {
      if (current) steps.push(current);
      current = { start: i, lines: [line] };
      continue;
    }
    if (current) current.lines.push(line);
  }
  if (current) steps.push(current);
  return steps.map((s, index) => ({ index, start: s.start, text: s.lines.join('\n') }));
}

function stepName(step) {
  const m = /^\s*- name:\s*(.+)$/m.exec(step.text);
  return m ? m[1].trim() : '';
}

function findStep(steps, predicate) {
  return steps.find(predicate) || null;
}

// Returns an array of {ok, id, detail}.
function runChecks(src) {
  const results = [];
  const add = (ok, id, detail) => results.push({ ok, id, detail });
  const steps = splitSteps(src);

  const leanStep = findStep(steps, (s) => /uses:\s*leanprover\/lean-action@/.test(s.text));
  add(!!leanStep, 'lean-action step present', leanStep ? `step ${leanStep.index}` : 'no step uses leanprover/lean-action');

  if (leanStep) {
    const pinned = /uses:\s*leanprover\/lean-action@([0-9a-f]{40})\b/.exec(leanStep.text);
    add(!!pinned, 'lean-action pinned to a commit SHA', pinned ? `@${pinned[1]}` : 'action is referenced by tag, which can move');
    add(
      !/continue-on-error:\s*true/.test(leanStep.text),
      'lean-action step cannot swallow its own failure',
      /continue-on-error:\s*true/.test(leanStep.text) ? 'continue-on-error: true hides a red build' : 'ok',
    );
  }

  const preStep = findStep(steps, (s) => /pre-install/i.test(stepName(s)) && /lean/i.test(stepName(s)));
  add(
    !!preStep,
    'pre-install step present',
    preStep ? `"${stepName(preStep)}"` : 'no step named like "Pre-install ... Lean toolchain"',
  );

  if (preStep && leanStep) {
    add(
      preStep.start < leanStep.start,
      'pre-install runs before lean-action',
      preStep.start < leanStep.start
        ? `line ${preStep.start + 1} < ${leanStep.start + 1}`
        : 'step is ordered after the action, so the action still downloads first',
    );
    add(
      /working-directory:\s*undecryptable-prover\/proof/.test(preStep.text),
      'pre-install runs in the Lake package directory',
      /working-directory:\s*undecryptable-prover\/proof/.test(preStep.text)
        ? 'ok'
        : 'without the package directory, lean-toolchain is not found and nothing is pinned',
    );
  }

  if (preStep) {
    const text = preStep.text;
    const curlRetry = /curl[^\n]*--retry\s+([0-9]+)/.exec(text);
    add(
      !!curlRetry && Number(curlRetry[1]) >= 3,
      'elan bootstrap download retries',
      curlRetry ? `--retry ${curlRetry[1]}` : 'no --retry on the elan bootstrap curl',
    );
    add(
      /--retry-all-errors/.test(text),
      'retries survive TLS-level failures',
      /--retry-all-errors/.test(text) ? 'ok' : 'plain --retry does not cover every TLS error class',
    );

    const loop = /for\s+([A-Za-z_]\w*)\s+in\s+1\s+2\s+3(?:\s+4)?(?:\s+5)?\s*;\s*do/.exec(text);
    add(!!loop, 'toolchain install is retried in a bounded loop', loop ? `loop variable ${loop[1]}` : 'no bounded for-loop');

    if (loop) {
      const afterLoop = text.slice(loop.index);
      const doneMatch = /\n[ \t]*done\b/.exec(afterLoop);
      const done = doneMatch ? doneMatch.index : -1;
      const body = done === -1 ? afterLoop : afterLoop.slice(0, done);
      add(
        /(?<!")\belan"?\s+toolchain\s+install/.test(body.replace(/^[ \t]*#.*$/gm, '')),
        'the retried command is the toolchain install',
        /(?<!")\belan"?\s+toolchain\s+install/.test(body.replace(/^[ \t]*#.*$/gm, ''))
          ? 'ok'
          : 'the loop retries something else, so a refused toolchain download still fails once',
      );
      add(
        !/\|\|\s*true/.test(body),
        'the loop does not swallow failures',
        /\|\|\s*true/.test(body) ? '`|| true` inside the retry loop turns a hard failure into a pass' : 'ok',
      );
      const tail = done === -1 ? '' : afterLoop.slice(done);
      add(
        /test\s+"\$\{?installed/.test(tail) || /\nexit\s+1\b/.test(tail),
        'exhausting the retries fails the step',
        /test\s+"\$\{?installed/.test(tail) || /\nexit\s+1\b/.test(tail)
          ? 'ok'
          : 'after the loop there is no assertion, so a failed install can fall through',
      );
    }
  }

  return results;
}

function report(results, label) {
  let failures = 0;
  for (const r of results) {
    if (!r.ok) failures++;
    console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.id}${r.ok ? '' : ` -- ${r.detail}`}`);
  }
  console.log(`${label}: ${results.length - failures}/${results.length} checks passed`);
  return failures;
}

function main() {
  let src;
  try {
    src = fs.readFileSync(workflowPath, 'utf8');
  } catch (e) {
    console.error(`cannot read ${workflowPath}: ${e.message}`);
    process.exit(2);
  }

  const base = runChecks(src);
  const baseFailures = base.filter((r) => !r.ok).length;

  if (selfTest) {
    // Each mutation must turn the gate red. A mutation that survives means the
    // corresponding check cannot fail, which makes it decoration.
    const mutations = [
      ['M1 the whole pre-install step is deleted', (s) => {
        const steps = splitSteps(s);
        const pre = findStep(steps, (x) => /pre-install/i.test(stepName(x)));
        if (!pre) return s;
        const lines = s.split('\n');
        const start = pre.start;
        let end = start + 1;
        while (end < lines.length && !STEP_START.test(lines[end])) end++;
        return [...lines.slice(0, start), ...lines.slice(end)].join('\n');
      }],
      ['M2 the retry loop header is removed', (s) => s.replace(/for\s+\w+\s+in\s+1\s+2\s+3\s+4\s+5\s*;\s*do/, 'if true; then')],
      ['M3 curl --retry is turned off', (s) => s.replace(/--retry\s+5/, '--retry 0')],
      ['M4 the failure assertion after the loop is removed', (s) => s.replace(/^\s*test\s+"\$\{installed:-0\}"\s*=\s*1\s*$/m, '')],
      ['M5 the pre-install step is moved after lean-action', (s) => {
        const steps = splitSteps(s);
        const pre = findStep(steps, (x) => /pre-install/i.test(stepName(x)));
        const lean = findStep(steps, (x) => /uses:\s*leanprover\/lean-action@/.test(x.text));
        if (!pre || !lean) return s;
        const lines = s.split('\n');
        let preEnd = pre.start + 1;
        while (preEnd < lines.length && !STEP_START.test(lines[preEnd])) preEnd++;
        const preBlock = lines.slice(pre.start, preEnd);
        let leanEnd = lean.start + 1;
        while (leanEnd < lines.length && !STEP_START.test(lines[leanEnd])) leanEnd++;
        const without = [...lines.slice(0, pre.start), ...lines.slice(preEnd)];
        const insertAt = leanEnd - (preEnd - pre.start);
        return [...without.slice(0, insertAt), ...preBlock, ...without.slice(insertAt)].join('\n');
      }],
      ['M6 lean-action is pinned by tag instead of SHA', (s) => s.replace(/(uses:\s*leanprover\/lean-action@)[0-9a-f]{40}/, '$1v1.6.2')],
      ['M7 the retry loop retries the wrong command', (s) => s.replace(/elan"\s+toolchain\s+install/, 'true "elan toolchain install"')],
      ['M8 continue-on-error hides a red build', (s) => s.replace(/(uses:\s*leanprover\/lean-action@[0-9a-f]{40})/, '$1\n        continue-on-error: true')],
      ['M9 the pre-install step loses its working directory', (s) => s.replace(/working-directory:\s*undecryptable-prover\/proof/g, 'working-directory: .')],
    ];

    console.log(`=== self-test against ${mutations.length} mutations ===`);
    let survivors = 0;
    for (const [label, mutate] of mutations) {
      const mutated = mutate(src);
      if (mutated === src) {
        console.log(`FAIL ${label} -- mutation did not change the file, so it proves nothing`);
        survivors++;
        continue;
      }
      const failures = runChecks(mutated).filter((r) => !r.ok).length;
      if (failures === 0) {
        console.log(`FAIL ${label} -- SURVIVED, the gate still passes`);
        survivors++;
      } else {
        console.log(`PASS ${label} -- ${failures} check(s) went red`);
      }
    }
    console.log(`self-test: ${mutations.length - survivors}/${mutations.length} mutations killed`);

    // The pristine file under test must itself pass, otherwise "the mutation
    // failed the gate" proves nothing about the real workflow.
    if (baseFailures > 0) {
      console.log('note: the workflow under test does not pass the gate on its own; a red mutation is not meaningful until it does');
    }
    if (survivors > 0) process.exit(3);
    if (baseFailures > 0) process.exit(1);
    process.exit(0);
  }

  const failures = report(base, path.relative(process.cwd(), workflowPath) || workflowPath);
  process.exit(failures === 0 ? 0 : 1);
}

main();
