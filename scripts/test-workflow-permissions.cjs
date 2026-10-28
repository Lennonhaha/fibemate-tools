#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Gate: every workflow declares a read-only top level, and every job that asks
// for a write scope can point at the thing in that job which needs it.
//
// Why a gate and not a one-off edit: OpenSSF Scorecard's Token-Permissions
// check scored this repository 0 ("detected GitHub workflow tokens with
// excessive permissions") for nine workflows that had no top-level
// `permissions:` at all. Fixing them once is a commit; keeping them fixed needs
// something that fails. The inverse check matters just as much: a review that
// only ever tightens permissions will eventually break a release, so a workflow
// that runs `gh release create` or `npm publish` must still be granted
// `contents: write` somewhere, and this gate says so out loud.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
const selfTest = args.includes('--self-test');
const dirArg = args.find((a) => a.startsWith('--dir='));
const workflowsDir = path.resolve(dirArg ? dirArg.slice('--dir='.length) : path.join(__dirname, '..', '.github', 'workflows'));

const READ_ONLY = new Set(['read', 'none']);

// Evidence for a write scope, per scope. Each entry is a regex that must match
// somewhere in the same job as the scope it justifies.
const WRITE_EVIDENCE = {
  contents: [/gh release (create|upload|edit)/, /npm publish(?!\s*--dry-run)/, /softprops\/action-gh-release/, /git push/],
  'id-token': [/npm publish[^\n]*--provenance/, /cosign (sign-blob|sign)/, /ossf\/scorecard-action/, /sigstore/, /pypa\/gh-action-pypi-publish/],
  'security-events': [/upload-sarif/, /codeql-action/],
  packages: [/docker push/, /ghcr\.io/, /npm publish[^\n]*--access public/],
  actions: [/workflow run/, /gh run/, /actions\/cache/],
  checks: [/gh pr checks/, /check-runs/],
  deployments: [/deployment/i],
  statuses: [/statuses/i],
  pull_requests: [/gh pr (create|merge|edit|comment|review)/],
};

function parseFile(src) {
  const lines = src.split('\n');
  const top = { present: false, line: 0, entries: [] };
  const jobs = [];
  let inJobs = false;
  let current = null;
  let inTopPerms = false;
  let inJobPerms = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln = i + 1;

    if (/^permissions:\s*(\S+)?\s*$/.test(line)) {
      top.present = true;
      top.line = ln;
      const inline = line.replace(/^permissions:\s*/, '').trim();
      if (inline) top.entries.push({ key: inline, value: inline });
      inTopPerms = true;
      inJobPerms = false;
      continue;
    }
    if (/^[A-Za-z_][\w-]*:/.test(line)) {
      // Any other top-level key ends the top-level permissions block.
      inTopPerms = false;
      if (/^jobs:/.test(line)) inJobs = true;
      continue;
    }
    if (inTopPerms && /^\s{2}[a-z_-]+:\s*\S+/.test(line)) {
      const m = line.match(/^\s{2}([a-z_-]+):\s*(\S+)/);
      top.entries.push({ key: m[1], value: m[2].trim(), line: ln });
      continue;
    }

    if (inJobs) {
      const jobStart = line.match(/^\s{2}([A-Za-z0-9_-]+):\s*$/);
      if (jobStart) {
        current = { name: jobStart[1], line: ln, perms: [], body: [] };
        jobs.push(current);
        inJobPerms = false;
        continue;
      }
      if (current) {
        if (/^\s{4}permissions:\s*$/.test(line)) { inJobPerms = true; continue; }
        if (inJobPerms && /^\s{6}([a-z_-]+):\s*(\S+)/.test(line)) {
          const m = line.match(/^\s{6}([a-z_-]+):\s*(\S+)/);
          current.perms.push({ key: m[1], value: m[2].trim(), line: ln });
          continue;
        }
        if (inJobPerms && /^\s{4}\S/.test(line)) inJobPerms = false;
        current.body.push(line);
      }
    }
  }
  return { top, jobs };
}

function checkWorkflow(name, src) {
  const problems = [];
  const details = [];
  const parsed = parseFile(src);

  if (!parsed.top.present) {
    problems.push(`${name}: no top-level permissions block (Scorecard Token-Permissions scores this 0)`);
    return { problems, details };
  }
  if (parsed.top.entries.length === 0) {
    problems.push(`${name}: top-level permissions is empty`);
  }
  for (const e of parsed.top.entries) {
    if (e.key === 'write-all' || e.value === 'write-all') {
      problems.push(`${name}: top-level 'write-all'`);
      continue;
    }
    if (e.value === 'read-all') continue; // `permissions: read-all` is the recommended shorthand
    if (/^write$/.test(e.value)) {
      problems.push(`${name}: top-level '${e.key}: write' (line ${e.line}) - writes belong on the job that needs them`);
      continue;
    }
    if (!READ_ONLY.has(e.value)) {
      problems.push(`${name}: top-level '${e.key}: ${e.value}' (line ${e.line}) is neither read nor none`);
    }
  }

  let anyWriteJob = false;
  for (const job of parsed.jobs) {
    if (job.perms.length === 0) continue;
    const body = job.body.join('\n');
    for (const p of job.perms) {
      if (p.value !== 'write') continue;
      anyWriteJob = true;
      const evidence = WRITE_EVIDENCE[p.key];
      if (!evidence) {
        problems.push(`${name}: job '${job.name}' asks for '${p.key}: write' (line ${p.line}) and this gate knows no command that needs it`);
        continue;
      }
      if (!evidence.some((re) => re.test(body))) {
        problems.push(`${name}: job '${job.name}' asks for '${p.key}: write' (line ${p.line}) but nothing in that job needs it`);
      } else {
        details.push(`${name}: ${job.name} -> ${p.key}: write justified`);
      }
    }
  }

  // Inverse check: publishing must still be allowed to write.
  const needsContentsWrite = [
    { re: /gh release create/, what: 'gh release create' },
    { re: /gh release upload/, what: 'gh release upload' },
    { re: /npm publish(?!\s*--dry-run)/, what: 'npm publish' },
  ].filter((x) => x.re.test(src));
  if (needsContentsWrite.length > 0) {
    const granted = parsed.jobs.some((j) => j.perms.some((p) => p.key === 'contents' && p.value === 'write'));
    if (!granted) {
      problems.push(`${name}: runs ${needsContentsWrite.map((x) => x.what).join(', ')} but no job is granted 'contents: write'`);
    }
  }

  details.push(`${name}: top-level ${parsed.top.entries.map((e) => `${e.key}:${e.value}`).join(', ') || '(empty)'}${anyWriteJob ? ', job-level writes justified' : ''}`);
  return { problems, details };
}

function run(dir) {
  const problems = [];
  const details = [];
  const files = fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort();
  if (files.length === 0) return { problems: [`no workflow files in ${dir}`], details };
  for (const f of files) {
    const res = checkWorkflow(f, fs.readFileSync(path.join(dir, f), 'utf8'));
    problems.push(...res.problems);
    details.push(...res.details);
  }
  return { problems, details };
}

// ---------------------------------------------------------------- self-test
function selfTestRun() {
  const srcDir = workflowsDir;
  const base = fs.readFileSync(path.join(srcDir, 'release.yml'), 'utf8');
  const mutations = [];

  mutations.push(['M1 top-level permissions removed', base.replace(/^permissions:\n(  [a-z_-]+: \w+\n)+\n?/m, ''), 'no top-level permissions block']);
  mutations.push(['M2 top-level write', base.replace(/^permissions:\n/m, 'permissions:\n  contents: write\n  x: read\n'), "top-level 'contents: write'"]);
  mutations.push(['M3 write-all at top level', base.replace(/^permissions:\n/m, 'permissions: write-all\n'), 'write-all']);
  mutations.push([
    'M4 unjustified job write',
    base.replace('    permissions:\n      contents: write\n      id-token: write', '    permissions:\n      contents: write\n      id-token: write\n      pull_requests: write'),
    "asks for 'pull_requests: write'",
  ]);
  mutations.push([
    'M5 publishing without contents: write',
    base.replace('    permissions:\n      contents: write\n      id-token: write', '    permissions:\n      contents: read\n      id-token: write'),
    "no job is granted 'contents: write'",
  ]);

  let broken = 0;
  for (const [label, text, expected] of mutations) {
    if (text === base) {
      console.log(`SELF-TEST BROKEN ${label}  [mutation did not apply]`);
      broken++;
      continue;
    }
    const res = checkWorkflow('mutant.yml', text);
    const hit = res.problems.some((p) => p.includes(expected.split(' (')[0]));
    console.log(`${hit ? 'RED-OK ' : 'SELF-TEST BROKEN '}${label}  [${res.problems.length} problem(s)]`);
    if (!hit) {
      console.log('   expected something containing: ' + expected);
      for (const p of res.problems) console.log('   got: ' + p);
      broken++;
    }
  }
  console.log(`\nself-test: ${mutations.length - broken}/${mutations.length} mutations detected`);
  return broken === 0 ? 0 : 3;
}

if (selfTest) {
  process.exit(selfTestRun());
}

const { problems, details } = run(workflowsDir);
for (const d of details) console.log('  ' + d);
if (problems.length > 0) {
  console.log('');
  for (const p of problems) console.log('FAIL ' + p);
  console.log(`\n${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`\nall workflows declare a read-only top level, and every write scope is justified`);
