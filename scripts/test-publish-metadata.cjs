#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Gate: every package this repository publishes must carry the metadata npm's
// provenance check demands.
//
// Context: release.yml always publishes with --provenance. npm validates that a
// package's `repository` block points at the repository the workflow runs in,
// and at the subdirectory that package lives in. `hallucination-detector`
// declared the URL but not `"directory"`, so tagging it would have failed at
// the last step of a green pipeline - after tests, after pack, after the whole
// job looked fine. A version number would have been burned and the error would
// have arrived as a repository-mismatch from the registry.
//
// The fix for that one file is one line. This gate is so the fourth package
// doesn't repeat it.
//
// Run: node scripts/test-publish-metadata.cjs [--self-test]
// Exit: 0 all good, 1 a finding, 2 usage.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const selfTest = process.argv.includes('--self-test');
const root = path.resolve(__dirname, '..');

// Packages release.yml can publish: the tag prefix is the directory name.
const PUBLISHABLE = ['verifact', 'cbom-tools', 'hallucination-detector'];
const EXPECTED_URL = 'git+https://github.com/Lennonhaha/fibemate-tools.git';

function load(dir) {
  const p = path.join(root, dir, 'package.json');
  if (!fs.existsSync(p)) return { dir, error: 'no package.json' };
  try {
    return { dir, json: JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch (e) {
    return { dir, error: 'invalid JSON: ' + e.message.split('\n')[0] };
  }
}

function check(dir, json) {
  const problems = [];
  const facts = [];

  if (!json || typeof json !== 'object') return { problems: [`${dir}: no package metadata`], facts };

  if (json.private === true) problems.push(`${dir}: "private": true, so a tag would publish nothing`);

  const repo = json.repository;
  if (!repo) {
    problems.push(`${dir}: no "repository" block - provenance cannot be verified`);
  } else {
    const url = typeof repo === 'string' ? repo : repo.url;
    const sub = typeof repo === 'object' ? repo.directory : undefined;
    if (!url) problems.push(`${dir}: repository.url missing`);
    else if (url !== EXPECTED_URL) problems.push(`${dir}: repository.url is ${url}, expected ${EXPECTED_URL}`);
    if (sub === undefined) {
      problems.push(`${dir}: repository.directory missing - npm provenance will reject a subdirectory package`);
    } else if (sub !== dir) {
      problems.push(`${dir}: repository.directory is "${sub}", expected "${dir}" (tag prefix -> directory)`);
    }
    facts.push(`${dir}: url ok, directory=${sub === undefined ? 'MISSING' : sub}`);
  }

  if (!json.version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(json.version)) {
    problems.push(`${dir}: version "${json.version}" is not semver`);
  }

  return { problems, facts };
}

function run() {
  const problems = [];
  const facts = [];
  for (const dir of PUBLISHABLE) {
    const { json, error } = load(dir);
    if (error) { problems.push(`${dir}: ${error}`); continue; }
    const res = check(dir, json);
    problems.push(...res.problems);
    facts.push(...res.facts);
  }
  return { problems, facts };
}

function selfTestRun() {
  const base = JSON.parse(fs.readFileSync(path.join(root, 'hallucination-detector', 'package.json'), 'utf8'));
  const mutations = [
    ['M1 directory removed', (j) => { delete j.repository.directory; }, 'repository.directory missing'],
    ['M2 directory names the package, not the folder', (j) => { j.repository.directory = 'crypto-hallucination-detector'; }, 'expected "hallucination-detector"'],
    ['M3 repository url points elsewhere', (j) => { j.repository.url = 'git+https://github.com/someone/fork.git'; }, 'expected ' + EXPECTED_URL],
    ['M4 private true', (j) => { j.private = true; }, '"private": true'],
  ];
  let broken = 0;
  for (const [label, mutate, expected] of mutations) {
    const j = JSON.parse(JSON.stringify(base));
    mutate(j);
    const res = check('hallucination-detector', j);
    const hit = res.problems.some((p) => p.includes(expected));
    console.log(`${hit ? 'RED-OK ' : 'SELF-TEST BROKEN '}${label}${hit ? '' : '  [expected: ' + expected + ']'}`);
    if (!hit) {
      for (const p of res.problems) console.log('   got: ' + p);
      broken++;
    }
  }
  console.log(`\nself-test: ${mutations.length - broken}/${mutations.length} mutations detected`);
  return broken === 0 ? 0 : 3;
}

if (selfTest) process.exit(selfTestRun());

const { problems, facts } = run();
for (const f of facts) console.log('  ' + f);
if (problems.length > 0) {
  console.log('');
  for (const p of problems) console.log('FAIL ' + p);
  console.log(`\n${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`\n${PUBLISHABLE.length} publishable packages carry provenance-ready repository metadata`);
