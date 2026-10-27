#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Contract test for .github/workflows/resign-release.yml.
//
// This workflow touches published release pages, which is the one place in the
// repo where a mistake is not fixable by pushing again: a wrong upload, or a
// signature over bytes that were silently modified in transit, stays on the
// internet attached to a version people may already have installed.
//
// So the checks are about the properties that make it safe, not that YAML
// parses:
//
//   - dry_run defaults to true: the default dispatch must not publish;
//   - the artifact digest is recorded before and after signing and compared;
//   - the signature suffix is one OpenSSF Scorecard actually recognises
//     (.sig/.asc/.minisig/.sign/.sigstore/.sigstore.json - .bundle is not);
//   - an existing .sig is skipped, so re-running does not re-sign or --clobber
//     over a good signature;
//   - the token can write releases and mint an OIDC identity, and nothing more.
//
// Run: node scripts/test-resign-workflow.cjs [--workflow <path>] [--self-test]
// Exit: 0 pass, 1 a check failed, 2 usage.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const argv = process.argv.slice(2);
function arg(flag, fallback) {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : fallback;
}
const ROOT = path.resolve(__dirname, '..');
const WF = path.resolve(arg('--workflow', path.join(ROOT, '.github/workflows/resign-release.yml')));
const selfTest = argv.includes('--self-test');

const SCORECARD_SIGNATURE_SUFFIXES = ['.asc', '.minisig', '.sig', '.sign', '.sigstore', '.sigstore.json'];

function analyse(src) {
  const lines = src.split('\n');
  const codeLines = lines.filter((l) => !/^\s*#/.test(l));
  const code = codeLines.join('\n');
  const problems = [];
  const facts = [];

  const need = (cond, msg) => { if (!cond) problems.push(msg); };

  need(/^name:\s*resign-release\s*$/m.test(src), 'workflow is not named resign-release');
  need(/workflow_dispatch:/.test(src), 'no workflow_dispatch trigger');
  need(/^\s+tag:$/m.test(src), 'workflow_dispatch has no tag input');
  need(/^\s+dry_run:$/m.test(src), 'workflow_dispatch has no dry_run input');
  need(/default:\s*true/.test(src), 'dry_run does not default to true');

  // Signing must be tied to the OIDC identity, and writing must be job-scoped.
  need(/id-token:\s*write/.test(code), 'no id-token: write - keyless signing cannot get an identity');
  need(/contents:\s*write/.test(code), 'no contents: write - signatures cannot be uploaded');
  const top = src.slice(0, src.indexOf('jobs:'));
  need(/permissions:\s*\n\s+contents:\s*read/.test(top), 'top-level permissions are not read-only');
  need(!/id-token:\s*write/.test(top), 'id-token: write is at the top level instead of the signing job');

  // The artifact must be signed, and the suffix must be one Scorecard counts.
  const signsBlob = /cosign\s+sign-blob\b/.test(code);
  need(signsBlob, 'no cosign sign-blob invocation');
  need(/output-signature/.test(code), 'cosign does not write a signature file');
  const usesSigSuffix = /\.sig/.test(code);
  need(usesSigSuffix, 'no .sig suffix anywhere: Scorecard would not see the signature');
  for (const bad of ['.bundle', '.att', '.pem only']) {
    if (bad === '.pem only') continue;
    need(!new RegExp(`output-signature[^\\n]*${bad.replace('.', '\\.')}`).test(code),
      `signature output uses ${bad}, which Scorecard does not count`);
  }

  // Bytes must be provably unchanged by signing.
  need(/sha256sum/.test(code), 'no sha256sum: the digest of the artifact is never recorded');
  need(/before/.test(code) && /after/.test(code), 'no before/after digest comparison');
  need(/\[ "\$before" != "\$after" \]/.test(code), 'before/after digests are recorded but never compared');

  // Idempotency: never re-sign or clobber an existing signature.
  need(/already has/.test(code), 'no skip for an asset that already has a .sig');
  need(/--clobber/.test(code) === false || /already has/.test(code),
    'uploads with --clobber and no skip guard: re-running can overwrite a good signature');

  // Only signable artifacts.
  for (const skip of ['*.sig', '*.pem', '*.sha256', 'SHA256SUMS']) {
    need(code.includes(skip), `does not skip ${skip}: it would sign a signature`);
  }

  // Actions pinned by commit SHA, not tag.
  for (const m of src.matchAll(/uses:\s*([^\s#]+)/g)) {
    const ref = m[1];
    need(/@[0-9a-f]{40}$/.test(ref), `action not pinned by SHA: ${ref}`);
  }

  facts.push(`${Buffer.byteLength(src)} B, ${codeLines.length} code lines`);
  return { problems, facts };
}

function run() {
  if (!fs.existsSync(WF)) return { problems: [`${WF} does not exist`], facts: [] };
  const src = fs.readFileSync(WF, 'utf8');
  return { ...analyse(src), src };
}

if (selfTest) {
  const src = fs.readFileSync(WF, 'utf8');
  const mutations = [
    ['M1 dry_run defaults to false', (s) => s.replace('default: true', 'default: false')],
    ['M2 before/after digests not compared', (s) => s.replace('if [ "$before" != "$after" ]; then', 'if [ "$before" = "" ]; then')],
    ['M3 existing .sig not skipped', (s) => s.replace(/if grep -qx "\$name\.sig"[^\n]*\n\s+echo "skip \$name \(already has \$name\.sig\)"\n\s+skipped=\$\(\(skipped \+ 1\)\)\n\s+continue\n\s+fi\n/, '')],
    ['M4 signature written as .bundle', (s) => s.replace('--output-signature "out/$name.sig"', '--output-signature "out/$name.bundle"')],
    ['M5 id-token write removed', (s) => s.replace(/\n\s+id-token:\s*write/, '')],
    ['M6 sign a signature too (no .sha256 skip)', (s) => s.replace('*.sig|*.pem|*.sha256|SHA256SUMS', '*.sig|*.pem|SHA256SUMS')],
  ];
  let broken = 0;
  for (const [label, mutate] of mutations) {
    const mutated = mutate(src);
    if (mutated === src) { console.log(`SELF-TEST BROKEN ${label}: mutation changed nothing`); broken++; continue; }
    const { problems } = analyse(mutated);
    const red = problems.length > 0;
    console.log(`${red ? 'RED-OK ' : 'SURVIVED '}${label}${red ? '' : '  [no check noticed]'}`);
    if (!red) broken++;
  }
  console.log(`\nself-test: ${mutations.length - broken}/${mutations.length} mutations detected`);
  process.exit(broken === 0 ? 0 : 3);
}

const { problems, facts, src } = run();
for (const f of facts || []) console.log('  ' + f);
if (!src) { console.log('FAIL ' + problems[0]); process.exit(1); }
if (problems.length > 0) {
  for (const p of problems) console.log('FAIL ' + p);
  console.log(`\n${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`\nresign-release.yml signs release assets without altering them, skipping existing signatures (${SCORECARD_SIGNATURE_SUFFIXES.join(' ')} are the suffixes Scorecard counts)`);
