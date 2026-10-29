'use strict';
// SPDX-License-Identifier: Apache-2.0
/**
 * Claim–evidence end-to-end experiment (2026-10-29).
 *
 * Two verifiers, two questions, one artifact:
 *
 *   verifact        "do the numbers in the claim match the numbers in the artifact?"
 *   verify-evidence "are these the exact bytes the timestamp token seals?"
 *
 * S2 is the row that matters: a one-byte edit in a non-numeric field leaves every
 * number intact, so a purely value-level checker stays green. A digest list alone
 * would catch it, but only until someone rewrites the list too — which is what S3
 * does, and why the token has to seal the list.
 *
 * Usage:
 *   node scripts/claim-evidence/run-e2e.cjs [--tools <dir>] [--fibemate <dir>] [--work <dir>] [--keep]
 *
 * Exit: 0 all expectations met | 1 an expectation failed | 3 required input missing
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const here = __dirname;
const repo = path.resolve(here, '..', '..');

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--keep') { o.keep = true; continue; }
    if (!a.startsWith('--')) throw new Error('unexpected argument ' + a);
    o[a.slice(2)] = argv[++i];
  }
  return o;
}

const args = parseArgs(process.argv.slice(2));
const tools = path.resolve(args.tools || repo);
const fibemate = path.resolve(args.fibemate || path.join(tools, '..', 'fibemate'));
const work = path.resolve(args.work || path.join(os.tmpdir(), 'claim-evidence-e2e-' + process.pid));

const ARTIFACTS = path.join(tools, 'interop-matrix/out');
const EVID = path.join(fibemate, 'docs/tsa/2026-10-28-interop-matrix');
const CA = path.join(fibemate, 'docs/tsa/2026-09-06-vwz-rank2/freetsa-root-ca.pem');
const VERIFACT = path.join(tools, 'verifact/bin/verifact.js');
const VERIFY = path.join(here, 'verify-evidence.cjs');
const EVIDENCE_FILES = ['SHA256SUMS', 'lg-116-interop-matrix-SHA256SUMS.tsr', 'lg-116-interop-matrix-SHA256SUMS.tsq', 'timestamp-manifest.json'];

function need(p, hint) {
  if (fs.existsSync(p)) return;
  console.error('missing input: ' + p + (hint ? '\n  ' + hint : ''));
  process.exit(3);
}

need(path.join(ARTIFACTS, 'matrix.json'), 'run from a fibemate-tools checkout');
need(path.join(EVID, 'SHA256SUMS'), 'the evidence package lives in the fibemate repository; pass --fibemate <dir>');
need(path.join(EVID, 'lg-116-interop-matrix-SHA256SUMS.tsr'));
need(path.join(EVID, 'lg-116-interop-matrix-SHA256SUMS.tsq'));
need(CA);

fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(path.join(work, 'evidence'), { recursive: true });
for (const f of EVIDENCE_FILES) fs.copyFileSync(path.join(EVID, f), path.join(work, 'evidence', f));
fs.copyFileSync(CA, path.join(work, 'evidence/freetsa-root-ca.pem'));

/** Scenario workspace: <dir>/rep mirrors the artifact tree at manifest paths. */
function scenario(name) {
  const dir = path.join(work, name);
  fs.mkdirSync(path.join(dir, 'evidence'), { recursive: true });
  fs.cpSync(ARTIFACTS, path.join(dir, 'rep/interop-matrix/out'), { recursive: true });
  for (const f of EVIDENCE_FILES.concat(['freetsa-root-ca.pem'])) {
    fs.copyFileSync(path.join(work, 'evidence', f), path.join(dir, 'evidence', f));
  }
  const claim = (numbers) => {
    fs.writeFileSync(
      path.join(dir, 'claim.md'),
      '# Interop evidence claim (mock)\n\n' +
        'Scope: `interop-matrix`, ML-KEM-768, mode D, commit `898ce28`.\n\n' +
        `The recorded matrix run reports checks: ${numbers.checks}, cells: ${numbers.cells}, failed: ${numbers.failed}.\n\n` +
        'Evidence package: TSR lg-116 seals the digest list for this run.\n',
      'utf8'
    );
    fs.writeFileSync(
      path.join(dir, 'verifact.json'),
      JSON.stringify(
        {
          docs: { roots: ['.'], include: ['claim.md'], exclude: [] },
          artifacts: { roots: ['rep'], presenceRoots: ['evidence'], exclude: [] },
          cache: { enabled: false },
          gate: { failOn: 'drift' },
        },
        null,
        2
      ) + '\n',
      'utf8'
    );
  };
  return {
    dir,
    matrixPath: path.join(dir, 'rep/interop-matrix/out/matrix.json'),
    manifestPath: path.join(dir, 'evidence/SHA256SUMS'),
    claim,
  };
}

function runVerifact(dir) {
  const r = spawnSync(
    process.execPath,
    [VERIFACT, 'verify', '--cwd', dir, '--format', 'json', '--out', 'report.json', '--quiet'],
    { encoding: 'utf8', maxBuffer: 1 << 24 }
  );
  let rep = null;
  try { rep = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8')); } catch {}
  const claims = (rep && rep.claims) || [];
  return {
    exit: r.status,
    counts: (rep && rep.counts) || null,
    drift: claims.filter((c) => c.status === 'drift').map((c) => c.key + '=' + (c.value && c.value.raw)),
  };
}

function runEvidence(dir) {
  const r = spawnSync(
    process.execPath,
    [
      VERIFY,
      '--manifest', path.join(dir, 'evidence/SHA256SUMS'),
      '--root', path.join(dir, 'rep'),
      '--tsr', path.join(dir, 'evidence/lg-116-interop-matrix-SHA256SUMS.tsr'),
      '--tsq', path.join(dir, 'evidence/lg-116-interop-matrix-SHA256SUMS.tsq'),
      '--ca', path.join(dir, 'evidence/freetsa-root-ca.pem'),
      '--json',
    ],
    { encoding: 'utf8', maxBuffer: 1 << 24 }
  );
  let out = null;
  try { out = JSON.parse(r.stdout); } catch {}
  return { exit: r.status, out };
}

const rows = [];
function expect(name, what, got, want, note) {
  const ok = got === want;
  rows.push({ name, ok, what, got, want, note });
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + ' — ' + what + ' (got ' + got + ', want ' + want + ')' + (note ? '\n       ' + note : ''));
}

function runEvidenceWithoutCA(dir) {
  const r = spawnSync(
    process.execPath,
    [
      VERIFY,
      '--manifest', path.join(dir, 'evidence/SHA256SUMS'),
      '--root', path.join(dir, 'rep'),
      '--tsr', path.join(dir, 'evidence/lg-116-interop-matrix-SHA256SUMS.tsr'),
      '--json',
    ],
    { encoding: 'utf8', maxBuffer: 1 << 24 }
  );
  let out = null;
  try { out = JSON.parse(r.stdout); } catch {}
  return { exit: r.status, out };
}

const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

// ---------------- S0: untouched package ----------------
{
  console.log('\n[S0] baseline');
  const s = scenario('s0');
  s.claim({ checks: 62, cells: 12, failed: 0 });
  const v = runVerifact(s.dir);
  const e = runEvidence(s.dir);
  console.log('     verifact counts=' + JSON.stringify(v.counts) + ' | evidence verdict=' + (e.out && e.out.verdict));
  expect('S0', 'value-level check passes', v.exit, 0);
  expect('S0', 'byte-level check passes', e.exit, 0);
}

// ---------------- S1: a number changes ----------------
{
  console.log('\n[S1] value tamper: summary.checks 62 -> 61');
  const s = scenario('s1');
  const j = JSON.parse(fs.readFileSync(s.matrixPath, 'utf8'));
  j.summary.checks = 61;
  fs.writeFileSync(s.matrixPath, JSON.stringify(j, null, 1) + '\n', 'utf8');
  s.claim({ checks: 62, cells: 12, failed: 0 });
  const v = runVerifact(s.dir);
  const e = runEvidence(s.dir);
  console.log('     verifact drift=' + JSON.stringify(v.drift) + ' | evidence verdict=' + (e.out && e.out.verdict));
  expect('S1', 'value-level check fails closed', v.exit, 1);
  expect('S1', 'byte-level check fails too', e.exit, 1);
}

// ---------------- S2: a byte changes, no number does ----------------
{
  console.log('\n[S2] byte tamper: ends.P.name, every number intact');
  const s = scenario('s2');
  const text = fs.readFileSync(s.matrixPath, 'utf8');
  const tampered = text.replace('"name": "fibemate-pqc-kem"', '"name": "fibemate-pqc-kemX"');
  if (tampered === text) throw new Error('S2: tamper anchor not found');
  fs.writeFileSync(s.matrixPath, tampered, 'utf8');
  s.claim({ checks: 62, cells: 12, failed: 0 });
  const v = runVerifact(s.dir);
  const e = runEvidence(s.dir);
  console.log('     sha256 ' + sha(s.matrixPath) + ' (recorded 47726670…) | evidence verdict=' + (e.out && e.out.verdict));
  expect('S2', 'value-level check is blind to a non-numeric byte change (this is the finding, not a bug)', v.exit, 0);
  expect('S2', 'byte-level check catches it', e.exit, 1);
}

// ---------------- S3: the digest list is rewritten to match ----------------
{
  console.log('\n[S3] rewritten manifest: attacker recomputes the digest line');
  const s = scenario('s3');
  const text = fs.readFileSync(s.matrixPath, 'utf8');
  fs.writeFileSync(s.matrixPath, text.replace('"name": "fibemate-pqc-kem"', '"name": "fibemate-pqc-kemX"'), 'utf8');
  const lines = fs.readFileSync(s.manifestPath, 'utf8').split('\n');
  const i = lines.findIndex((l) => l.endsWith('interop-matrix/out/matrix.json'));
  if (i < 0) throw new Error('S3: manifest line not found');
  lines[i] = sha(s.matrixPath) + '  interop-matrix/out/matrix.json';
  fs.writeFileSync(s.manifestPath, lines.join('\n'), 'utf8');
  s.claim({ checks: 62, cells: 12, failed: 0 });
  const v = runVerifact(s.dir);
  const e = runEvidence(s.dir);
  const imprint = e.out && e.out.checks.imprintMatchesManifest;
  const files = e.out && e.out.checks.filesMatchManifest;
  console.log('     files-vs-manifest=' + files + ' | token-vs-manifest=' + imprint + ' | evidence verdict=' + (e.out && e.out.verdict));
  expect('S3', 'a rewritten digest list still satisfies link 1 (files match)', files, 'pass');
  expect('S3', 'but the token no longer seals that list (link 2 fails)', imprint, 'fail');
  expect('S3', 'and the verdict fails closed', e.exit, 1);
}

// ---------------- S4: the chain is missing ----------------
{
  console.log('\n[S4] no CA supplied: cannot check must not read as pass');
  const s = scenario('s4');
  s.claim({ checks: 62, cells: 12, failed: 0 });
  const e = runEvidenceWithoutCA(s.dir);
  console.log('     verdict=' + (e.out && e.out.verdict) + ' signatureVerified=' + (e.out && e.out.checks.signatureVerified));
  expect('S4', 'missing chain yields unverifiable, not verified', e.out && e.out.verdict, 'unverifiable');
  expect('S4', 'exit code is 3, outside the pass range', e.exit, 3);
}

// ---------------- summary ----------------
const bad = rows.filter((r) => !r.ok);
console.log('\n' + '='.repeat(74));
for (const r of rows) console.log((r.ok ? 'PASS ' : 'FAIL ') + r.name + ' — ' + r.what);
console.log('='.repeat(74));
console.log((rows.length - bad.length) + '/' + rows.length + ' expectations met');
if (!args.keep) {
  try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
} else {
  console.log('workdir kept: ' + work);
}
process.exit(bad.length ? 1 : 0);
