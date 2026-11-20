// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

// Tests for cbom-compliance.cjs.
//
// Two things are being protected here, and only one of them is arithmetic:
//
//   1. The bucket mapping, including the case that motivated the module:
//      SM4 is `quantumSecurity: weak` and still an approved algorithm. A test
//      that only checks "weak algorithms are flagged" would lock in the bug.
//   2. The words. A report that says "合规" when the scan found nothing is
//      worse than no report, so the empty-BOM case is asserted to say the
//      opposite in plain Chinese.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const CLI = path.join(__dirname, '..', 'cbom-compliance.cjs');

const {
  classify,
  familyOf,
  collect,
  summarise,
  renderMarkdown,
  scanPrivateKeyBlocks,
  cell,
} = require('../cbom-compliance.cjs');

const { lookupMeta } = require('../cbom-scan.cjs');

function comp(name, extras) {
  const e = extras || {};
  return {
    type: 'cryptographic-asset',
    name,
    'bom-ref': 'crypto:' + name,
    cryptoProperties: e.cryptoProperties,
    properties: e.properties,
    evidence: {
      identity: [{ field: 'name', confidence: 0.9, concludedValue: name, methods: [{ technique: 'source-code-analysis', confidence: 0.9 }] }],
      occurrences: e.occurrences || [{ location: 'app.js', line: 1, symbol: name }],
    },
  };
}

function bom(components) {
  return { bomFormat: 'CycloneDX', specVersion: '1.7', version: 1, metadata: { timestamp: '2026-01-01T00:00:00.000Z' }, components };
}

test('approved algorithms are approved, including the quantum-weak ones', () => {
  // The trap: metadata marks SM3/SM4 `quantumSecurity: weak`. If classify()
  // ever starts reading that field, this assertion is what stops it.
  assert.equal(classify('SM2', lookupMeta('SM2')).bucket, 'approved');
  assert.equal(classify('SM3', lookupMeta('SM3')).bucket, 'approved');
  assert.equal(classify('SM4', lookupMeta('SM4')).bucket, 'approved');
  assert.equal(lookupMeta('SM4').quantumSecurity.level, 'weak', 'precondition: the two axes disagree on SM4');
});

test('post-quantum families are not approved, and are labelled as PQC', () => {
  const r = classify('ML-KEM-768', lookupMeta('ML-KEM-768'));
  assert.equal(r.bucket, 'not_approved');
  assert.equal(r.pqc, true);
  assert.equal(classify('Falcon', lookupMeta('Falcon')).pqc, true);
});

test('broken algorithms are deprecated, by name and by metadata', () => {
  assert.equal(classify('MD5', lookupMeta('MD5')).bucket, 'deprecated');
  assert.equal(classify('SHA-1', lookupMeta('SHA-1')).bucket, 'deprecated');
  // No policy entry: falls through to certificationLevel.
  assert.equal(classify('Blowfish', lookupMeta('Blowfish')).bucket, 'deprecated');
});

test('foreign-but-not-broken algorithms are not_approved', () => {
  assert.equal(classify('RSA', lookupMeta('RSA')).bucket, 'not_approved');
  assert.equal(classify('AES-GCM', lookupMeta('AES-GCM')).bucket, 'not_approved');
  assert.equal(classify('SHA-256', lookupMeta('SHA-256')).bucket, 'not_approved');
});

test('constructs are neither approved nor non-approved', () => {
  assert.equal(classify('NTT', lookupMeta('NTT')).bucket, 'construct');
  assert.equal(classify('Double-Ratchet', lookupMeta('Double-Ratchet')).bucket, 'construct');
});

test('a name with no metadata is unknown, never approved', () => {
  const r = classify('Totally-New-Cipher-9000', null);
  assert.equal(r.bucket, 'unknown');
});

test('familyOf strips one parameter suffix and the slash form', () => {
  assert.equal(familyOf('ML-DSA-65'), 'ML-DSA');
  assert.equal(familyOf('AES-GCM'), 'AES');
  assert.equal(familyOf('P-256/ECDH'), 'P-256');
  assert.equal(familyOf('secp256k1'), 'secp256k1');
  assert.equal(familyOf('SM4'), 'SM4');
});

test('markdown cells escape the escape character before the delimiter', () => {
  // `a\|b` must not render as `a\` + cell break. Escaping only the pipe leaves
  // a trailing backslash that re-opens exactly the hole it was meant to close.
  const raw = cell('a\\|b');
  assert.equal(raw, 'a\\\\\\|b');
  assert.ok(!/(^|[^\\])\|/.test(raw), 'no unescaped pipe may survive');
  assert.equal(cell('line\nbreak'), 'line break');
});

test('collect reads occurrences, the cap, and the deprecated property', () => {
  const rows = collect(bom([
    comp('SM4'),
    comp('MD5', { properties: [{ name: 'fibemate:testingStatus', value: 'deprecated' }] }),
    comp('Keccak', { properties: [{ name: 'fibemate:occurrenceCountAtLeast', value: '57' }] }),
  ]));
  const byName = Object.fromEntries(rows.map((r) => [r.name, r]));
  assert.equal(byName.MD5.bucket, 'deprecated');
  assert.equal(byName.Keccak.truncatedAt, 57);
  assert.equal(byName.SM4.count, 1);
});

test('summarise counts algo and evidence separately', () => {
  const s = summarise(bom([
    comp('SM4', { occurrences: [{ location: 'a.js', line: 1, symbol: 'sm4' }, { location: 'b.js', line: 2, symbol: 'sm4' }] }),
    comp('RSA'),
  ]), {});
  assert.equal(s.componentCount, 2);
  assert.equal(s.counts.approved, 1);
  assert.equal(s.counts.not_approved, 1);
  assert.equal(s.occurrences.approved, 2);
});

test('an empty CBOM says "not found", not "compliant"', () => {
  const md = renderMarkdown(summarise(bom([]), {}));
  assert.match(md, /没有密码资产/);
  assert.match(md, /不是「合规」，是「没扫到」/);
  assert.match(md, /算法维度未见需要整改的项/);
  assert.match(md, /这不等于合规/);
});

test('the report states the two-axis caveat and the key-length limit', () => {
  const md = renderMarkdown(summarise(bom([comp('SM4'), comp('RSA')]), {}));
  assert.match(md, /两个正交的轴/);
  assert.match(md, /不识别密钥长度/);
  assert.ok(md.includes('RSA'), 'RSA row must be present');
  // The caveat mentions RSA-1024 by name; a finding row must not, because the
  // scan never measured a key size.
  assert.ok(!/^\|\s*RSA-1024\s*\|/m.test(md), 'must not invent a key size it did not measure');
});

test('PEM scanning finds private keys, ignores certificates, skips node_modules', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-pem-'));
  try {
    fs.writeFileSync(path.join(dir, 'dev.pem'), 'x\n-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n');
    fs.writeFileSync(path.join(dir, 'cert.pem'), '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n');
    fs.writeFileSync(path.join(dir, 'blob.bin'), Buffer.from([0, 1, 2, 3, 0, 255]));
    fs.mkdirSync(path.join(dir, 'node_modules'));
    fs.writeFileSync(path.join(dir, 'node_modules', 'vendored.pem'), '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n');

    const r = scanPrivateKeyBlocks(dir);
    assert.equal(r.found.length, 1, 'exactly the developer key, not the cert, not the vendored one');
    assert.equal(r.found[0].location, 'dev.pem');
    assert.equal(r.found[0].line, 2);
    assert.equal(r.found[0].label, 'RSA PRIVATE KEY');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the report refuses to claim a PEM scan it did not run', () => {
  const withPem = renderMarkdown(summarise(bom([comp('SM4')]), {
    pem: { root: 'proj', scannedFiles: 3, found: [{ location: 'keys/dev.pem', line: 1, label: 'RSA PRIVATE KEY' }], skipped: [] },
  }));
  assert.match(withPem, /命中 PEM 私钥块 \| 1/);
  assert.ok(withPem.includes('keys/dev.pem:1'));

  const withoutPem = renderMarkdown(summarise(bom([comp('SM4')]), {}));
  assert.match(withoutPem, /未执行/);
});

test('reproduce block matches the flags the CLI actually accepts', () => {
  const md = renderMarkdown(summarise(bom([comp('SM4')]), {}));
  assert.ok(md.includes('cbom-tools compliance --bom'));
  assert.ok(md.includes('--out'));
});

// ── CLI contract ────────────────────────────────────────────────────
// The exit codes are part of the interface: 2 for misuse (a typo must not read
// as a clean run), 0 only when a report was actually produced.

function runCli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('CLI writes both formats and exits 0', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cli-'));
  try {
    const bomPath = path.join(dir, 'cbom.json');
    fs.writeFileSync(bomPath, JSON.stringify(bom([comp('SM4'), comp('RSA')])));

    const md = runCli(['--bom', bomPath, '--out', path.join(dir, 'r.md')]);
    assert.equal(md.code, 0);
    assert.match(fs.readFileSync(path.join(dir, 'r.md'), 'utf8'), /密码应用合规自查报告/);

    const js = runCli(['--bom', bomPath, '--format', 'json']);
    assert.equal(js.code, 0);
    const parsed = JSON.parse(js.stdout);
    assert.equal(parsed.componentCount, 2);
    assert.equal(parsed.counts.approved, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI treats misuse as exit 2, not as an empty report', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cli-bad-'));
  try {
    const notBom = path.join(dir, 'not-a-bom.json');
    fs.writeFileSync(notBom, JSON.stringify({ hello: 'world' }));
    const badJson = path.join(dir, 'broken.json');
    fs.writeFileSync(badJson, '{ nope');

    assert.equal(runCli([]).code, 2, 'no --bom');
    assert.equal(runCli(['--bom', path.join(dir, 'missing.json')]).code, 2, 'unreadable bom');
    assert.equal(runCli(['--bom', badJson]).code, 2, 'invalid json');
    assert.equal(runCli(['--bom', notBom]).code, 2, 'not CycloneDX');
    assert.equal(runCli(['--bom', notBom, '--format', 'xml']).code, 2, 'unknown format');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI rejects a --dir that is not a directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cli-dir-'));
  try {
    const bomPath = path.join(dir, 'cbom.json');
    fs.writeFileSync(bomPath, JSON.stringify(bom([comp('SM4')])));
    const notDir = path.join(dir, 'file.txt');
    fs.writeFileSync(notDir, 'x');
    assert.equal(runCli(['--bom', bomPath, '--dir', path.join(dir, 'nope')]).code, 2);
    assert.equal(runCli(['--bom', bomPath, '--dir', notDir]).code, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
