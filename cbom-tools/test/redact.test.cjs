// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

// Tests for `--redact`.
//
// The point of the flag is that a report leaves the machine it was generated on.
// An absolute path names a user, a department, sometimes a project that has not
// been announced. The relative part is the finding; the prefix is the leak.
//
// Every assertion about masking is paired with a control run *without* the flag
// showing the same string present. A test that only checks "the path is gone"
// passes just as well when the path was never there, which is the same shape of
// false green this repository keeps writing tests against.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { summarise, renderMarkdown } = require('../cbom-compliance.cjs');

const CLI = path.join(__dirname, '..', 'cbom-compliance.cjs');
const ABS_ROOT = process.platform === 'win32'
  ? 'C:\\Users\\alice\\secret-project'
  : '/home/alice/secret-project';

function comp(name, location) {
  return {
    type: 'cryptographic-asset',
    name,
    'bom-ref': 'crypto:' + name,
    properties: [],
    evidence: {
      identity: [{ field: 'name', confidence: 0.9, concludedValue: name, methods: [{ technique: 'source-code-analysis', confidence: 0.9 }] }],
      occurrences: [{ location: location, line: 12, symbol: name }],
    },
  };
}

function bom(components) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    version: 1,
    metadata: { timestamp: '2026-01-01T00:00:00.000Z' },
    components: components,
  };
}

function summaryWith(redact) {
  return summarise(bom([comp('RSA', 'src/app.js')]), {
    dir: ABS_ROOT,
    redact: redact,
    pem: { root: ABS_ROOT, scannedFiles: 3, found: [], skipped: [] },
  });
}

test('redact masks the absolute scan root and keeps the relative evidence', () => {
  const s = summaryWith(true);
  assert.equal(s.scanRoot, '<redacted>');
  assert.equal(s.pem.root, '<redacted>');
  assert.equal(s.redacted, true);

  const md = renderMarkdown(s);
  assert.ok(!md.includes('alice'), 'absolute root leaked into the report');
  assert.ok(md.includes('src/app.js'), 'relative evidence was lost');
  assert.ok(md.includes('路径脱敏'), 'the report does not say masking was applied');
});

test('control: without redact the same report does contain the absolute root', () => {
  // This is the assertion that makes the test above meaningful: it proves the
  // string would appear, so "it is absent" is evidence of masking and not of a
  // fixture that never had it.
  const md = renderMarkdown(summaryWith(false));
  assert.ok(md.includes('alice'), 'control failed: the fixture does not carry the path');
});

test('absolute evidence locations are scrubbed, not just the scan root', () => {
  const abs = ABS_ROOT + path.sep + 'src' + path.sep + 'leak.js';
  const s = summarise(bom([comp('RSA', abs)]), { dir: ABS_ROOT, redact: true });
  const md = renderMarkdown(s);
  assert.ok(!md.includes('alice'), 'absolute evidence location leaked');
  assert.ok(md.includes('leak.js'), 'the file name should survive: it is the finding');
});

test('a relative location that merely looks odd is left alone', () => {
  const s = summarise(bom([comp('RSA', 'weird/../src/app.js')]), { dir: '', redact: true });
  const md = renderMarkdown(s);
  assert.ok(md.includes('weird/../src/app.js'), 'relative paths must not be rewritten');
});

function run(args) {
  return spawnSync(process.execPath, [CLI].concat(args), { encoding: 'utf8' });
}

test('CLI: --redact removes the temp root from the report file, control keeps it', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-redact-'));
  try {
    fs.writeFileSync(path.join(dir, 'key.pem'), '-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n', 'utf8');
    const bomPath = path.join(dir, 'bom.json');
    fs.writeFileSync(bomPath, JSON.stringify(bom([comp('RSA', 'src/app.js')])), 'utf8');

    const redactedOut = path.join(dir, 'redacted.md');
    const plainOut = path.join(dir, 'plain.md');

    const a = run(['--bom', bomPath, '--dir', dir, '--out', redactedOut, '--redact']);
    assert.equal(a.status, 0, a.stderr);
    const b = run(['--bom', bomPath, '--dir', dir, '--out', plainOut]);
    assert.equal(b.status, 0, b.stderr);

    const marker = path.basename(dir);
    const redacted = fs.readFileSync(redactedOut, 'utf8');
    const plain = fs.readFileSync(plainOut, 'utf8');

    assert.ok(!redacted.includes(marker), 'the temp directory name is still in the redacted report');
    assert.ok(plain.includes(marker), 'control failed: the plain report has no temp path');
    assert.ok(redacted.includes('<redacted>'));
    assert.ok(redacted.includes('已扫描文本文件'), 'the PEM section should still be present');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: --redact=false is the same as not passing it', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-redact-false-'));
  try {
    const bomPath = path.join(dir, 'bom.json');
    fs.writeFileSync(bomPath, JSON.stringify(bom([comp('RSA', 'src/app.js')])), 'utf8');
    const out = path.join(dir, 'out.md');
    const r = run(['--bom', bomPath, '--dir', dir, '--out', out, '--redact=false']);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.readFileSync(out, 'utf8').includes(path.basename(dir)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: --redact=bogus is a usage error, not a silent default', () => {
  const r = run(['--bom', 'x.json', '--redact=bogus']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--redact takes no value, or true \/ false/);
});
