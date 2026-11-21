'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// False-positive gate for cbom-compliance's "deprecated algorithm" verdict.
//
// On liboqs (1.94 M lines, commit 8c7f659) the scanner reported 18 occurrences
// of deprecated algorithms and the report concluded "high risk". All 18 were
// wrong: 15 were the DSA inside "ML-DSA" / "SLH-DSA" (space-separated) or
// inside prose in a comment, and 3 were the ARM instruction name SHA1 in a
// comment. See output/large-repo-bench-20261121/deprecated-hits.json.
//
// Two directions have to hold, and each can fail on its own:
//
//   suppression  -> prose and compound names produce nothing
//   recall       -> a real DSA_sign() / createHash('sha1') is still reported,
//                   at the right line, even with a comment right above it
//
// A test that only checked the first direction would pass by turning the
// scanner off, so every suppression case is paired with a recall case.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const PROSE = path.join(ROOT, 'fixtures', 'false-positives');
const NODE = process.execPath;

let tmp;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-fp-'));
});
after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function scan(dir) {
  const r = spawnSync(NODE, [SCAN, '--dir', dir], { encoding: 'utf-8' });
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  return JSON.parse(r.stdout);
}

function names(bom) {
  return bom.components.map((c) => c.name).sort();
}

function linesOf(bom, name) {
  const c = bom.components.find((x) => x.name === name);
  if (!c) return [];
  return (c.evidence.occurrences || []).map((o) => o.line);
}

function mk(name, files) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const [file, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, file), content, 'utf8');
  }
  return dir;
}

// ── suppression ─────────────────────────────────────────────────────

test('prose fixture: the 18 liboqs shapes produce no components', () => {
  const got = names(scan(PROSE));
  assert.deepStrictEqual(got, [], `expected no components, got: ${got.join(', ')}`);
});

test('space-separated PQC family plus DSA is not classic DSA', () => {
  const dir = mk('space-separated', {
    'a.cjs': "const ok = 'Copied from slh dsa commit';\nconst bad = 'failed in ml dsa path';\n",
  });
  assert.deepStrictEqual(names(scan(dir)), [], 'space-separated ML-DSA/SLH-DSA leaked as DSA');
});

test('a comment does not hide the code that follows it', () => {
  const dir = mk('comment-then-code', {
    'a.cjs': [
      '// legacy note: DSA keypairs used to be generated here',
      "const key = crypto.generateKeyPairSync('dsa');",
      '',
    ].join('\n'),
  });
  const bom = scan(dir);
  assert.deepStrictEqual(names(bom), ['DSA'], 'the real call after a comment was lost');
  assert.deepStrictEqual(linesOf(bom, 'DSA'), [2], 'line number drifted while stripping');
});

// ── recall ──────────────────────────────────────────────────────────

test('a real DSA_sign() call is still reported', () => {
  const dir = mk('real-dsa', {
    'sign.c': [
      '#include <openssl/dsa.h>',
      '',
      'int do_sign(DSA *k) {',
      '  return DSA_sign(0, digest, 20, sig, &siglen, k);',
      '}',
      '',
    ].join('\n'),
  });
  const bom = scan(dir);
  assert.deepStrictEqual(names(bom), ['DSA'], 'a real DSA_sign() call must not be suppressed');
  // Three hits, all real: the include names the DSA API (1), the type appears
  // in the signature (3), and the call itself is line 4. Asserting the exact
  // trio also proves the stripping pass kept the numbering intact — a pass that
  // ate newlines would collapse them onto one line.
  assert.deepStrictEqual(linesOf(bom, 'DSA'), [1, 3, 4]);
});

test("createHash('sha1') is still reported", () => {
  const dir = mk('real-sha1', {
    'a.cjs': "const h = crypto.createHash('sha1');\n",
  });
  assert.deepStrictEqual(names(scan(dir)), ['SHA-1']);
});

test('string literals are still scanned (the fix must strip comments, not strings)', () => {
  const dir = mk('literal-kept', {
    'a.cjs': "const c = crypto.createCipheriv('aes-256-gcm', k, iv);\n",
  });
  assert.deepStrictEqual(names(scan(dir)), ['AES-GCM']);
});

test('a comment marker inside a string does not swallow the rest of the line', () => {
  // `//` appears inside a URL literal. A naive "cut at //" pass would blank the
  // rest of the line and lose the md5 call that follows it.
  const dir = mk('slash-in-string', {
    'a.cjs': "const u = 'https://example.test//path'; const h = crypto.createHash('md5');\n",
  });
  assert.deepStrictEqual(names(scan(dir)), ['MD5'], 'a // inside a string started a comment');
});
