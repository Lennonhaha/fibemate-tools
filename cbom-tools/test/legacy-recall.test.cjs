'use strict';
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Recall gate for cbom-scan (issue #186).
//
// The fixtures live in `fixtures/legacy/` rather than `test/fixtures/` on
// purpose: `node --test` treats every file under `test/` as a test file and
// would execute them, and the cipher calls in them throw on a real run. They
// are meant to be read as source text by the scanner, nothing else.
//
// The scanner's failure mode is a silent omission, not an error: a file full
// of md5/3des/dsa used to produce a valid, empty-looking CBOM and exit 0. A
// test that only checks "the scanner ran" cannot catch that, so every case
// here asserts the exact set of algorithms that must appear, and each one is
// able to fail.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { DEFAULT_RULES, lookupMeta } = require('../cbom-scan.cjs');
const { HIERARCHY } = require('../algorithm-hierarchy.cjs');

const ROOT = path.join(__dirname, '..');
const SCAN = path.join(ROOT, 'cbom-scan.cjs');
const FIXTURES = path.join(ROOT, 'fixtures', 'legacy');
const NODE = process.execPath;

let tmp;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-recall-'));
});
after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function scan(dir) {
  const r = spawnSync(NODE, [SCAN, '--dir', dir], { encoding: 'utf-8' });
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${r.stderr}`);
  return { bom: JSON.parse(r.stdout), stderr: r.stderr };
}

function names(bom) {
  return new Set(bom.components.map((c) => c.name));
}

function mk(name, files) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const [file, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, file), content, 'utf8');
  }
  return dir;
}

// Twelve legacy algorithms that an audit CBOM must never omit.
const LEGACY = [
  'MD5', 'SHA-1', '3DES', 'Blowfish', 'Camellia-256', 'ARIA-256',
  'Poly1305', 'Blake2b-512', 'EdDSA-Ed448', 'X448', 'DSA', 'RSA',
];

// Positive control: detected before and after the change.
const CONTROL = ['SHA-256', 'SHA3-256', 'SHA-512', 'AES-GCM'];

test('legacy fixture: all twelve algorithms are reported', () => {
  const { bom } = scan(FIXTURES);
  const got = names(bom);
  const missing = LEGACY.filter((n) => !got.has(n));
  assert.deepStrictEqual(missing, [], `missing: ${missing.join(', ')}; got: ${[...got].sort().join(', ')}`);
});

test('control fixture: the previously detected set still works', () => {
  const { bom } = scan(FIXTURES);
  const got = names(bom);
  const missing = CONTROL.filter((n) => !got.has(n));
  assert.deepStrictEqual(missing, [], `missing: ${missing.join(', ')}; got: ${[...got].sort().join(', ')}`);
});

// liboqs and PQClean spell the family and its parameter set without a
// separator (`OQS_KEM_alg_frodokem_640_aes`, `pqclean_mceliece348864_clean`).
// Word-boundary rules match the canonical name (`FrodoKEM-640-AES`) but not the
// identifier a vendored implementation directory actually contains, which is
// the source an auditor usually has (issue #186 follow-up).
const COMPACT = ['Classic-McEliece', 'FrodoKEM', 'NTRU', 'NTRU-Prime'];

test('liboqs/PQClean compact identifiers are reported', () => {
  const { bom } = scan(path.join(ROOT, 'fixtures', 'liboqs-compact'));
  const got = names(bom);
  const missing = COMPACT.filter((n) => !got.has(n));
  assert.deepStrictEqual(missing, [], `missing: ${missing.join(', ')}; got: ${[...got].sort().join(', ')}`);
  const unexpected = [...got].filter((n) => !COMPACT.includes(n));
  assert.deepStrictEqual(unexpected, [], `unexpected: ${unexpected.join(', ')}`);
});

test('prose that shares a word with an algorithm produces no component', () => {
  const { bom } = scan(path.join(ROOT, 'fixtures', 'prose'));
  const got = [...names(bom)];
  assert.deepStrictEqual(got, [], `unexpected components: ${got.join(', ')}`);
});

test('no duplicate (location, line, symbol) occurrences ship', () => {
  const { bom } = scan(FIXTURES);
  for (const comp of bom.components) {
    const seen = new Set();
    for (const o of comp.evidence.occurrences || []) {
      const key = `${o.location}:${o.line}:${o.symbol}`;
      assert.strictEqual(seen.has(key), false, `${comp.name} repeats ${key}`);
      seen.add(key);
    }
  }
});

test('hitting the occurrence cap is announced and marked on the component', () => {
  // 60 distinct lines, so the cap drops 10 of them.
  const lines = [];
  for (let i = 0; i < 60; i++) lines.push(`crypto.createHash('md5').update('x${i}');`);
  const dir = mk('cap', { 'cap.js': lines.join('\n') + '\n' });
  const { bom, stderr } = scan(dir);

  const md5 = bom.components.find((c) => c.name === 'MD5');
  assert.ok(md5, 'MD5 component missing');
  assert.match(stderr, /occurrence cap 50 reached/, `stderr did not mention the cap: ${stderr}`);

  const props = new Map((md5.properties || []).map((p) => [p.name, p.value]));
  assert.strictEqual(props.has('fibemate:occurrencesTruncated'), true, 'fibemate:occurrencesTruncated missing');
  assert.ok(Number(props.get('fibemate:occurrenceCountAtLeast')) >= 60, 'lower bound not recorded');
  assert.strictEqual(md5.evidence.occurrences.length, 50, 'component should hold exactly the cap');
});

test('a parameterised name inherits its family metadata', () => {
  const dir = mk('sized', { 'sized.js': "const h = 'keccak-224';\n" });
  const { bom } = scan(dir);
  const comp = bom.components.find((c) => c.name === 'Keccak-224');
  assert.ok(comp, 'Keccak-224 missing');
  assert.strictEqual(comp.cryptoProperties.algorithmProperties.primitive, 'hash');
  const props = new Map((comp.properties || []).map((p) => [p.name, p.value]));
  assert.strictEqual(props.get('fibemate:quantumSecurity:level'), 'safe');
});

test('every detection rule resolves to algorithm metadata', () => {
  // An unmapped name still ships, but without primitive/level — a component
  // that looks classified and is not. Catch that at build time instead.
  const params = ['256', '512', '768', '1024', 'l1', '1', '2'];
  const bad = [];
  const algs = [];
  for (const { algs: ruleAlgs } of DEFAULT_RULES.sourcePatterns) algs.push(...ruleAlgs);
  for (const algos of Object.values(DEFAULT_RULES.packages)) algs.push(...algos);

  for (const tpl of new Set(algs)) {
    if (!tpl.includes('$')) {
      if (!lookupMeta(tpl)) bad.push(tpl);
      continue;
    }
    const resolved = params.some((p) => lookupMeta(tpl.replace(/\$(\d+)/g, p)) !== null);
    if (!resolved) bad.push(tpl);
  }
  assert.deepStrictEqual(bad, [], `no metadata for: ${bad.join(', ')}`);
});

// ── dictionary alignment gate ───────────────────────────────────────
//
// A rule with no hierarchy entry still emits a component, but it takes no
// part in generic/specific absorption and ships with a 0.7 source
// confidence instead of 0.9. A rule with no metadata ships with no
// primitive and no quantum level at all — a component that looks
// classified and is not. Both failures are silent, so the dictionary is
// asserted instead of being maintained by hand (issue #186 follow-up).
//
// Templates such as `Camellia-$1` expand to one name per alternative in the
// rule's own capture group. The alternatives are read out of the regex here
// rather than copied into this file, so the gate cannot drift away from what
// the scanner can actually emit. A group that is `\d+` has no finite
// alternative list; for those the gate requires the generic family entry
// (e.g. `SHA3`) to exist, which is the "explicitly belongs to a defined
// parameter family" half of the rule.
function captureAlternatives(re) {
  const m = /(?<!\\)\(((?:[^()\\]|\\.)*?)\)/.exec(re.source);
  if (!m) return null;
  const body = m[1];
  if (body === '\\d+') return { unbounded: true, values: [] };
  const values = body.split('|');
  // Anything with regex syntax left in it is not a literal alternative and
  // must not be silently accepted as one.
  if (values.some((v) => /[\\^$*+?[\]{}]/.test(v))) return null;
  return { unbounded: false, values };
}

function dictionaryGaps(hierarchy, metaLookup, rules) {
  const gaps = [];
  const wantMeta = (name, where) => {
    if (!metaLookup(name)) gaps.push(`${name}: no metadata (${where})`);
  };
  const wantEntry = (name, where) => {
    if (!hierarchy[name]) gaps.push(`${name}: no hierarchy entry (${where})`);
  };

  for (const { re, algs } of rules.sourcePatterns) {
    for (const tpl of algs) {
      if (!tpl.includes('$')) {
        wantMeta(tpl, 'sourcePatterns');
        wantEntry(tpl, 'sourcePatterns');
        continue;
      }
      const cap = captureAlternatives(re);
      if (!cap) {
        gaps.push(`${tpl}: cannot read the capture group of ${re}`);
        continue;
      }
      if (cap.unbounded) {
        const family = tpl.replace(/-\$\d+$/, '');
        const entry = hierarchy[family];
        if (!entry) gaps.push(`${tpl}: no generic family entry for ${family}`);
        else if (entry.params !== null) gaps.push(`${family}: family entry must be generic (params: null)`);
        wantMeta(family, `family of ${tpl}`);
        continue;
      }
      for (const value of cap.values) {
        const name = tpl.replace(/\$\d+/g, value);
        wantMeta(name, `expanded from ${tpl}`);
        wantEntry(name, `expanded from ${tpl}`);
      }
    }
  }

  for (const algs of Object.values(rules.packages)) {
    for (const name of algs) {
      wantMeta(name, 'packages');
      wantEntry(name, 'packages');
    }
  }
  return gaps;
}

test('every detection rule resolves to metadata and a hierarchy entry', () => {
  const gaps = dictionaryGaps(HIERARCHY, lookupMeta, DEFAULT_RULES);
  assert.deepStrictEqual(gaps, [], `dictionary gaps:\n${gaps.join('\n')}`);
});

test('the dictionary gate fails when an entry is removed (self-check)', () => {
  // A gate that cannot go red is decoration. Both failure modes are
  // exercised here so a future refactor cannot turn the check into a no-op.
  const noEntry = { ...HIERARCHY };
  delete noEntry.MD5;
  const entryGaps = dictionaryGaps(noEntry, lookupMeta, DEFAULT_RULES);
  assert.ok(
    entryGaps.some((g) => g.startsWith('MD5:')),
    `removing HIERARCHY.MD5 was not reported: ${entryGaps.join(', ')}`
  );

  const withoutMd5Meta = (name) => (name === 'MD5' ? null : lookupMeta(name));
  const metaGaps = dictionaryGaps(HIERARCHY, withoutMd5Meta, DEFAULT_RULES);
  assert.ok(
    metaGaps.some((g) => g.startsWith('MD5:')),
    `removing MD5 metadata was not reported: ${metaGaps.join(', ')}`
  );
});
