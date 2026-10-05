// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// CSV → CBOM 转换测试

const { test, describe } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CSV_CLI = path.join(ROOT, 'cbom-csv.cjs');
const FIXTURES = path.join(__dirname, 'fixtures', 'csv');
const SCHEMA = path.join(__dirname, 'fixtures', 'bom-1.6.schema.json');
const NODE = process.execPath;
const TEMP = path.join(ROOT, 'test', '_tmp_csv');

// Helpers

function run(args) {
  const r = spawnSync(NODE, [CSV_CLI, ...args], {
    encoding: 'utf-8',
    cwd: ROOT,
  });
  return r;
}

function runOk(args) {
  const r = run(args);
  assert.strictEqual(r.status, 0, `exit=${r.status} stderr=${(r.stderr || '').slice(0, 200)}`);
  return JSON.parse(r.stdout);
}

function runFail(args) {
  const r = run(args);
  assert.notStrictEqual(r.status, 0, 'expected non-zero exit');
  return r;
}

function comp(bom, name) {
  return bom.components?.find((c) => c.name === name);
}

// ---- Tests ----

test('simple CSV → valid CBOM with correct components', () => {
  const bom = runOk(['--input', path.join(FIXTURES, 'simple.csv')]);
  assert.strictEqual(bom.bomFormat, 'CycloneDX');
  assert.strictEqual(bom.specVersion, '1.6');

  // 6 rows → 5 unique algorithms (SHA-256 appears twice → merged)
  assert.strictEqual(bom.components.length, 5);
  const names = bom.components.map((c) => c.name).sort();
  assert.deepStrictEqual(names, ['AES-256-GCM', 'ML-DSA-65', 'ML-KEM-768', 'RSA', 'SHA-256']);
});

test('duplicate algorithms merged into one component with accumulated occurrences', () => {
  const bom = runOk(['--input', path.join(FIXTURES, 'simple.csv')]);
  const sha = comp(bom, 'SHA-256');
  assert.ok(sha, 'SHA-256 component not found');
  assert.strictEqual(sha.evidence.occurrences.length, 2);
  assert.strictEqual(sha.evidence.occurrences[0].location, 'src/crypto.js');
  assert.strictEqual(sha.evidence.occurrences[0].line, 42);
  assert.strictEqual(sha.evidence.occurrences[1].location, 'src/utils.js');
  assert.strictEqual(sha.evidence.occurrences[1].line, 7);
});

test('known algorithms get cryptoProperties from metadata', () => {
  const bom = runOk(['--input', path.join(FIXTURES, 'simple.csv')]);
  const kem = comp(bom, 'ML-KEM-768');
  assert.ok(kem, 'ML-KEM-768 not found');
  assert.strictEqual(kem.type, 'cryptographic-asset');
  assert.strictEqual(kem.cryptoProperties.assetType, 'algorithm');
  assert.strictEqual(kem.cryptoProperties.algorithmProperties.primitive, 'kem');
});

test('unknown algorithms classified without cryptoProperties, warning on stderr', () => {
  const csvPath = path.join(TEMP, 'unknown.csv');
  if (!fs.existsSync(TEMP)) fs.mkdirSync(TEMP, { recursive: true });
  fs.writeFileSync(
    csvPath,
    'file,line,algorithm\nsrc/foo.js,1,MySecretAlgo\nsrc/bar.js,2,AnotherAlgo\n',
    'utf-8',
  );

  const r = run(['--input', csvPath]);
  // Exit code 0 (we still produce a valid CBOM)
  assert.strictEqual(r.status, 0);

  // Warning on stderr
  assert.ok(r.stderr.includes('not in metadata'), 'stderr should list unknown algorithms');

  const bom = JSON.parse(r.stdout);
  assert.strictEqual(bom.components.length, 2);
  // Unknown algorithms get no cryptoProperties
  assert.strictEqual(bom.components[0].cryptoProperties, undefined);
  assert.strictEqual(bom.components[1].cryptoProperties, undefined);

  // Cleanup
  fs.rmSync(csvPath);
});

test('empty CSV produces empty CBOM with warning', () => {
  const csvPath = path.join(TEMP, 'empty.csv');
  if (!fs.existsSync(TEMP)) fs.mkdirSync(TEMP, { recursive: true });
  // Header only — no data rows
  fs.writeFileSync(csvPath, 'file,line,algorithm\n', 'utf-8');

  const r = run(['--input', csvPath]);
  assert.strictEqual(r.status, 0);
  assert.ok(r.stderr.includes('no algorithms found'));

  const bom = JSON.parse(r.stdout);
  assert.strictEqual(bom.components.length, 0);

  fs.rmSync(csvPath);
});

test('missing required column exits with error', () => {
  const csvPath = path.join(TEMP, 'bad.csv');
  if (!fs.existsSync(TEMP)) fs.mkdirSync(TEMP, { recursive: true });
  fs.writeFileSync(csvPath, 'path,desc,algo\nx.js,hash,SHA-256\n', 'utf-8');

  const r = runFail(['--input', csvPath]);
  assert.ok(r.stderr.includes('required column'), 'should report missing column');

  fs.rmSync(csvPath);
});

test('--map flag renames columns', () => {
  const csvPath = path.join(TEMP, 'mapped.csv');
  if (!fs.existsSync(TEMP)) fs.mkdirSync(TEMP, { recursive: true });
  fs.writeFileSync(
    csvPath,
    'sourcefile,linenum,cryptoalgo\nsrc/a.js,10,ML-KEM-768\nsrc/b.js,20,SHA-256\n',
    'utf-8',
  );

  const bom = runOk([
    '--input', csvPath,
    '--map', 'file=sourcefile,line=linenum,algorithm=cryptoalgo',
    '--name', 'test-project',
    '--version', '1.0.0',
  ]);
  assert.strictEqual(bom.components.length, 2);
  // Project name in metadata
  assert.strictEqual(bom.metadata.component.name, 'test-project');
  assert.strictEqual(bom.metadata.component.version, '1.0.0');

  const kem = comp(bom, 'ML-KEM-768');
  assert.strictEqual(kem.evidence.occurrences[0].location, 'src/a.js');
  assert.strictEqual(kem.evidence.occurrences[0].line, 10);

  fs.rmSync(csvPath);
});

test('--name/--version adds project component to metadata', () => {
  const bom = runOk([
    '--input', path.join(FIXTURES, 'simple.csv'),
    '--name', 'test-app',
    '--version', '2.0.0',
  ]);
  assert.strictEqual(bom.metadata.component.name, 'test-app');
  assert.strictEqual(bom.metadata.component.version, '2.0.0');
});

test('output file via --out', () => {
  if (!fs.existsSync(TEMP)) fs.mkdirSync(TEMP, { recursive: true });
  const outPath = path.join(TEMP, 'result.json');

  const r = run(['--input', path.join(FIXTURES, 'simple.csv'), '--out', outPath]);
  assert.strictEqual(r.status, 0);
  assert.ok(r.stderr.includes('wrote'));

  const bom = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  assert.strictEqual(bom.components.length, 5);

  fs.rmSync(outPath);
});

test('non-existent input file exits with error', () => {
  const r = runFail(['--input', '/nonexistent/file.csv']);
  assert.ok(r.stderr.includes('not found'));
});

test('library-safe: require() does NOT execute main', () => {
  const mod = require(CSV_CLI);
  assert.ok(typeof mod.toCycloneDX === 'function');
  assert.ok(typeof mod.lookupMeta === 'function');
  assert.ok(typeof mod.readCsv === 'function');
  assert.ok(typeof mod.main === 'function');
});

test('output validates against CycloneDX 1.6 schema', () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, 'utf-8'));
  const bom = runOk(['--input', path.join(FIXTURES, 'simple.csv')]);

  // Validate using ajv if available, else skip
  let validate;
  try {
    const Ajv = require('ajv');
    const ajv = new Ajv({ strict: false });
    validate = ajv.compile(schema);
  } catch {
    // ajv not installed — skip schema validation, test structural instead
    assert.strictEqual(bom.bomFormat, 'CycloneDX');
    assert.strictEqual(bom.specVersion, '1.6');
    return; // skip full schema validation
  }

  const valid = validate(bom);
  if (!valid) {
    assert.fail(`schema validation failed:\n${validate.errors.map(e => `  ${e.instancePath}: ${e.message}`).join('\n')}`);
  }
});

// Cleanup temp dir
test.after(() => {
  try { fs.rmSync(TEMP, { recursive: true }); } catch { /* ok */ }
});