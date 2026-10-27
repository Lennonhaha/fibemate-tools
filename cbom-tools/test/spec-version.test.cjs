// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
'use strict';

/**
 * The spec version is not a cosmetic field: a downstream consumer validates the
 * document against the schema that `specVersion` names. So these tests check
 * three things that can break independently:
 *
 *   1. the flag is parsed at all (including `--spec=1.7`, which the old parser
 *      silently ignored for every flag),
 *   2. the emitted document validates against the official schema for the
 *      version it claims,
 *   3. switching versions does not silently change what was found.
 *
 * Schemas are vendored under test/fixtures (bom-1.6/1.7 + cryptography-defs +
 * spdx + jsf), so the suite stays offline and does not drift with the network.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const FIXTURES = path.join(__dirname, 'fixtures');
const SCAN = path.join(__dirname, '..', 'cbom-scan.cjs');
const MLKEM = path.join(FIXTURES, 'mlkem-control');

function validatorFor(version) {
  const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
  addFormats(ajv);
  for (const f of ['spdx.schema.json', 'jsf-0.82.schema.json', 'cryptography-defs.schema.json']) {
    const p = path.join(FIXTURES, f);
    if (!fs.existsSync(p)) continue;
    const schema = JSON.parse(fs.readFileSync(p, 'utf8'));
    schema.$id = schema.$id || 'http://cyclonedx.org/schema/' + f;
    ajv.addSchema(schema, schema.$id);
  }
  const bom = JSON.parse(fs.readFileSync(path.join(FIXTURES, `bom-${version}.schema.json`), 'utf8'));
  bom.$id = bom.$id || `http://cyclonedx.org/schema/bom-${version}.schema.json`;
  return ajv.compile(bom);
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-spec-'));
}

function scan(args) {
  return spawnSync(process.execPath, [SCAN, ...args], { encoding: 'utf8' });
}

function scanToJson(extraArgs) {
  const dir = tmpDir();
  const out = path.join(dir, 'bom.json');
  const res = scan(['--dir', MLKEM, '--out', out, ...extraArgs]);
  assert.equal(res.status, 0, 'scan should succeed, stderr=' + res.stderr);
  assert.ok(fs.existsSync(out), 'scan must write the BOM');
  return JSON.parse(fs.readFileSync(out, 'utf8'));
}

describe('cbom-tools: CycloneDX spec version', () => {
  it('defaults to 1.7 and the output validates against the 1.7 schema', () => {
    const bom = scanToJson([]);
    assert.equal(bom.specVersion, '1.7', 'default must be 1.7 now that 1.7 is published');
    const validate = validatorFor('1.7');
    const ok = validate(bom);
    assert.ok(ok, 'default output must validate against bom-1.7: ' + JSON.stringify((validate.errors || []).slice(0, 3)));
  });

  it('--spec 1.6 emits a document that validates against the 1.6 schema', () => {
    const bom = scanToJson(['--spec', '1.6']);
    assert.equal(bom.specVersion, '1.6');
    const validate = validatorFor('1.6');
    const ok = validate(bom);
    assert.ok(ok, '1.6 output must validate against bom-1.6: ' + JSON.stringify((validate.errors || []).slice(0, 3)));
  });

  it('accepts the equals form --spec=1.6', () => {
    const bom = scanToJson(['--spec=1.6']);
    assert.equal(bom.specVersion, '1.6', '--spec=1.6 must not be ignored');
  });

  it('changing the spec version does not change the findings', () => {
    const a = scanToJson(['--spec', '1.6']);
    const b = scanToJson(['--spec', '1.7']);
    delete a.specVersion;
    delete b.specVersion;
    delete a.metadata.timestamp;
    delete b.metadata.timestamp;
    assert.deepEqual(a, b, 'the same tree must yield the same components under both versions');
  });

  it('rejects an unknown spec version with exit 2 and names the allowed values', () => {
    const res = scan(['--dir', MLKEM, '--spec', '1.5']);
    assert.equal(res.status, 2, 'unknown --spec must be a usage error');
    assert.match(res.stderr, /1\.6, 1\.7/, 'the error must list what is accepted, stderr=' + res.stderr);
  });

  it('rejects a missing --spec value with exit 2', () => {
    const res = scan(['--dir', MLKEM, '--spec']);
    assert.equal(res.status, 2, 'a flag without a value must not silently fall back to the default');
    assert.match(res.stderr, /--spec needs a value/);
  });

  it('--dir=path works (the equals form used to fall back to cwd)', () => {
    const dir = tmpDir();
    const out = path.join(dir, 'bom.json');
    const res = scan(['--dir=' + MLKEM, '--out=' + out]);
    assert.equal(res.status, 0, 'stderr=' + res.stderr);
    const bom = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.ok(bom.components.length > 0, 'a wrong cwd would find nothing; this must find the fixture components');
  });
});
