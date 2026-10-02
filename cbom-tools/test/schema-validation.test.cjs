// SPDX-License-Identifier: Apache-2.0
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const FIXTURES = path.join(__dirname, 'fixtures');
const SCHEMA_PATH = path.join(FIXTURES, 'bom-1.6.schema.json');
const SCAN_SCRIPT = path.join(__dirname, '..', 'cbom-scan.cjs');
const TEMP_DIR = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cbom-schema-test-'));

/**
 * Load CycloneDX 1.6 schema with external $ref deps resolved.
 */
function createValidator() {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf-8'));
  const spdxSchema = JSON.parse(
    fs.readFileSync(path.join(FIXTURES, 'spdx.schema.json'), 'utf-8')
  );
  const jsfSchema = JSON.parse(
    fs.readFileSync(path.join(FIXTURES, 'jsf-0.82.schema.json'), 'utf-8')
  );

  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  // Register external schemas so $ref resolves
  ajv.addSchema(spdxSchema, 'spdx.schema.json');
  ajv.addSchema(jsfSchema, 'jsf-0.82.schema.json#/definitions/signature');
  const validate = ajv.compile(schema);
  return validate;
}

function generateCBOM(dir, outPath) {
  const { execSync } = require('child_process');
  execSync(`node "${SCAN_SCRIPT}" --dir "${dir}" --out "${outPath}"`, {
    stdio: 'pipe',
    timeout: 15000,
  });
  assert(fs.existsSync(outPath), 'CBOM output not written');
  return JSON.parse(fs.readFileSync(outPath, 'utf-8'));
}

describe('CBOM CycloneDX 1.6 schema validation', () => {
  it('generated CBOM is schema-valid', () => {
    const outPath = path.join(TEMP_DIR, 'cbom.json');
    const cbom = generateCBOM(__dirname, outPath);

    assert(cbom.components, 'CBOM has no components array');
    assert(cbom.components.length > 0, 'CBOM has zero components');

    const validate = createValidator();
    const valid = validate(cbom);

    if (!valid) {
      const msg = validate.errors
        .map(e =>
          `  ${e.instancePath || '/'}: ${e.message}` +
          (e.params ? ' ' + JSON.stringify(e.params) : '')
        )
        .join('\n');
      assert.fail(`CBOM failed schema validation:\n${msg}`);
    }
  });

  it('primitive values are lowercase', () => {
    const outPath = path.join(TEMP_DIR, 'cbom-prim.json');
    const cbom = generateCBOM(__dirname, outPath);

    const primitives = cbom.components
      .filter(c => c.cryptoProperties?.algorithmProperties?.primitive)
      .map(c => c.cryptoProperties.algorithmProperties.primitive);

    const uppercase = primitives.filter(p => p !== p.toLowerCase());
    if (uppercase.length > 0) {
      assert.fail(`Uppercase primitive values found: ${uppercase.join(', ')}`);
    }

    const forbidden = ['HASH', 'KEM', 'SIGN', 'ECC', 'MATH', 'PROTO', 'AEAD',
      'SYM', 'ASYMMETRIC', 'KDF', 'OTHER', 'PKE'];
    const foundForbidden = primitives.filter(p => forbidden.includes(p));
    if (foundForbidden.length > 0) {
      assert.fail(`Old uppercase primitive values still present: ${foundForbidden.join(', ')}`);
    }
  });
});