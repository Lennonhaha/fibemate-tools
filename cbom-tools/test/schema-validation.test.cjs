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

  it('Keccak-256 dependency receives cryptoProperties via NAME_ALIASES', () => {
    const fixDir = path.join(FIXTURES, 'dep-only-keccak');
    const outPath = path.join(TEMP_DIR, 'cbom-keccak.json');

    const { execSync } = require('child_process');
    execSync(`node "${SCAN_SCRIPT}" --dir "${fixDir}" --out "${outPath}"`, {
      stdio: 'pipe',
      timeout: 15000,
    });

    const cbom = JSON.parse(fs.readFileSync(outPath, 'utf-8'));

    const keccak = cbom.components.find(c => c.name === 'Keccak-256');
    assert(keccak, 'Output should contain Keccak-256 component');

    const props = keccak.cryptoProperties;
    assert(props, 'Keccak-256 should have cryptoProperties (not null)');
    assert.equal(props.assetType, 'algorithm');
    assert.equal(props.algorithmProperties?.primitive, 'other');

    const namespaced = keccak.properties || [];
    const implLang = namespaced.find(p => p.name === 'fibemate:implementationLanguages');
    assert(implLang, 'Keccak-256 should have fibemate:implementationLanguages');
    assert.equal(implLang.value, 'javascript');
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

  describe('José\'s regression fixtures (CycloneDX 1.6 standalone)', () => {
    const REGRESSION = path.join(FIXTURES, 'jose-regression');

    it('valid-sha256.json passes schema validation', () => {
      const cbom = JSON.parse(
        fs.readFileSync(path.join(REGRESSION, 'valid-sha256.json'), 'utf-8')
      );
      const validate = createValidator();
      const valid = validate(cbom);
      if (!valid) {
        const msg = validate.errors.map(e =>
          `  ${e.instancePath || '/'}: ${e.message}`
        ).join('\n');
        assert.fail(`valid-sha256.json should pass, but failed:\n${msg}`);
      }
    });

    it('invalid-uppercase-primitive.json fails (HASH → not hash)', () => {
      const cbom = JSON.parse(
        fs.readFileSync(path.join(REGRESSION, 'invalid-uppercase-primitive.json'), 'utf-8')
      );
      const validate = createValidator();
      const valid = validate(cbom);
      assert.equal(valid, false,
        'invalid-uppercase-primitive.json should fail (uppercase HASH)'
      );
    });

    it('invalid-misplaced-field.json fails (implementationPlatform under cryptoProperties)', () => {
      const cbom = JSON.parse(
        fs.readFileSync(path.join(REGRESSION, 'invalid-misplaced-field.json'), 'utf-8')
      );
      const validate = createValidator();
      const valid = validate(cbom);
      assert.equal(valid, false,
        'invalid-misplaced-field.json should fail (misplaced field)'
      );
    });
  });
});