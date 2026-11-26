// SPDX-License-Identifier: Apache-2.0
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const SCAN_SCRIPT = path.join(__dirname, '..', 'cbom-scan.cjs');

/**
 * Scan a throwaway project and return its components.
 * @param {Record<string,string>} files relative path -> contents
 */
function scan(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-impl-lang-'));
  try {
    for (const [rel, body] of Object.entries(files)) {
      const abs = path.join(dir, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, body, 'utf8');
    }
    const out = path.join(dir, 'bom.json');
    execFileSync(process.execPath, [SCAN_SCRIPT, '--dir', dir, '--out', out], {
      stdio: 'pipe',
      timeout: 15000,
    });
    return JSON.parse(fs.readFileSync(out, 'utf8'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function languagesOf(bom, name) {
  const comp = bom.components.find((c) => c.name === name);
  assert.ok(comp, `expected a ${name} component`);
  const prop = (comp.properties || []).find((p) => p.name === 'fibemate:implementationLanguages');
  return prop ? prop.value : null;
}

describe('fibemate:implementationLanguages is derived from the hit, not the metadata', () => {
  it('a JavaScript call site reports javascript even when the metadata says c', () => {
    // AES-GCM's metadata carries implementationPlatform "c" (the reference
    // implementation). Emitting it verbatim labelled every JS call site as C.
    const bom = scan({
      'src/app.js': "const c = require('crypto');\nconst x = c.createCipheriv('aes-256-gcm', k, iv);\n",
    });
    assert.equal(languagesOf(bom, 'AES-GCM'), 'javascript');
  });

  it('a hit in two languages reports both, sorted', () => {
    const bom = scan({
      'src/app.js': "c.createCipheriv('aes-256-gcm', k, iv);\n",
      'src/native.c': 'void f(void) { use("aes-256-gcm"); }\n',
    });
    assert.equal(languagesOf(bom, 'AES-GCM'), 'c, javascript');
  });

  it('TypeScript is reported as typescript, not folded into javascript', () => {
    const bom = scan({
      'src/app.ts': "c.createCipheriv('aes-256-gcm', k, iv);\n",
    });
    assert.equal(languagesOf(bom, 'AES-GCM'), 'typescript');
  });

  it('a manifest-only hit keeps the metadata value as the fallback', () => {
    // jsbn maps to RSA, whose metadata is "c". There is no source occurrence,
    // so there is nothing to derive from: the declared value must survive
    // rather than degrade to an empty property.
    const bom = scan({
      'package.json': JSON.stringify({ name: 'dep-only', dependencies: { jsbn: '^1.1.0' } }),
    });
    assert.equal(languagesOf(bom, 'RSA'), 'c');
  });
});
