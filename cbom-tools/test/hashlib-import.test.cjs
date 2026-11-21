// SPDX-License-Identifier: Apache-2.0
// An import is not a usage. `import hashlib` was mapped to SHA-256, so a file
// that imports the module and calls hashlib.md5() reported SHA-256 at the
// import line. That is the same class of false positive as reading comments
// as evidence (see #212), one layer up: the tool inferred from a module name.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const SCAN = path.join(__dirname, '..', 'cbom-scan.cjs');

function scanSource(source, name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-hashlib-'));
  fs.writeFileSync(path.join(dir, name), source, 'utf8');
  const out = path.join(dir, 'out.cbom.json');
  execFileSync(process.execPath, [SCAN, '--dir', dir, '--out', out], { encoding: 'utf8' });
  const bom = JSON.parse(fs.readFileSync(out, 'utf8'));
  const byName = {};
  for (const c of bom.components || []) byName[c.name] = c;
  return { dir, byName };
}

test('an import alone does not produce SHA-256', () => {
  const { dir, byName } = scanSource('import hashlib\n\n\ndef digest(x):\n    return hashlib.md5(x).hexdigest()\n', 'legacy.py');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.strictEqual(byName['SHA-256'], undefined, 'import hashlib alone must not claim SHA-256');
  assert.ok(byName['MD5'], 'the real hashlib.md5() call must still be detected');
});

test('the call site still produces SHA-256 at its own line', () => {
  const { dir, byName } = scanSource('import hashlib\n\n\ndef digest(x):\n    return hashlib.sha256(x).hexdigest()\n', 'modern.py');
  fs.rmSync(dir, { recursive: true, force: true });
  const comp = byName['SHA-256'];
  assert.ok(comp, 'hashlib.sha256() must be detected');
  const lines = (comp.evidence?.occurrences || []).map((o) => o.line);
  assert.ok(lines.includes(5), 'evidence must point at line 5, got ' + JSON.stringify(lines));
});

test('hashlib.new("sha256") still counts', () => {
  const { dir, byName } = scanSource('import hashlib\nh = hashlib.new("sha256")\n', 'dyn.py');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(byName['SHA-256'], 'hashlib.new("sha256") must be detected');
});
