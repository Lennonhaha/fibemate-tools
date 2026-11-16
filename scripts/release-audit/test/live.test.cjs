'use strict';
// End-to-end smoke test. Hits the real registry and GitHub, so it is opt-in:
//   AUDIT_LIVE=1 node --test scripts/release-audit/test/live.test.cjs
//
// This proves "the network path still works today". It deliberately does NOT carry
// the grading coverage - that lives in classify.test.cjs, which runs offline on
// every PR. A gate whose only test needs the internet is a gate that gets skipped.
//
// What it audits is the CURRENT latest version, resolved from the registry at run
// time. It used to name 0.2.9, which stopped being "the release that should be
// PASS/A" the moment 0.3.0 was published: the test then failed on `latest matches`
// and told us nothing about the tool. Naming a version in a regression test makes
// the test expire; resolving it makes the assertion "whatever we publish next must
// still audit as A" - which is the property worth guarding.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const enabled = process.env.AUDIT_LIVE === '1';
const ROOT = path.join(__dirname, '..', '..', '..');
const CLI = path.join(__dirname, '..', 'verify-one.cjs');
const PKG = 'cbom-tools';

function latestVersion() {
  // Ask the registry directly instead of shelling out to the npm CLI: on Windows
  // `npm` is a .cmd shim that spawnSync cannot execute without a shell, so the CLI
  // route quietly makes this test Windows-only-broken while passing in CI.
  const https = require('node:https');
  return new Promise((resolve, reject) => {
    const req = https.get(`https://registry.npmjs.org/${PKG}/latest`, {
      headers: { accept: 'application/json', 'user-agent': 'fibemate-release-audit' },
      timeout: 20000,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`registry returned ${res.statusCode} for ${PKG}/latest`));
        try {
          const v = JSON.parse(body).version;
          if (!v) return reject(new Error(`no version field in the registry response for ${PKG}`));
          resolve(v);
        } catch (e) { reject(new Error(`registry response was not JSON: ${e.message}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('registry request timed out')); });
    req.on('error', reject);
  });
}

test('live: the latest published cbom-tools resolves to PASS / A', { skip: enabled ? false : 'set AUDIT_LIVE=1 to run' }, async () => {
  const version = await latestVersion();
  console.log(`# auditing ${PKG}@${version} (registry dist-tags.latest)`);

  const r = spawnSync(process.execPath, [
    CLI, PKG, version,
    '--git-dir', ROOT,
    '--pkg-dir', PKG,
    // The prefix is known for this package; naming it means a missing tag is a
    // real failure instead of "maybe the prefix differs".
    '--tag', `cbom-tools-v${version}`,
  ], { encoding: 'utf8', env: process.env });
  const line = (r.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop();
  assert.ok(line, `no output; stderr: ${r.stderr}`);
  const rec = JSON.parse(line);

  // Say why the checkout cannot answer before blaming the release: a shallow
  // checkout has no tags and no tag history, and that is a job-configuration bug.
  assert.equal(rec.tag_lookup, 'present',
    `tag ${rec.tag} was not resolvable in this checkout - the live job needs fetch-depth: 0 ` +
    `(reasons: ${(rec.reasons || []).join(' | ')})`);
  assert.equal(rec.tag_exists, true);

  assert.equal(rec.verdict, 'PASS', `reasons: ${(rec.reasons || []).join(' | ')}`);
  assert.equal(rec.level, 'A');
  assert.ok(rec.builder, 'builder must be filled from runDetails.builder.id');
  assert.equal(rec.subject_match, true);
});
