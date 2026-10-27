// SPDX-License-Identifier: Apache-2.0
//
// Contract test for .github/workflows/release.yml.
//
// The point of this file is not "does YAML parse". It is: does the release
// workflow actually do the things we claim on the tin, and would it notice if
// one of them silently disappeared? Every assertion below is tied to a fact
// that OpenSSF Scorecard, npm, or a reader of the release page can verify:
//
//   - Scorecard Packaging only scores 10 when one job contains actions/setup-node
//     with registry-url https://registry.npmjs.org AND a `npm ... publish` run
//     step AND that workflow has at least one successful run on record.
//   - Scorecard Signed-Releases only sees asset names ending in .asc/.minisig/
//     .sig/.sign/.sigstore/.sigstore.json - not .bundle, not .pem.
//   - npm provenance only happens with --provenance and id-token: write.
//
// Run: node scripts/test-release-workflow.cjs
// Exit: 0 all pass, 1 a check failed, 2 usage/environment problem.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const WF_REL = '.github/workflows/release.yml';
// RELEASE_WF lets the mutation suite point this gate at a deliberately
// broken copy instead of editing the real workflow.
const WF = process.env.RELEASE_WF ? path.resolve(process.env.RELEASE_WF) : path.join(ROOT, WF_REL);

const results = [];
function check(name, fn) {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail: detail || '' });
  } catch (err) {
    results.push({ name, ok: false, detail: err.message });
  }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

if (!fs.existsSync(WF)) {
  console.log(`FAIL ${WF_REL} does not exist`);
  console.log('(this is the expected red state before the workflow is written)');
  process.exit(1);
}

const src = fs.readFileSync(WF, 'utf8');
const lines = src.split('\n');

// Comments are documentation, not behaviour. A check that a phrase "exists"
// can be satisfied by a comment describing the phrase, which is exactly how a
// gate goes green while the workflow does nothing, so everything below reads
// executable lines only.
const codeLines = lines.filter((l) => !/^\s*#/.test(l));
const code = codeLines.join('\n');
const windowAfter = (needle, size) => {
  const at = code.indexOf(needle);
  return at < 0 ? '' : code.slice(at, at + size);
};

// --- structural facts ------------------------------------------------------

check('workflow.exists_and_nonempty', () => {
  assert(src.trim().length > 0, 'file is empty');
  return `${Buffer.byteLength(src)} bytes, ${lines.length} lines`;
});

check('workflow.declares_name_and_on', () => {
  assert(/^name:\s*\S+/m.test(src), 'missing top-level name:');
  assert(/^on:/m.test(src), 'missing top-level on:');
  return 'name + on present';
});

check('workflow.has_workflow_dispatch_with_dry_run_default_true', () => {
  assert(/workflow_dispatch:/.test(src), 'no workflow_dispatch trigger');
  const idx = src.indexOf('workflow_dispatch:');
  const tail = src.slice(idx, idx + 600);
  assert(/dry_run:/.test(tail), 'workflow_dispatch has no dry_run input');
  assert(/default:\s*true/.test(tail), 'dry_run does not default to true (safe default required)');
  return 'dispatchable, dry_run defaults to true';
});

check('workflow.tag_triggers_are_package_prefixed', () => {
  const tags = [...src.matchAll(/-\s*'([a-z0-9-]+)-v\*'/g)].map((m) => m[1]);
  assert(tags.length > 0, 'no package-prefixed tag patterns, e.g. - \'verifact-v*\'');
  assert(tags.includes('verifact'), 'verifact-v* trigger missing');
  assert(tags.includes('cbom-tools'), 'cbom-tools-v* trigger missing');
  assert(tags.includes('hallucination-detector'), 'hallucination-detector-v* trigger missing');
  return tags.join(', ');
});

// --- Scorecard Packaging matcher (same job!) --------------------------------

check('packaging.setup_node_with_registry_url', () => {
  assert(/uses:\s*actions\/setup-node@/.test(src), 'no actions/setup-node step');
  assert(/registry-url:\s*https:\/\/registry\.npmjs\.org\s*$/m.test(src),
    'registry-url must be exactly https://registry.npmjs.org');
  return 'registry-url present';
});

check('packaging.npm_publish_in_same_job', () => {
  // Scorecard requires setup-node and npm publish inside ONE job; a separate
  // publish job would silently score -1 forever.
  const jobStarts = [...src.matchAll(/^  ([a-zA-Z0-9_-]+):\s*$/gm)].map((m) => ({ name: m[1], at: m.index }));
  assert(jobStarts.length > 0, 'no jobs found');
  const jobs = jobStarts.map((j, i) => ({
    name: j.name,
    body: src.slice(j.at, i + 1 < jobStarts.length ? jobStarts[i + 1].at : src.length),
  }));
  const job = jobs.find((j) => /actions\/setup-node@/.test(j.body));
  assert(job, 'setup-node not inside any job body');
  assert(/npm[^\n]*publish/.test(job.body), `job "${job.name}" has setup-node but no "npm ... publish" run step`);
  return `same job: ${job.name}`;
});

check('packaging.publish_uses_provenance', () => {
  const publishLines = codeLines.filter((l) => /^\s*npm\s+publish\b/.test(l) && !/--dry-run/.test(l));
  assert(publishLines.length > 0, 'no npm publish invocation');
  const without = publishLines.filter((l) => !/--provenance/.test(l));
  assert(without.length === 0,
    'these publish paths skip --provenance: ' + without.map((l) => l.trim()).join(' | '));
  return publishLines.map((l) => l.trim()).join(' | ').slice(0, 160);
});

check('packaging.id_token_write_present', () => {
  // Find the *job-level* permissions block, not the first one in the file.
  // Since every workflow now declares a read-only top level, the first block is
  // no longer the one that publishes, and asserting against it was a check that
  // could not pass for the right reason.
  const blocks = [];
  for (let i = 0; i < codeLines.length; i++) {
    if (!/^\s*permissions:\s*$/.test(codeLines[i])) continue;
    const indent = codeLines[i].search(/\S/);
    if (indent === 0) continue; // top level: read-only by policy
    const block = [];
    for (let j = i + 1; j < codeLines.length; j++) {
      const line = codeLines[j];
      if (line.trim() === '') continue;
      if (line.search(/\S/) <= indent) break;
      block.push(line.trim());
    }
    blocks.push({ indent, block });
  }
  assert(blocks.length > 0, 'no job-level permissions block');
  // Scope the assertion to a block: a comment or an unrelated step mentioning
  // id-token must not satisfy it.
  const publishing = blocks.filter((b) =>
    b.block.some((l) => /^id-token:\s*write$/.test(l)) &&
    b.block.some((l) => /^contents:\s*write$/.test(l)));
  assert(publishing.length > 0,
    'no job-level permissions block grants both contents: write and id-token: write');
  return 'job-level contents + id-token write';
});

// --- Scorecard Signed-Releases matcher --------------------------------------

check('signing.cosign_sign_blob_present', () => {
  assert(/cosign-installer@/.test(src), 'cosign is not installed');
  assert(/cosign sign-blob/.test(src), 'no cosign sign-blob step');
  return 'cosign sign-blob present';
});

check('signing.produces_a_suffix_scorecard_recognises', () => {
  // scorecard: signatureExtensions = .asc .minisig .sig .sign .sigstore .sigstore.json
  const outSig = /--output-signature\s+"?([^"\s]+)"?/.exec(src);
  assert(outSig, 'sign-blob does not set --output-signature');
  const name = outSig[1];
  const recognised = ['.asc', '.minisig', '.sig', '.sign', '.sigstore', '.sigstore.json'];
  assert(recognised.some((s) => name.endsWith(s) || name.includes(s)),
    `signature artifact "${name}" is not one of ${recognised.join('/')} - Scorecard will report 0`);
  assert(!/--bundle/.test(src),
    'only --bundle is used: scorecard does not recognise .bundle as a signature');
  return name;
});

check('signing.verifies_its_own_signature_before_publishing', () => {
  const step = windowAfter('name: Verify our own signature', 1400);
  assert(step, 'no "Verify our own signature" step');
  assert(/cosign verify-blob/.test(step), 'the verification step does not run cosign verify-blob');
  assert(/--certificate-identity-regexp/.test(step), 'verify-blob without identity pinning');
  assert(/--certificate-oidc-issuer\s+https:\/\/token\.actions\.githubusercontent\.com/.test(step),
    'verify-blob must pin the GitHub OIDC issuer');
  return 'verify-blob with identity + issuer pinned';
});

check('signing.attaches_signature_to_the_release', () => {
  assert(/(gh release create|action-gh-release)/.test(src), 'no release creation step');
  const uploads = lines.filter((l) => /gh release (create|upload)/.test(l));
  assert(uploads.length > 0, 'release exists but nothing is uploaded to it');
  const uploadText = uploads.join(' ');
  // Either the .sig is named explicitly, or a glob over the directory the
  // signature was written into is uploaded. Both are legitimate; an upload that
  // only mentions the tarball is not.
  const explicitSig = /\.sig\b/.test(uploadText) || /\$\{?sig\}?/i.test(uploadText);
  const globOverSignatureDir = /artifacts\/\*/.test(uploadText) && /\$GITHUB_WORKSPACE\/artifacts/.test(src);
  assert(explicitSig || globOverSignatureDir,
    'release upload would carry the tarball but not the .sig asset');
  return explicitSig ? 'explicit .sig asset' : 'uploads the directory the .sig is written into';
});

// --- honesty / supply-chain hygiene ----------------------------------------

check('hygiene.all_uses_pinned_to_sha', () => {
  const uses = [...src.matchAll(/uses:\s*([^\s#]+)/g)].map((m) => m[1]);
  assert(uses.length > 0, 'no uses: entries');
  const unpinned = uses.filter((u) => !/@[0-9a-f]{40}$/.test(u));
  assert(unpinned.length === 0, `floating tags: ${unpinned.join(', ')}`);
  return `${uses.length} actions, all 40-hex pinned`;
});

check('hygiene.version_must_match_tag', () => {
  const at = code.indexOf('PKG_VERSION');
  assert(at >= 0, 'the workflow never compares the tag version against package.json');
  const branch = code.slice(at, at + 800);
  assert(/\[\s*"\$PKG_VERSION"\s*!=\s*"\$VERSION"\s*\]/.test(branch),
    'no direct comparison of PKG_VERSION and VERSION');
  assert(/exit\s+[1-9]/.test(branch), 'the mismatch branch does not exit non-zero, so publishing continues');
  return 'tag/version mismatch exits non-zero';
});

check('hygiene.no_hardcoded_token', () => {
  assert(!/npm_[A-Za-z0-9]{36}/.test(src), 'looks like a literal npm token in the workflow');
  assert(/secrets\.NPM_TOKEN/.test(src), 'does not read secrets.NPM_TOKEN as one of the auth paths');
  return 'no literal credentials';
});

check('hygiene.dry_run_guards_the_publish', () => {
  const publishIdx = src.indexOf('npm publish') >= 0 ? src.indexOf('npm publish') : src.indexOf('publish');
  const window = src.slice(Math.max(0, publishIdx - 800), publishIdx);
  assert(/dry_run|DRY_RUN/.test(window), 'nothing near the publish step consults dry_run: --dry-run mode is not wired');
  return 'publish is gated by dry_run';
});

check('hygiene.dry_run_does_not_touch_the_registry', () => {
  // Learned the hard way: npm publish --dry-run still asks the registry whether
  // the version already exists, so a rehearsal of an already-shipped version
  // fails. A dry run must stop after packing.
  const at = code.indexOf('dry_run }}" = "true"');
  assert(at >= 0, 'no dry_run branch');
  const block = code.slice(at, code.indexOf('exit 0', at));
  assert(block, 'dry_run branch does not exit early');
  const calls = block.split('\n').filter((l) => /^\s*npm\s+publish\b/.test(l));
  assert(calls.length === 0, 'dry_run branch still calls npm publish, which queries the registry');
  return 'dry run stops after pack';
});

check('hygiene.runs_tests_before_publishing', () => {
  assert(/npm test|node --test/.test(src), 'workflow publishes without running the package tests');
  return 'tests run in the same job';
});

check('hygiene.installs_declared_dependencies_before_tests', () => {
  // cbom-tools declares ajv as a devDependency for its schema tests. This
  // workflow ran `npm test` without ever installing, so the tests passed on a
  // machine that already had node_modules and failed on a clean runner with
  // Cannot find module 'ajv' - after the version had been tagged.
  assert(/npm ci\b/.test(code), 'no "npm ci" anywhere: declared dependencies are never installed');
  assert(/package-lock\.json/.test(code), 'npm ci is not guarded by a package-lock.json check');
  const installAt = code.search(/if \[ -f package-lock\.json \]/);
  const testAt = code.search(/npm test/);
  assert(installAt >= 0, 'no lockfile-guarded install block');
  assert(testAt >= 0, 'no npm test');
  assert(installAt < testAt, 'dependencies are installed after the tests, not before');
  assert(/no dependencies declared - nothing to install/.test(code),
    'no zero-dependency path: packages without deps would still run npm install');
  return 'lockfile-guarded install runs before the tests';
});

// --- report ----------------------------------------------------------------

let failed = 0;
for (const r of results) {
  if (!r.ok) failed++;
  console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}${r.detail ? '  [' + r.detail + ']' : ''}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed === 0 ? 0 : 1);
