// SPDX-License-Identifier: Apache-2.0
//
// Mutation test for scripts/test-release-workflow.cjs.
//
// A gate that cannot go red is decoration, so mutate the release workflow ten
// ways and require the contract test to reject every one of them. If a future
// edit weakens the contract test (for example by matching a comment instead of
// a command), this file turns red in CI before the weakness ships.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const wf = fs.readFileSync(path.join(REPO, '.github/workflows/release.yml'), 'utf8');
const tester = fs.readFileSync(path.join(REPO, 'scripts/test-release-workflow.cjs'), 'utf8');

const all = (s, from, to) => s.split(from).join(to);

const mutations = [
  ['M1 drop --provenance everywhere', (s) => all(s, ' --provenance', '')],
  ['M2 wrong registry-url', (s) => s.replace('registry-url: https://registry.npmjs.org', 'registry-url: https://registry.yarnpkg.com')],
  ['M3 drop id-token write from permissions', (s) => s.replace('      id-token: write\n', '')],
  ['M4 bundle instead of output-signature', (s) => s.replace('--output-signature "$TB.sig"', '--bundle "$TB.sigstore"')],
  ['M5 unpin checkout', (s) => s.replace(/actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@v4')],
  // The dispatch path can no longer publish, so "the input defaults to true" is
  // no longer the invariant. What has to stay true is the derivation itself:
  // a flip here would publish every push.
  ['M6 flip dry_run derivation', (s) => s.replace('then DRY="false"; else DRY="true"; fi', 'then DRY="true"; else DRY="false"; fi')],
  ['M7 drop the tag-push guard', (s) => s.replace(/if \[ "\$\{\{ github\.event_name \}\}" != "push" \] \|\| \[ "\$\{GITHUB_REF#refs\/tags\/\}" = "\$GITHUB_REF" \]; then/, 'if false; then')],
  ['M13 checkout stops following the tag', (s) => s.replace(/\n\s*ref: \$\{\{ github\.event\.inputs\.tag \|\| github\.ref \}\}/, '')],
  ['M8 publish without tests', (s) => s.replace('        run: npm test', '        run: echo skipped')],
  ['M9 verification step no longer verifies', (s) => s.replace('          cosign verify-blob \\', '          cosign help-blob \\')],
  // A rehearsal that queries the registry fails for any version already on it;
  // that is how the first real run of this workflow died, so it stays pinned.
  ['M12 dry run calls the registry', (s) => s.replace(
    '      echo "dry_run is true - tarball built, nothing is sent to the registry"',
    '      npm publish --dry-run')],
  ['M10 release carries no assets', (s) => all(all(s, 'gh release create "$TAG" artifacts/*', 'gh release create "$TAG" --draft'), 'gh release upload "$TAG" artifacts/*', 'gh release upload "$TAG" README.md')],
];

let red = 0;
let applied = 0;
let skipped = 0;
for (const [label, mutate] of mutations) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wfmut-'));
  fs.mkdirSync(path.join(dir, '.github/workflows'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  const mutated = mutate(wf);
  // A mutation that no longer applies is drift, not a pass: it means this file
  // stopped testing the thing it claims to test (a stale pinned SHA did exactly
  // that for months). Count it and fail at the end.
  if (mutated === wf) { console.log(`SKIP ${label} (mutation did not apply - pattern drifted)`); skipped++; fs.rmSync(dir, { recursive: true, force: true }); continue; }
  applied++;
  fs.writeFileSync(path.join(dir, '.github/workflows/release.yml'), mutated);
  fs.writeFileSync(path.join(dir, 'scripts/test-release-workflow.cjs'), tester);
  const r = spawnSync(process.execPath, [path.join(dir, 'scripts/test-release-workflow.cjs')], { encoding: 'utf8' });
  const failed = (r.stdout.match(/^FAIL /gm) || []);
  const ok = r.status === 1 && failed.length > 0;
  if (ok) red++;
  console.log(`${ok ? 'RED-OK      ' : 'STILL-GREEN!'} ${label} -> exit=${r.status} failed=${failed.length}`);
  if (!ok) console.log(r.stdout.split('\n').filter((l) => l.startsWith('FAIL')).join('\n') || r.stdout.slice(0, 300));
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${red}/${applied} mutations detected, ${skipped} skipped`);
process.exit(red === applied && skipped === 0 ? 0 : 1);
