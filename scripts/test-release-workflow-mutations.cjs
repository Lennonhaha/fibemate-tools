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
  ['M5 unpin checkout', (s) => s.replace('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683', 'actions/checkout@v4')],
  ['M6 dry_run defaults to false', (s) => s.replace('default: true', 'default: false')],
  ['M7 mismatch branch no longer exits', (s) => s.replace('            exit 2\n          fi\n          DRY=', '            true\n          fi\n          DRY=')],
  ['M8 publish without tests', (s) => s.replace('        run: npm test', '        run: echo skipped')],
  ['M9 verification step no longer verifies', (s) => s.replace('          cosign verify-blob \\', '          cosign help-blob \\')],
  ['M10 release carries no assets', (s) => all(all(s, 'gh release create "$TAG" artifacts/*', 'gh release create "$TAG" --draft'), 'gh release upload "$TAG" artifacts/*', 'gh release upload "$TAG" README.md')],
];

let red = 0;
let applied = 0;
for (const [label, mutate] of mutations) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wfmut-'));
  fs.mkdirSync(path.join(dir, '.github/workflows'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  const mutated = mutate(wf);
  if (mutated === wf) { console.log(`SKIP ${label} (mutation did not apply)`); fs.rmSync(dir, { recursive: true, force: true }); continue; }
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

console.log(`\n${red}/${applied} mutations detected`);
process.exit(red === applied ? 0 : 1);
