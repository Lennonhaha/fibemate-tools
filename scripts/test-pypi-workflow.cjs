// SPDX-License-Identifier: Apache-2.0
// Gate: the PyPI release workflow must fail closed.
//
// release-pypi.yml 是唯一能把 artifact 推到公网的入口。trigger / 版本校验 /
// OIDC 权限 / action pin 任何一项写错，错误只在上传那一刻才暴露，所以先用
// 静态检查挡住「一定不能出现的形状」，再用变异证明每条检查真的会红。
//
// 用法：
//   node scripts/test-pypi-workflow.cjs
//   node scripts/test-pypi-workflow.cjs --self-test
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const WF = path.join(ROOT, '.github', 'workflows', 'release-pypi.yml');
const PIN = '7245906fb61fa33a13554f9d5fb856fe61758086';
const TAG_LINE = "      - 'crypto-time-machine-v*'";

function stripComments(s) {
  return s.split(/\r?\n/).map((l) => l.replace(/\s+#.*$/, '')).join('\n');
}

function jobBlock(all, name) {
  const start = all.findIndex((l) => l === '  ' + name + ':');
  if (start < 0) return '';
  let end = all.length;
  for (let i = start + 1; i < all.length; i++) {
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(all[i])) { end = i; break; }
  }
  return all.slice(start, end).join('\n');
}

const CHECKS = [
  {
    id: 'tag_trigger',
    what: 'push tag crypto-time-machine-v* is a trigger',
    run: (t) => t.includes(TAG_LINE),
  },
  {
    id: 'top_permissions_read',
    what: 'top-level permissions is contents: read',
    run: (t) => /^permissions:\n  contents: read$/m.test(t),
  },
  {
    id: 'no_token_secret',
    what: 'no long-lived PyPI token or password is referenced',
    run: (t) => !/PYPI_API_TOKEN|TWINE_PASSWORD|^\s*password:\s*\$\{\{/m.test(t),
  },
  {
    id: 'version_guard',
    what: 'tag version is compared with ctime.__version__ before building',
    run: (t) => t.includes('from ctime import __version__') && t.includes('refusing to publish') && t.includes('exit 2'),
  },
  {
    id: 'twine_check',
    what: 'twine check runs on the built distributions',
    run: (t) => t.includes('python -m twine check dist/*'),
  },
  {
    id: 'packaging_test',
    what: 'the packaging contract test runs in the workflow',
    run: (t) => t.includes('python test/packaging_test.py'),
  },
  {
    id: 'publish_needs_build',
    what: 'publish depends on build',
    run: (t, all) => /^    needs: build$/m.test(jobBlock(all, 'publish')),
  },
  {
    id: 'publish_environment',
    what: 'publish runs in the pypi environment (trusted publisher binding)',
    run: (t, all) => /^    environment: pypi$/m.test(jobBlock(all, 'publish')),
  },
  {
    id: 'id_token_write',
    what: 'publish grants id-token: write for OIDC',
    run: (t, all) => /^\s+id-token: write$/m.test(jobBlock(all, 'publish')),
  },
  {
    id: 'pypi_publish_pinned',
    what: 'pypa/gh-action-pypi-publish is pinned to a 40-hex commit',
    run: (t) => t.includes('pypa/gh-action-pypi-publish@' + PIN) && !/gh-action-pypi-publish@(release|v)\//.test(t),
  },
  {
    id: 'dry_run_guard',
    what: 'workflow_dispatch dry_run keeps publish from running',
    run: (t, all) => jobBlock(all, 'publish').includes('inputs.dry_run == false'),
  },
];

function checkAll(text) {
  const all = text.split(/\r?\n/);
  return CHECKS.map((c) => {
    let ok = false;
    let err = '';
    try { ok = !!c.run(text, all); } catch (e) { err = e.message; }
    return { id: c.id, what: c.what, ok, err };
  });
}

function report(results) {
  let bad = 0;
  for (const r of results) {
    if (!r.ok) bad++;
    console.log((r.ok ? 'PASS ' : 'FAIL ') + r.id + '  [' + r.what + ']' + (r.err ? ' ' + r.err : ''));
  }
  return bad;
}

const TWINE_STEP = [
  '      - name: Check the metadata with twine',
  '        working-directory: crypto-time-machine',
  '        run: python -m twine check dist/*',
  '',
].join('\n');

const PACK_STEP = [
  '      - name: Run the packaging contract test',
  '        working-directory: crypto-time-machine',
  '        run: python test/packaging_test.py',
  '',
].join('\n');

const MUTATIONS = [
  ['M1 tag trigger removed', (t) => t.replace(TAG_LINE + '\n', ''), 'tag_trigger'],
  ['M2 top-level write permission', (t) => t.replace('permissions:\n  contents: read', 'permissions:\n  contents: write'), 'top_permissions_read'],
  ['M3 long-lived token reintroduced', (t) => t.replace('          print-hash: true', '          password: ${{ secrets.PYPI_API_TOKEN }}'), 'no_token_secret'],
  ['M4 version guard neutered', (t) => t.replace('PKG_VERSION="$(python -c "from ctime import __version__; print(__version__)")"', 'PKG_VERSION="$VERSION"'), 'version_guard'],
  ['M5 twine check removed', (t) => t.replace(TWINE_STEP, ''), 'twine_check'],
  ['M6 packaging test removed', (t) => t.replace(PACK_STEP, ''), 'packaging_test'],
  ['M7 publish no longer needs build', (t) => t.replace('    needs: build\n', ''), 'publish_needs_build'],
  ['M8 environment dropped', (t) => t.replace('    environment: pypi\n', ''), 'publish_environment'],
  ['M9 id-token dropped', (t) => t.replace('      id-token: write\n', ''), 'id_token_write'],
  ['M10 floating tag instead of SHA', (t) => t.replace('pypa/gh-action-pypi-publish@' + PIN, 'pypa/gh-action-pypi-publish@release/v1'), 'pypi_publish_pinned'],
  ['M11 dry_run guard removed', (t) => t.replace("    if: ${{ github.event_name == 'push' || inputs.dry_run == false }}\n", ''), 'dry_run_guard'],
];

function selfTest(text) {
  console.log('--- mutations ---');
  let survived = 0;
  for (const [name, mutate, expectFail] of MUTATIONS) {
    const mutated = mutate(text);
    if (mutated === text) {
      console.log('FAIL ' + name + '  [mutation did not change the file]');
      survived++;
      continue;
    }
    const res = checkAll(mutated);
    const target = res.find((r) => r.id === expectFail);
    const red = !!target && !target.ok;
    if (!red) survived++;
    console.log((red ? 'RED-OK   ' : 'SURVIVED ') + name + '  -> ' + expectFail);
  }
  console.log((MUTATIONS.length - survived) + '/' + MUTATIONS.length + ' mutations killed');
  return survived;
}

function main() {
  const raw = fs.readFileSync(WF, 'utf8');
  const text = stripComments(raw);
  const bad = report(checkAll(text));
  console.log((CHECKS.length - bad) + '/' + CHECKS.length + ' checks passed');
  let survived = 0;
  if (process.argv.includes('--self-test') || process.argv.length === 2) {
    survived = selfTest(text);
  }
  if (bad || survived) {
    console.log('GATE FAIL');
    process.exit(1);
  }
  console.log('GATE PASS');
}

main();
