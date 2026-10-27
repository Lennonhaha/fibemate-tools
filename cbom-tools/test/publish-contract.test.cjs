// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// 发布契约测试 —— 回归「包能 pack、装上去就跑不起来」的缺陷。
//
// 背景：0.2.1 的 `files` 白名单漏了 algorithm-hierarchy.cjs，tarball 里没有它，
// 于是 `npx cbom-tools scan` 在第一行 require 就崩：
//   Error: Cannot find module './algorithm-hierarchy.cjs'
// `npm pack --dry-run` 看着完全正常（7 个文件、没有 node_modules），因为
// 它只回答「打进去了什么」，不回答「打进去的东西能不能跑」。
//
// 这个测试补上后半个问题：把白名单里的每个脚本解析一遍，凡是 require('./x')
// 指向本包内文件的，该文件必须在白名单里，否则 npm test 直接红。

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

const shipped = new Set(pkg.files || []);
// npm always includes package.json, README and LICENSE regardless of files[].
// Only package.json can be targeted by a require(), so that is the one we add.
shipped.add('package.json');
const scripts = [...shipped].filter((f) => f.endsWith('.cjs') || f.endsWith('.js'));

test('every shipped script resolves its local requires inside the tarball', () => {
  assert.ok(scripts.length > 0, 'package.json files 里没有任何脚本');

  const missing = [];
  for (const rel of scripts) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const requires = [...src.matchAll(/require\(\s*['"](\.[^'"]+)['"]\s*\)/g)].map((m) => m[1]);
    for (const req of requires) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), req));
      if (!shipped.has(target)) {
        missing.push(`${rel} requires ${req} -> ${target} (not in files[])`);
      }
    }
  }

  assert.deepEqual(missing, [], 'tarball 会缺这些文件，装上去必然崩：\n' + missing.join('\n'));
});

test('bin entries point at shipped files', () => {
  const bins = pkg.bin || {};
  const broken = Object.entries(bins)
    .filter(([, target]) => !shipped.has(target))
    .map(([name, target]) => `${name} -> ${target} (not in files[])`);
  assert.deepEqual(broken, [], 'bin 指向了不会被打包的文件：\n' + broken.join('\n'));
});

test('every shipped file exists on disk', () => {
  const absent = [...shipped].filter((f) => !fs.existsSync(path.join(ROOT, f)));
  assert.deepEqual(absent, [], 'files[] 里列了不存在的文件：\n' + absent.join('\n'));
});
