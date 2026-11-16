#!/usr/bin/env node
'use strict';
// Build the tag x registry matrix. Read-only.
// Usage: node enumerate.cjs --git-dir <path> [--scan <repo-root>] [--packages a,b,c] [--out matrix.json]
//
// The npm package name is NOT always the directory name: fibemate-tools/xdiff
// publishes as `fibemate-xdiff`, hallucination-detector as
// `crypto-hallucination-detector`. Tags follow the directory, so they are kept
// as `tagPrefix` and the registry lookup uses package.json's `name`. Guessing
// the registry name from the tag prefix resolves to somebody else's package
// (npm `xdiff` belongs to dominictarr), which is a silent false positive.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const REG = 'https://registry.npmjs.org';
const HDRS = { 'cache-control': 'no-cache', 'user-agent': 'release-audit/1.0' };

function arg(n, d) { const i = process.argv.indexOf(n); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : d; }
const gitDir = arg('--git-dir', process.cwd());
const scanRoot = arg('--scan', null);
const pkgs = (arg('--packages', '') || '').split(',').map(s => s.trim()).filter(Boolean);
const out = arg('--out', null);

function git(a) {
  const r = spawnSync('git', a, { cwd: gitDir, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : '';
}
function findPackageJsons(root, depth, acc) {
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(root, e.name);
    const pj = path.join(p, 'package.json');
    if (fs.existsSync(pj)) {
      try {
        const j = JSON.parse(fs.readFileSync(pj, 'utf8'));
        if (j.name) acc.push({ dir: e.name, name: j.name, version: j.version, private: !!j.private, rel: path.relative(root, p) });
      } catch { /* unreadable package.json is reported by CI, not here */ }
    }
    if (depth > 1) findPackageJsons(p, depth - 1, acc);
  }
}

(async () => {
  const tagLines = git(['for-each-ref', '--format=%(refname:short)', 'refs/tags']).split(/\r?\n/).filter(Boolean);
  const tags = [];
  for (const t of tagLines) {
    const m = /^(.+)-v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(t);
    if (m) tags.push({ tag: t, tagPrefix: m[1], version: m[2] });
  }

  // local package manifests: directory name -> npm name
  const manifests = [];
  if (scanRoot && fs.existsSync(scanRoot)) findPackageJsons(scanRoot, 3, manifests);
  for (const m of manifests) {
    if (!tags.some(t => t.tagPrefix === m.dir)) tags.push({ tag: null, tagPrefix: m.dir, version: m.version });
  }

  const names = new Set([...pkgs, ...manifests.map(m => m.name)]);
  const packages = {};
  for (const name of names) {
    let reg = null;
    const isPrivatePkg = manifests.some(m => m.name === name && m.private);
    // private packages are never published; querying the registry only produces noise
    if (!isPrivatePkg) try {
      const r = await fetch(`${REG}/${name.replace('/', '%2F')}`, { headers: HDRS });
      if (r.ok) {
        const j = await r.json();
        reg = { versions: Object.keys(j.versions || {}), latest: (j['dist-tags'] || {}).latest || null, repository: (j.repository || {}).url || null };
      }
    } catch { /* recorded as null */ }
    const local = manifests.filter(m => m.name === name).map(m => ({ dir: m.dir, rel: m.rel, version: m.version, private: m.private }));
    const prefixes = new Set(local.map(l => l.dir));
    // packages with no manifest on disk are matched by tag prefix (dir name convention)
    const matchedTags = local.length
      ? tags.filter(t => prefixes.has(t.tagPrefix))
      : tags.filter(t => t.tagPrefix === name);
    const isPrivate = local.some(l => l.private);
    // A tag that never had a published package is an orphan, not a release defect:
    // it must not enter the FAIL list, but it should not silently disappear either.
    const status = isPrivate ? 'PRIVATE' : (!reg && matchedTags.length && local.length === 0) ? 'ORPHAN_TAG' : undefined;
    packages[name] = {
      local,
      registry: reg,
      status,
      tags: matchedTags,
      // tag prefixes that never resolved to a package name (would be a mapping bug)
      unmatchedTagPrefixes: [...prefixes].filter(p => !tags.some(t => t.tagPrefix === p)),
    };
  }
  const matrix = { generated_at: new Date().toISOString(), git_dir: gitDir, scan: scanRoot, packages };
  const s = JSON.stringify(matrix, null, 2);
  if (out) fs.writeFileSync(out, s + '\n', 'utf8');
  console.log(s);
})();
