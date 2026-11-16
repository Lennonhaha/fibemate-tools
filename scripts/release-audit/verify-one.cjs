#!/usr/bin/env node
'use strict';
// Audit one published npm version. Read-only.
// Usage: node verify-one.cjs <pkg> <version> [--repo owner/repo] [--git-dir path] [--tag tag] [--out file] [--ignore-latest]
//
// Two deliberate additions to the reviewed design, both from evidence:
//   - prov_git_commit: SLSA v1 for GitHub Actions carries the built commit in
//     resolvedDependencies[0].digest.gitCommit. GitHub's release target_commitish
//     is usually a branch name, so comparing that is unreliable; the provenance
//     gitCommit is the check that can actually go red.
//   - --ignore-latest: auditing a historical version would otherwise fail the
//     "latest matches" gate, which only makes sense for the newest release.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { classify } = require('./lib/classify.cjs');

const REG = 'https://registry.npmjs.org';
const HDRS = { 'cache-control': 'no-cache', 'user-agent': 'release-audit/1.0' };

const pkg = process.argv[2];
const version = process.argv[3];
if (!pkg || !version || pkg.startsWith('--')) {
  console.error('usage: node verify-one.cjs <pkg> <version> [--repo owner/repo] [--git-dir path] [--tag tag] [--out file] [--ignore-latest]');
  process.exit(2);
}
function arg(n, d) { const i = process.argv.indexOf(n); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : d; }
const outFile = arg('--out', null);
const gitDir = arg('--git-dir', null);
const tag = arg('--tag', `${pkg}-v${version}`);
const ignoreLatest = process.argv.includes('--ignore-latest');
const pkgDir = arg('--pkg-dir', null); // repo-relative package dir, for the equivalence check
let repo = arg('--repo', null);

function encPkg(p) { return p.replace(/\//g, '%2F'); } // scoped names contain one slash, but replace-all survives nesting

async function fetchText(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 30000);
  try {
    const r = await fetch(url, { headers: { ...HDRS, ...(opts.headers || {}) }, signal: ctrl.signal });
    return { status: r.status, text: await r.text() };
  } finally { clearTimeout(t); }
}
async function fetchJson(url, opts = {}) {
  const { status, text } = await fetchText(url, opts);
  if (status < 200 || status >= 300) throw new Error(`HTTP ${status} for ${url}`);
  return JSON.parse(text);
}
async function fetchBuf(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60000);
  try {
    const r = await fetch(url, { headers: HDRS, signal: ctrl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
    return Buffer.from(await r.arrayBuffer());
  } finally { clearTimeout(t); }
}
function git(args) {
  const r = spawnSync('git', args, { cwd: gitDir || process.cwd(), encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

(async () => {
  const rec = {
    pkg, version, tag,
    checked_at: new Date().toISOString(),
    registry_exists: false, latest: null, latest_matches: null,
    dist_shasum: null, tarball_sha1: null, sha1_match: null,
    integrity: null, tarball_sha512_sri: null, sha512_match: null,
    tarball_sha256: null, tarball_bytes: null,
    provenance: false, predicate_type: null,
    workflow_path: null, workflow_ref: null, run_id: null, builder: null,
    subject_sha512: null, subject_match: null, prov_git_commit: null,
    cosign_sig: false, cosign_pem: false,
    sha256sums: false, sha256_match: null,
    tag_exists: false, tag_type: null, tag_commit: null,
    release_target_commitish: null, tag_commit_match: null,
    prov_commit_match: null, tag_is_ancestor_of_built: null, pkg_dir_diff_empty: null,
    dco: null, reasons: [], verdict: 'UNKNOWN', level: null,
  };

  // 1. packument
  let pack;
  try { pack = await fetchJson(`${REG}/${encPkg(pkg)}`); }
  catch (e) { rec.reasons.push(`registry unreachable: ${e.message}`); return finish(rec, outFile); }
  const v = pack.versions && pack.versions[version];
  rec.latest = (pack['dist-tags'] || {}).latest || null;
  rec.latest_matches = rec.latest === version;
  rec.latest_actual = rec.latest;
  // Historical versions are not supposed to be `latest`; with --ignore-latest the
  // comparison is recorded as null (not applicable) instead of a red gate.
  if (ignoreLatest && !rec.latest_matches) rec.latest_matches = null;
  if (!v) { rec.reasons.push(`version ${version} not in registry`); return finish(rec, outFile); }
  rec.registry_exists = true;
  rec.dist_shasum = (v.dist && v.dist.shasum) || null;
  rec.integrity = (v.dist && v.dist.integrity) || null;

  // 2. tarball + hashes
  try {
    const buf = await fetchBuf(v.dist.tarball);
    rec.tarball_bytes = buf.length;
    rec.tarball_sha1 = crypto.createHash('sha1').update(buf).digest('hex');
    rec.tarball_sha512_sri = 'sha512-' + crypto.createHash('sha512').update(buf).digest('base64');
    rec.tarball_sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    rec.sha1_match = rec.tarball_sha1 === rec.dist_shasum;
    rec.sha512_match = rec.tarball_sha512_sri === rec.integrity;
  } catch (e) { rec.reasons.push(`tarball download failed: ${e.message}`); }

  // 3. provenance (SLSA v1)
  try {
    const att = await fetchJson(`${REG}/-/npm/v1/attestations/${encPkg(pkg)}@${version}`);
    const slsa = (att.attestations || []).find(a => a.predicateType === 'https://slsa.dev/provenance/v1');
    if (slsa && slsa.bundle && slsa.bundle.dsseEnvelope && slsa.bundle.dsseEnvelope.payload) {
      rec.provenance = true;
      rec.predicate_type = slsa.predicateType;
      const payload = JSON.parse(Buffer.from(slsa.bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
      const bd = (payload.predicate && payload.predicate.buildDefinition) || {};
      const ext = bd.externalParameters || {};
      const wf = ext.workflow || {};
      rec.workflow_path = wf.path || wf.workflowPath || null;
      rec.workflow_ref = wf.ref || null;
      const run = (payload.predicate.runDetails || {});
      rec.run_id = (run.metadata && run.metadata.invocationId) || null;
      rec.builder = (run.builder && run.builder.id) || null;
      const subj = (payload.subject || [])[0];
      rec.subject_sha512 = (subj && subj.digest && subj.digest.sha512) || null;
      if (rec.subject_sha512 && rec.integrity) {
        const integHex = Buffer.from(rec.integrity.replace(/^sha512-/, ''), 'base64').toString('hex');
        rec.subject_match = integHex === rec.subject_sha512;
      }
      const dep = (bd.resolvedDependencies || [])[0] || {};
      rec.prov_git_commit = (dep.digest && dep.digest.gitCommit) || null;
    }
  } catch (e) { rec.reasons.push(`attestations unavailable: ${e.message}`); }

  // 4. GitHub Release assets
  if (!repo && pack.repository && pack.repository.url) {
    const m = /github\.com[/:]([^/]+)\/([^/#?]+)/.exec(pack.repository.url);
    if (m) repo = `${m[1]}/${m[2].replace(/\.git$/, '')}`;
  }
  let release = null;
  if (repo) {
    const gh = { accept: 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) gh.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    try { release = await fetchJson(`https://api.github.com/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, { headers: gh }); }
    catch (e) { rec.reasons.push(`release ${tag} not found via API: ${e.message}`); }
  } else { rec.reasons.push('repo not given and not derivable; Release checks skipped'); }

  if (release) {
    const assets = (release.assets || []).map(a => a.name);
    rec.release_assets = assets;
    rec.cosign_sig = assets.some(n => n.endsWith('.sig'));
    rec.cosign_pem = assets.some(n => n.endsWith('.pem'));
    rec.sha256sums = assets.includes('SHA256SUMS');
    rec.release_target_commitish = release.target_commitish || null;
    if (rec.sha256sums) {
      const a = release.assets.find(x => x.name === 'SHA256SUMS');
      try {
        // browser_download_url 302s to objects.githubusercontent.com, which this
        // host cannot always reach. The API asset endpoint streams the same bytes
        // and honours the token, so prefer it and keep the redirect URL as fallback.
        let body;
        if (a.id) {
          const gh2 = { accept: 'application/octet-stream' };
          if (process.env.GITHUB_TOKEN) gh2.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
          const r = await fetchText(`https://api.github.com/repos/${repo}/releases/assets/${a.id}`, { headers: gh2 });
          if (r.status >= 200 && r.status < 300) body = r.text;
        }
        if (!body) body = (await fetchText(a.browser_download_url)).text;
        const first = body.split(/\r?\n/).find(l => l.trim());
        const sum = first ? first.trim().split(/\s+/)[0] : null;
        rec.sha256_match = (sum && rec.tarball_sha256) ? sum === rec.tarball_sha256 : null;
      } catch (e) { rec.reasons.push(`SHA256SUMS download failed: ${e.message}`); }
    }
  }

  // 5. local git
  if (gitDir) {
    const type = git(['cat-file', '-t', `refs/tags/${tag}`]);
    if (type) {
      rec.tag_exists = true;
      rec.tag_type = type === 'tag' ? 'annotated' : 'lightweight';
      rec.tag_commit = git(['rev-parse', `${tag}^{commit}`]);
      if (rec.tag_commit) {
        const body = git(['log', '-1', '--format=%B', rec.tag_commit]);
        rec.dco = body ? /^Signed-off-by:\s+.+<.+>$/m.test(body) : null;
      }
    } else { rec.reasons.push(`tag ${tag} not present in ${gitDir}`); }
  } else { rec.reasons.push('--git-dir not given; git tag checks skipped'); }

  if (rec.tag_commit && rec.release_target_commitish) {
    rec.tag_commit_match = /^[0-9a-f]{40}$/.test(rec.release_target_commitish)
      ? rec.tag_commit === rec.release_target_commitish
      : null; // branch name, not comparable
  }
  if (rec.tag_commit && rec.prov_git_commit) {
    rec.prov_commit_match = rec.tag_commit === rec.prov_git_commit;
    // Evidence only, never a way to turn the gate green: when the artifact was
    // built from a branch after the tag, record whether the tag is an ancestor
    // and whether the package directory actually changed. A reader can then see
    // "process mismatch, content identical" instead of guessing.
    const anc = spawnSync('git', ['merge-base', '--is-ancestor', rec.tag_commit, rec.prov_git_commit], { cwd: gitDir });
    rec.tag_is_ancestor_of_built = anc.status === 0;
    if (rec.tag_is_ancestor_of_built && pkgDir) {
      const d = spawnSync('git', ['diff', '--stat', rec.tag_commit, rec.prov_git_commit, '--', pkgDir], { cwd: gitDir, encoding: 'utf8' });
      rec.pkg_dir_diff_empty = d.status === 0 && (d.stdout || '').trim() === '';
    }
  }

  finish(rec, outFile);
})().catch(e => { console.error('ERR', e.stack || e.message); process.exit(1); });

function finish(rec, outFile) {
  // Grading lives in lib/classify.cjs so it can be exercised offline; this file
  // only fills the record (network + git) and prints the result.
  const graded = classify(rec, { ignoreLatest });
  rec.reasons.push(...graded.reasons);
  rec.verdict = graded.verdict;
  rec.level = graded.level;

  const line = JSON.stringify(rec);
  if (outFile) {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, line + '\n', 'utf8');
  }
  console.log(line);
  process.exit(rec.verdict === 'FAIL' ? 1 : 0);
}
