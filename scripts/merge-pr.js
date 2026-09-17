#!/usr/bin/env node
// merge-pr.js — squash / merge / rebase merge a PR via GitHub REST API.
//
// Token read from $GITHUB_TOKEN (or $GH_TOKEN).
//
// Usage:
//   GITHUB_TOKEN=ghp_xxx \
//   node scripts/merge-pr.js \
//       --repo Lennonhaha/fibemate \
//       --pr 65 \
//       --sha 06226a8209efa0f4a46a3f586d7033a9f59ebf12 \
//       --method squash \
//       --commit-title "docs(homepage): ... (#65)"
//
// Method defaults to 'squash'. sha defaults to the PR's current head SHA
// (auto-discovered if --sha omitted; that costs one extra API call).
//
// === DCO / SIGN-OFF DISCIPLINE (hard rule) ===
// For squash merges (this repo's policy), NEVER pass --commit-message.
// When merge_method=squash, GitHub concatenates EVERY source commit's
// message into the resulting commit body and PRESERVES their Signed-off-by
// / Co-Authored-By trailers. Passing --commit-message REPLACES that entire
// body and WIPES the source sign-off trailers -> DCO check fails and the
// trailer can never be retro-fitted onto an already-squashed main commit
// (Repository Rule forbids force-push to main -> it is irreversible).
// Only --commit-title is safe: GitHub uses it for the subject line and still
// keeps the auto-concatenated body (with trailers) for squash.
// To ADD a Co-Authored-By without wiping source messages, use --co-author.
//
// Why this exists: gh pr merge on Windows shells out to `git merge`
// which fails when the bundled git shim can't find the merge subcommand
// (same root cause as create-pr.js).

'use strict';

const https = require('https');

function parseArgs(argv) {
  const out = { method: 'squash' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--repo')        out.repo = argv[++i];
    else if (a === '--pr')     out.pr = parseInt(argv[++i], 10);
    else if (a === '--sha')    out.sha = argv[++i];
    else if (a === '--method') out.method = argv[++i];
    else if (a === '--commit-title')    out.commitTitle = argv[++i];
    else if (a === '--commit-message')  { out.commitMessage = argv[++i]; out.commitMessageExplicit = true; }
    else if (a === '--co-author')        out.coAuthor = argv[++i];
    else throw new Error('unknown arg: ' + a);
  }
  for (const k of ['repo', 'pr']) {
    if (!out[k]) throw new Error('missing required arg: --' + k);
  }
  // === DCO guard ===
  // Squash + --commit-message would wipe source Signed-off-by trailers.
  // Repository Rule forbids force-push to main, so a lost trailer on main
  // is irreversible. Refuse outright.
  if (out.commitMessageExplicit && out.method === 'squash') {
    console.error('REFUSED: --commit-message is forbidden with squash merge.');
    console.error('It replaces the auto-concatenated body and WIPES source');
    console.error('Signed-off-by trailers. Use --commit-title only (keeps the');
    console.error('body + trailers), or --co-author to append a Co-Authored-By.');
    process.exit(4);
  }
}

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
if (!TOKEN) {
  console.error('GITHUB_TOKEN (or GH_TOKEN) env var is required');
  process.exit(2);
}

let args;
try { args = parseArgs(process.argv.slice(2)); }
catch (e) { console.error('ARGS ERR: ' + e.message); process.exit(2); }

const [owner, repo] = args.repo.split('/');

function api(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const reqOpts = {
      hostname: 'api.github.com',
      method,
      path,
      headers: {
        'Authorization': 'Bearer ' + TOKEN,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'fibemate-tools-merge-pr',
      },
    };
    if (data) {
      reqOpts.headers['Content-Type'] = 'application/json';
      reqOpts.headers['Content-Length'] = Buffer.byteLength(data);
    }
    const req = https.request(reqOpts, (res) => {
      let chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = JSON.parse(txt); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, body: parsed, raw: txt });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  // If --sha not provided, fetch the PR's current head SHA.
  if (!args.sha) {
    const r = await api('GET', `/repos/${owner}/${repo}/pulls/${args.pr}`);
    if (r.status !== 200) { console.error('PR FETCH ERR: ' + r.status + ' ' + r.raw); process.exit(1); }
    args.sha = r.body.head.sha;
    console.log('auto-discovered head SHA: ' + args.sha);

    // P1④: refuse to merge if PR is not mergeable or CI has failing/pending checks
    if (r.body.mergeable === false) {
      console.error('REFUSED: PR is not mergeable (mergeable=false).');
      console.error('Resolve conflicts before merging.');
      process.exit(5);
    }
    if (r.body.mergeable === null) {
      console.error('REFUSED: GitHub is still computing mergeable status (null).');
      console.error('Wait a few seconds and retry.');
      process.exit(5);
    }
  }

  // P1④: check CI status before merging
  const cr = await api('GET', `/repos/${owner}/${repo}/pulls/${args.pr}`);
  if (cr.status === 200 && cr.body.mergeable === false) {
    console.error('REFUSED: PR became unmergeable.');
    process.exit(5);
  }
  const sr = await api('GET', `/repos/${owner}/${repo}/commits/${args.sha}/check-runs`);
  if (sr.status === 200 && sr.body && sr.body.check_runs) {
    const runs = sr.body.check_runs;
    const pending = runs.filter(r => r.status !== 'completed');
    const failed  = runs.filter(r => r.status === 'completed' && r.conclusion === 'failure');
    if (pending.length > 0) {
      console.error('REFUSED: ' + pending.length + ' check(s) still pending:');
      pending.forEach(r => console.error('  - ' + r.name));
      process.exit(5);
    }
    if (failed.length > 0) {
      console.error('REFUSED: ' + failed.length + ' check(s) failed:');
      failed.forEach(r => console.error('  - ' + r.name));
      process.exit(5);
    }
    console.log('CI: ' + runs.length + ' checks, all passed.');
  }

  const payload = {
    merge_method: args.method,
    sha: args.sha,
  };
  if (args.commitTitle)   payload.commit_title = args.commitTitle;
  // Only attach commit_message when NOT squash (squash must keep the
  // auto-concatenated source body so Signed-off-by trailers survive).
  if (args.commitMessage && args.method !== 'squash') {
    payload.commit_message = args.commitMessage;
  }
  // --co-author appends a trailer WITHOUT wiping the source body.
  if (args.coAuthor) {
    payload.commit_message = 'Co-Authored-By: ' + args.coAuthor;
  }

  const r = await api('PUT', `/repos/${owner}/${repo}/pulls/${args.pr}/merge`, payload);
  console.log('STATUS=' + r.status);
  if (r.body && r.body.sha) {
    console.log('MERGED-SHA=' + r.body.sha);
    console.log('MERGED=' + r.body.merged);
    console.log('MSG=' + r.body.message);
    process.exit(r.body.merged ? 0 : 1);
  } else {
    console.log('BODY=' + r.raw);
    process.exit(1);
  }
})().catch((e) => { console.error('REQ ERR: ' + e.message); process.exit(3); });
