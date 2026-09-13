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
//       --commit-title "docs(homepage): ... (#65)" \
//       --commit-message "Closes the gap ..."
//
// Method defaults to 'squash'. sha defaults to the PR's current head SHA
// (auto-discovered if --sha omitted; that costs one extra API call).
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
    else if (a === '--commit-message')  out.commitMessage = argv[++i];
    else throw new Error('unknown arg: ' + a);
  }
  for (const k of ['repo', 'pr']) {
    if (!out[k]) throw new Error('missing required arg: --' + k);
  }
  return out;
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
  }

  const payload = {
    merge_method: args.method,
    sha: args.sha,
  };
  if (args.commitTitle)   payload.commit_title = args.commitTitle;
  if (args.commitMessage) payload.commit_message = args.commitMessage;

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
