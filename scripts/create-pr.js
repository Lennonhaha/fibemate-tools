#!/usr/bin/env node
// create-pr.js — open a PR via GitHub REST API, bypassing the gh CLI's
// `git merge` lookup on Windows (gh pr create on Windows fails with
// "failed to run git: 'merge' 不是内部或外部命令" because the bundled
// shim can't find the `merge` subcommand even with PATH set).
//
// Token is read from $GITHUB_TOKEN (or $GH_TOKEN) — never hardcoded.
//
// Usage:
//   GITHUB_TOKEN=ghp_xxx \
//   node scripts/create-pr.js \
//       --repo Lennonhaha/fibemate \
//       --head docs/some-branch \
//       --base main \
//       --title "docs(homepage): ..." \
//       --body-file /path/to/body.md
//
// Optional:
//   --draft   create as draft PR
//
// Exits 0 on 201, non-zero on any other status or network error.

'use strict';

const fs = require('fs');
const https = require('https');

function parseArgs(argv) {
  const out = { draft: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--repo')        out.repo = argv[++i];
    else if (a === '--head')   out.head = argv[++i];
    else if (a === '--base')   out.base = argv[++i];
    else if (a === '--title')  out.title = argv[++i];
    else if (a === '--body-file') out.bodyFile = argv[++i];
    else if (a === '--draft')  out.draft = true;
    else throw new Error('unknown arg: ' + a);
  }
  for (const k of ['repo', 'head', 'base', 'title', 'bodyFile']) {
    if (!out[k]) throw new Error('missing required arg: --' + k.replace(/([A-Z])/g, '-$1').toLowerCase());
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

const body = fs.readFileSync(args.bodyFile, 'utf8');
const payload = JSON.stringify({
  title: args.title,
  head: args.head,
  base: args.base,
  body,
  draft: args.draft,
});

const [owner, repo] = args.repo.split('/');
const path = `/repos/${owner}/${repo}/pulls`;

const opts = {
  hostname: 'api.github.com',
  method: 'POST',
  path,
  headers: {
    'Authorization': 'Bearer ' + TOKEN,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'fibemate-tools-create-pr',
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  },
};

const req = https.request(opts, (res) => {
  let chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    const txt = Buffer.concat(chunks).toString('utf8');
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch { /* not JSON */ }
    console.log('STATUS=' + res.statusCode);
    if (parsed && parsed.html_url) {
      console.log('PR=' + parsed.number + ' URL=' + parsed.html_url + ' STATE=' + parsed.state);
      process.exit(res.statusCode === 201 ? 0 : 1);
    } else {
      console.log('BODY=' + txt);
      process.exit(1);
    }
  });
});
req.on('error', (e) => { console.error('REQ ERR: ' + e.message); process.exit(3); });
req.write(payload);
req.end();
