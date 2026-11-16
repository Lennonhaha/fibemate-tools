#!/usr/bin/env node
'use strict';
// Usage: node summarize.cjs --dir results [--out audit.md]
const fs = require('fs');
const path = require('path');
function arg(n, d) { const i = process.argv.indexOf(n); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : d; }
const dir = arg('--dir', 'results');
const out = arg('--out', 'audit.md');

const recs = fs.readdirSync(dir).filter(f => f.endsWith('.json'))
  .map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')))
  .sort((a, b) => (a.pkg + '@' + a.version).localeCompare(b.pkg + '@' + b.version));

const c = v => v === true ? '✅' : v === false ? '❌' : (v == null ? '—' : String(v));
let md = `# Release audit — ${new Date().toISOString().slice(0, 10)}\n\n`;
md += '| 包 | 版本 | 结论 | 级别 | registry | latest | sha1 | sha512 | prov | workflow | ref | subject | gitCommit | sig | sums | sha256 | tag | type | commit | dco |\n';
md += '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n';
for (const r of recs) {
  const refOk = r.provenance ? r.workflow_ref === `refs/tags/${r.tag}` : null;
  md += `| ${r.pkg} | ${r.version} | ${r.verdict} | ${r.level || '—'} | ${c(r.registry_exists)} | ${c(r.latest_matches)} | ${c(r.sha1_match)} | ${c(r.sha512_match)} | ${c(r.provenance)} | ${c(!!r.workflow_path)} | ${c(refOk)} | ${c(r.subject_match)} | ${c(r.prov_commit_match)} | ${c(r.cosign_sig)} | ${c(r.sha256sums)} | ${c(r.sha256_match)} | ${c(r.tag_exists)} | ${r.tag_type || '—'} | ${r.tag_commit ? r.tag_commit.slice(0, 7) : '—'} | ${c(r.dco)} |\n`;
}

const counts = {};
for (const r of recs) {
  counts[r.verdict] = (counts[r.verdict] || 0) + 1;
  counts['L' + r.level] = (counts['L' + r.level] || 0) + 1;
}
md += `\n## 汇总\n\n- 总数: ${recs.length}\n`;
for (const k of ['PASS', 'FAIL', 'UNKNOWN']) md += `- ${k}: ${counts[k] || 0}\n`;
for (const k of ['A', 'B', 'C', 'D']) md += `- 级别 ${k}: ${counts['L' + k] || 0}\n`;

const fails = recs.filter(r => r.verdict === 'FAIL');
if (fails.length) {
  md += '\n## FAIL 清单\n\n';
  for (const r of fails) {
    const flow = (r.tag_is_ancestor_of_built && r.pkg_dir_diff_empty)
      ? ' — 证据完整、流程不符（包目录与 tag 逐字节相同，但 provenance 记的是分支）'
      : '';
    md += `- **${r.pkg}@${r.version}** (${r.level}): ${r.reasons.filter(x => x.startsWith('FAIL')).join('; ')}${flow}\n`;
  }
}

const warns = recs.filter(r => r.reasons.some(x => x.startsWith('WARN')));
if (warns.length) {
  md += '\n## WARN 清单\n\n';
  for (const r of warns) {
    md += `- **${r.pkg}@${r.version}**: ${r.reasons.filter(x => x.startsWith('WARN')).join('; ')}\n`;
  }
}

const unknowns = recs.filter(r => r.verdict === 'UNKNOWN');
if (unknowns.length) {
  md += '\n## UNKNOWN 清单（≠ PASS，进待办）\n\n';
  for (const r of unknowns) {
    md += `- **${r.pkg}@${r.version}**: ${r.reasons.filter(x => x.startsWith('UNKNOWN')).join('; ')}\n`;
  }
}

md += '\n## 口径\n\n';
md += '- A：provenance + cosign + SHA256SUMS + **provenance ref == tag ref**，全部对齐\n';
md += '- B：证据链完整（签名/SUMS/tarball hash 全对），但 provenance ref 不是 tag，或 tag 非 annotated，或无 DCO\n';
md += '- C：无 provenance\n';
md += '- D：tag↔commit 无法对应，或 registry 与 tag 缺一\n';
md += '- 级别描述的是“证据/流程差在哪”，与 verdict 独立；B + FAIL = 证据完整但流程不符。\n';

fs.writeFileSync(out, md, 'utf8');
console.log(md);
