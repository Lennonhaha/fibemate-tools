#!/usr/bin/env node
'use strict';
/*
 * scan-repo.js — 对整个仓库跑幻觉检测器（只读，不修改任何文件）
 *
 * 设计原则（源自 fibemate-tools 去硬编码纪律）：
 * - 路径参数化：优先环境变量 CHD_REPO，其次命令行 --repo，最后默认 '.'
 * - 不写回、不 push：纯只读静态分析
 * - 文件过滤：仅扫 .js/.ts 且路径含密码学相关关键词，减少噪声
 * - 输出：人类可读摘要 + 可机读 JSON（--json）
 *
 * 用法：
 *   node scan-repo.js
 *   node scan-repo.js --repo <path-to-repo>
 *   CHD_REPO=<path-to-repo> node scan-repo.js --json
 */

const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('./src/index');

// 路径参数化（无硬编码默认路径）
const REPO = process.env.CHD_REPO || (function () {
  const i = process.argv.indexOf('--repo');
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : '.';
})();

const JSON_OUT = process.argv.includes('--json');
const SKIP = /node_modules|dist|build|\.next|\.git|coverage|__pycache__/;
const PATTERN = /crypto|pqc|kem|sm2|sm3|sm4|ml-?kem|ntt|ratchet|cipher|hash|dsa|sign|zk|lattice|poly|ec\.js|key|secret|nonce|mac/i;

function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir); } catch (e) { return out; }
  for (const entry of entries) {
    if (SKIP.test(entry)) continue;
    const full = path.join(dir, entry);
    let stat;
    try { stat = fs.statSync(full); } catch (e) { continue; }
    if (stat.isDirectory()) {
      walk(full, out);
    } else if (/\.(js|ts|tsx|jsx)$/.test(entry) && PATTERN.test(full)) {
      out.push(full);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(REPO)) {
    console.error('repo not found: ' + REPO);
    process.exit(2);
  }
  const files = walk(REPO, []);
  console.log('scan ' + REPO + ': ' + files.length + ' candidate files\n');

  let total = 0;
  const jsonReport = { repo: REPO, scanned: files.length, files: [] };

  for (const f of files) {
    let code;
    try { code = fs.readFileSync(f, 'utf8'); } catch (e) { continue; }
    const report = analyzeFile(code, f);
    const findings = [];
    for (const x of (report.constantTime.findings || [])) {
      findings.push({ type: 'constant-time', rule: x.pattern || x.rule, line: x.line, severity: x.severity });
    }
    for (const s of (report.apiMisuse.suspects || [])) {
      findings.push({ type: 'api-misuse', rule: s.rule || s.name, line: s.line, severity: s.severity || 'review' });
    }
    if (findings.length > 0) {
      console.log('=== ' + f + ' ===');
      console.log('  findings: ' + findings.length);
      for (const fi of findings) {
        console.log('  [' + fi.severity + '] ' + fi.type + ' ' + fi.rule + ' L' + fi.line);
      }
      total += findings.length;
      jsonReport.files.push({ file: f, findings });
    }
  }

  console.log('\nTOTAL: ' + total + ' findings across ' + jsonReport.files.length + ' files (needs-human-review, not a verdict)');
  if (JSON_OUT) {
    process.stdout.write('\n' + JSON.stringify(jsonReport, null, 2) + '\n');
  }
  // 退出码：有 findings 不视为失败（这是信号不是判决），始终 0，便于 CI 接
  process.exit(0);
}

main();
