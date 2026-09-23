#!/usr/bin/env node
'use strict';
/*
 * cli.js — 命令行入口
 * 用法: node src/cli.js <file-or-dir> [rootDir] [--fail-on <low|medium|high>]
 */
const fs = require('fs');
const path = require('path');
const { analyzeProject } = require('./index');

const EXCLUDE_DIRS = new Set(['node_modules', 'test', '.git', 'dist', 'build', 'coverage', 'out', '.next', 'vendor', '.cache', 'tmp']);
const MAX_FILE_SIZE = 1024 * 1024; // 1 MB — skip files larger than this

function collect(dirOrFile, acc) {
  acc = acc || [];
  const stat = fs.statSync(dirOrFile);
  if (stat.isDirectory()) {
    for (const e of fs.readdirSync(dirOrFile)) {
      const full = path.join(dirOrFile, e);
      const s = fs.statSync(full);
      if (s.isDirectory()) {
        if (EXCLUDE_DIRS.has(e)) continue;
        collect(full, acc);
      } else if (/\.(js|ts)$/.test(e)) {
        if (s.size > MAX_FILE_SIZE) continue; // skip oversized files
        acc.push({ filename: full, source: fs.readFileSync(full, 'utf-8') });
      }
    }
  } else {
    acc.push({ filename: dirOrFile, source: fs.readFileSync(dirOrFile, 'utf-8') });
  }
  return acc;
}

const SEVERITY_RANK = { low: 0, medium: 1, high: 2 };

// 解析参数：--fail-on <level> 与位置参数分离；位置参数顺序保持不变
function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--fail-on') {
      flags.failOn = argv[++i];
    } else if (a.startsWith('--')) {
      flags[a.slice(2)] = true;
    } else {
      positional.push(a);
    }
  }
  return { flags, positional };
}

// finding 的 severity 归一化：无 severity 字段（api-misuse / domain-params /
// test-coverage）视为 medium——它们是「需人工核验」而非「确定违规」。
function severityOf(f) {
  return f.severity || 'medium';
}

function main() {
  const { flags, positional } = parseArgs(process.argv.slice(2));
  if (flags.failOn !== undefined && !Object.prototype.hasOwnProperty.call(SEVERITY_RANK, flags.failOn)) {
    console.error('--fail-on requires one of: low | medium | high');
    process.exit(2);
  }
  const target = positional[0];
  if (!target) { console.error('usage: node src/cli.js <file-or-dir> [rootDir] [--fail-on <low|medium|high>]'); process.exit(2); }
  const rootDir = positional[1] || (fs.statSync(target).isDirectory() ? target : '.');
  const sources = collect(target);
  const report = analyzeProject(sources, rootDir);
  console.log(JSON.stringify(report, null, 2));
  const n = report.findings.length;
  console.log('\n[summary] files=' + sources.length + ' findings=' + n);
  if (flags.failOn !== undefined && n > 0) {
    const threshold = SEVERITY_RANK[flags.failOn];
    const offending = report.findings.filter((f) => SEVERITY_RANK[severityOf(f)] >= threshold);
    if (offending.length > 0) {
      console.error('[fail-on] ' + offending.length + ' finding(s) at or above severity "' + flags.failOn + '"');
      process.exit(1);
    }
  }
}

main();
