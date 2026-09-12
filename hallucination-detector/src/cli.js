#!/usr/bin/env node
'use strict';
/*
 * cli.js — 命令行入口
 * 用法: node src/cli.js <file-or-dir> [rootDir]
 */
const fs = require('fs');
const path = require('path');
const { analyzeProject } = require('./index');

function collect(dirOrFile, acc) {
  acc = acc || [];
  const stat = fs.statSync(dirOrFile);
  if (stat.isDirectory()) {
    for (const e of fs.readdirSync(dirOrFile)) {
      const full = path.join(dirOrFile, e);
      const s = fs.statSync(full);
      if (s.isDirectory()) {
        if (e === 'node_modules' || e === 'test' || e === '.git') continue;
        collect(full, acc);
      } else if (/\.(js|ts)$/.test(e)) {
        acc.push({ filename: full, source: fs.readFileSync(full, 'utf-8') });
      }
    }
  } else {
    acc.push({ filename: dirOrFile, source: fs.readFileSync(dirOrFile, 'utf-8') });
  }
  return acc;
}

function main() {
  const target = process.argv[2];
  if (!target) { console.error('usage: node src/cli.js <file-or-dir>'); process.exit(2); }
  const rootDir = process.argv[3] || (fs.statSync(target).isDirectory() ? target : '.');
  const sources = collect(target);
  const report = analyzeProject(sources, rootDir);
  console.log(JSON.stringify(report, null, 2));
  const n = report.findings.length;
  console.log('\n[summary] files=' + sources.length + ' findings=' + n);
}

main();
