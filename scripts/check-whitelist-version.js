#!/usr/bin/env node
'use strict';
/*
 * check-whitelist-version.js — CI 检查：白名单版本戳是否过期
 *
 * 用法: node scripts/check-whitelist-version.js [--max-age-days=180]
 *
 * 扫描 hallucination-detector/src/ 下所有 .js 文件中的 @whitelist-version 标记，
 * 若标记日期距今超过 --max-age-days（默认 180），exit 1 提示更新。
 * 若无标记，exit 1 提示缺失。
 */

const fs = require('fs');
const path = require('path');

const maxAgeDays = parseInt(
  (process.argv.find(a => a.startsWith('--max-age-days=')) || '').split('=')[1] || '180',
  10
);

const srcDir = path.join(__dirname, '..', 'hallucination-detector', 'src');
const STAMP_RE = /@whitelist-version\s+(\d{4}-\d{2}-\d{2})/;

function walk(dir, acc) {
  acc = acc || [];
  for (const e of fs.readdirSync(dir)) {
    const full = path.join(dir, e);
    const s = fs.statSync(full);
    if (s.isDirectory()) walk(full, acc);
    else if (e.endsWith('.js')) acc.push(full);
  }
  return acc;
}

const files = walk(srcDir);
const now = Date.now();
let failures = 0;

for (const f of files) {
  const src = fs.readFileSync(f, 'utf-8');
  const m = src.match(STAMP_RE);
  if (!m) continue; // no whitelist stamp in this file, skip
  const stampDate = new Date(m[1] + 'T00:00:00Z');
  const ageMs = now - stampDate.getTime();
  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
  if (ageDays > maxAgeDays) {
    console.error(`FAIL: ${path.relative(srcDir, f)} whitelist stamp ${m[1]} is ${ageDays} days old (max ${maxAgeDays})`);
    failures++;
  } else {
    console.log(`OK: ${path.relative(srcDir, f)} whitelist stamp ${m[1]} (${ageDays} days old)`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} whitelist stamp(s) expired. Update NIST params and refresh the @whitelist-version date.`);
  process.exit(1);
}
console.log('\nAll whitelist stamps current.');
