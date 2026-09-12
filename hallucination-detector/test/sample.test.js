'use strict';
/*
 * sample.test.js — 用自带样本验证检测器能命中真实幻觉模式、且不误报良好代码
 * 运行: node test/sample.test.js
 * 退出码 0 = 通过（命中了预期 + 未误报）
 */
const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../src/index');

const dir = __dirname;
const badPath = path.join(dir, 'sample.bad.js');
const goodPath = path.join(dir, 'sample.good.js');

function run() {
  const bad = analyzeFile(fs.readFileSync(badPath, 'utf-8'), badPath);
  const good = analyzeFile(fs.readFileSync(goodPath, 'utf-8'), goodPath);

  const badCt = bad.constantTime.findings.map((f) => f.pattern);
  const badApi = bad.apiMisuse.suspects.map((s) => s.api);

  const checks = [];
  // 期望命中：秘密相关分支 / 数组下标秘密 / 声明安全却分支 / 伪 API noble.kem
  checks.push(['secret-dependent-branch', badCt.includes('secret-dependent-branch')]);
  checks.push(['array-index-by-secret', badCt.includes('array-index-by-secret')]);
  checks.push(['declared-secure-but-branches-secret', badCt.includes('declared-secure-but-branches-secret')]);
  checks.push(['api noble.kem suspect', badApi.some((a) => /noble\.kem/i.test(a))]);

  // 期望良好代码不误报
  checks.push(['good: no constant-time findings', good.constantTime.findings.length === 0]);
  checks.push(['good: no api suspects', good.apiMisuse.suspects.length === 0]);

  let pass = true;
  for (const [name, ok] of checks) {
    console.log((ok ? 'PASS ' : 'FAIL ') + name);
    if (!ok) pass = false;
  }
  console.log('\n[result] ' + (pass ? 'ALL PASS' : 'SOME FAILED'));
  process.exit(pass ? 0 : 1);
}

run();
