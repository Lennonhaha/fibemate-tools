'use strict';
/*
 * sample.test.js — 用自带样本验证检测器能命中真实幻觉模式、且不误报良好代码
 * 运行: node test/sample.test.js
 * 退出码 0 = 通过（命中了预期 + 未误报）
 */
const fs = require('fs');
const path = require('path');
const { analyzeFile, analyzeProject } = require('../src/index');

const dir = __dirname;
const badPath = path.join(dir, 'sample.bad.js');
const goodPath = path.join(dir, 'sample.good.js');
const dpBadPath = path.join(dir, 'sample.domainparams.bad.js');
const dpGoodPath = path.join(dir, 'sample.domainparams.good.js');

function run() {
  const bad = analyzeFile(fs.readFileSync(badPath, 'utf-8'), badPath);
  const good = analyzeFile(fs.readFileSync(goodPath, 'utf-8'), goodPath);
  const dpBad = analyzeFile(fs.readFileSync(dpBadPath, 'utf-8'), dpBadPath);
  const dpGood = analyzeFile(fs.readFileSync(dpGoodPath, 'utf-8'), dpGoodPath);

  const badCt = bad.constantTime.findings.map((f) => f.pattern);
  const badApi = bad.apiMisuse.suspects.map((s) => s.api);
  const dpBadSuspects = dpBad.domainParams.suspects;

  const checks = [];
  // 期望命中：秘密相关分支 / 数组下标秘密 / 声明安全却分支 / 伪 API noble.kem
  checks.push(['secret-dependent-branch', badCt.includes('secret-dependent-branch')]);
  checks.push(['array-index-by-secret', badCt.includes('array-index-by-secret')]);
  checks.push(['declared-secure-but-branches-secret', badCt.includes('declared-secure-but-branches-secret')]);
  checks.push(['api noble.kem suspect', badApi.some((a) => /noble\.kem/i.test(a))]);

  // 期望良好代码不误报
  checks.push(['good: no constant-time findings', good.constantTime.findings.length === 0]);
  checks.push(['good: no api suspects', good.apiMisuse.suspects.length === 0]);

  // 域参数检测：错误参数命中白名单校验，正确参数不误报
  checks.push(['domainparams bad: verdict needs-human-review', dpBad.domainParams.verdict === 'needs-human-review']);
  checks.push(['domainparams bad: q=3330 flagged', dpBadSuspects.some((s) => s.param === 'q' && s.value === 3330)]);
  checks.push(['domainparams bad: k=4 flagged', dpBadSuspects.some((s) => s.param === 'k' && s.value === 4)]);
  checks.push(['domainparams good: verdict ok', dpGood.domainParams.verdict === 'ok']);

  // 测试覆盖检测（project 级）：
  //   ① 自匹配回归（A+B 修复的残留）：路径带 ./ 前缀时不得把自己当测试
  //   ② 有同名 .test 文件 → 已覆盖
  const selfmatch = analyzeProject(
    [{ filename: './test/sample.testcov.selfmatch.js', source: fs.readFileSync(path.join(dir, 'sample.testcov.selfmatch.js'), 'utf-8') }],
    '.',
  );
  const withtest = analyzeProject(
    [
      { filename: 'test/sample.testcov.withtest.js', source: fs.readFileSync(path.join(dir, 'sample.testcov.withtest.js'), 'utf-8') },
      { filename: 'test/sample.testcov.withtest.test.js', source: fs.readFileSync(path.join(dir, 'sample.testcov.withtest.test.js'), 'utf-8') },
    ],
    '.',
  );
  checks.push(['testcov: ./-prefixed src does not self-match', selfmatch.coverage.uncovered.length === 1]);
  // 实现文件已覆盖；uncovered 只含 .test.js 自身（测试的测试不存在，属预期）
  checks.push(['testcov: withtest impl covered', withtest.coverage.uncovered.length === 1 && withtest.coverage.uncovered[0].file.endsWith('sample.testcov.withtest.test.js')]);

  let pass = true;
  for (const [name, ok] of checks) {
    console.log((ok ? 'PASS ' : 'FAIL ') + name);
    if (!ok) pass = false;
  }
  console.log('\n[result] ' + (pass ? 'ALL PASS' : 'SOME FAILED'));
  process.exit(pass ? 0 : 1);
}

run();
