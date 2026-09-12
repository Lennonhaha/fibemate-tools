'use strict';
/*
 * index.js — 聚合四个检测器的统一入口
 * 输出结构化报告（供 CLI / 其他工具消费）。
 * 定位：启发式静态检查，标记「需人工核验」，不宣判漏洞。
 */
const ct = require('./constant-time');
const api = require('./api-misuse');
const cov = require('./test-coverage');

function analyzeFile(source, filename) {
  const ctRes = ct.analyzeConstantTime(source, filename);
  const apiRes = api.analyzeApiMisuse(source, filename);
  return {
    file: filename,
    constantTime: ctRes,
    apiMisuse: apiRes,
  };
}

function analyzeProject(sources /* [{filename, source}] */, rootDir) {
  const perFile = sources.map((s) => analyzeFile(s.source, s.filename));
  const srcPaths = sources.map((s) => s.filename);
  const covRes = cov.analyzeTestCoverage(srcPaths, rootDir);
  const allFindings = [];
  for (const f of perFile) {
    for (const x of f.constantTime.findings) allFindings.push({ type: 'constant-time', ...x });
    for (const s of f.apiMisuse.suspects) allFindings.push({ type: 'api-misuse', ...s });
  }
  for (const u of covRes.uncovered) allFindings.push({ type: 'test-coverage', file: u.file, note: 'no corresponding test file' });
  return { perFile, coverage: covRes, findings: allFindings };
}

module.exports = { analyzeFile, analyzeProject };
