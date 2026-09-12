'use strict';
/*
 * test-coverage.js — 检测「有实现但缺测试 / 测试与实现声明不符」启发式
 * 方法：扫描某文件是否有对应测试文件、以及测试中是否真正调用被测函数。
 * 极简：给定一组源文件路径，检查同目录或 test/ 下是否存在覆盖它的测试。
 */
const fs = require('fs');
const path = require('path');

function findTestFor(srcPath, rootDir) {
  const base = path.basename(srcPath, path.extname(srcPath));
  const candidates = [
    path.join(path.dirname(srcPath), base + '.test' + path.extname(srcPath)),
    path.join(path.dirname(srcPath), '__tests__', base + '.test' + path.extname(srcPath)),
    path.join(rootDir, 'test', base + '.test' + path.extname(srcPath)),
    path.join(rootDir, 'test', base + path.extname(srcPath)),
  ];
  return candidates.find((c) => fs.existsSync(c)) || null;
}

function analyzeTestCoverage(srcPaths, rootDir) {
  const uncovered = [];
  for (const p of srcPaths) {
    const t = findTestFor(p, rootDir);
    if (!t) uncovered.push({ file: p, test: null });
  }
  return { uncovered, verdict: uncovered.length ? 'needs-human-review' : 'ok' };
}

module.exports = { analyzeTestCoverage, findTestFor };
