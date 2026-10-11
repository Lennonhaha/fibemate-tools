// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * CI 降级门禁：读取一次 xdiff 运行报告，确认「实现不可用」时仍给出可读说明。
 * 用法：node test/ci-check.js [report.json]（默认 ../.xdiff/ci.json）
 * 由 .github/workflows/xdiff-ci.yml 的 graceful job 调用。
 */

const fs = require('fs');
const path = require('path');

const file = process.argv[2] || path.join(__dirname, '..', '.xdiff', 'ci.json');

let report;
try {
  report = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error('无法读取报告 ' + file + '：' + e.message);
  process.exit(1);
}

const impls = Array.isArray(report.implementations) ? report.implementations : [];
const ready = impls.filter((i) => i && i.status === 'ready').length;
const findings = Array.isArray(report.findings) ? report.findings : [];

console.log('ready=' + ready + '  gate=' + report.gate);
console.log('implementations=' + impls.length + '  findings=' + findings.length);

if (findings.length === 0) {
  console.error('缺少降级说明');
  process.exit(1);
}

console.log('降级说明存在，门禁通过');
