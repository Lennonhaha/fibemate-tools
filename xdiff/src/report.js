// SPDX-License-Identifier: Apache-2.0
'use strict';

const U = require('./util');

function renderJson(report) {
  return JSON.stringify(report, null, 2);
}

function sevMark(s) {
  if (s === 'error') return '✗';
  if (s === 'warn') return '!';
  return '·';
}

function renderText(report, opts) {
  const o = opts || {};
  const L = [];
  L.push('xdiff — 跨实现差分哨兵');
  L.push('算法 ' + report.algorithm + ' · 主种子 ' + report.masterSeed);
  L.push('');
  L.push('实现');
  for (const im of report.implementations) {
    const tag = im.status === 'ready' ? '可用' : (im.status === 'disabled' ? '已禁用' : '不可用');
    L.push('  ' + pad(im.id, 8) + pad(tag, 8) + (im.label || ''));
    if (im.status !== 'ready' && im.reason) L.push('  ' + pad('', 8) + '原因: ' + im.reason);
  }
  L.push('');
  L.push('用例');
  for (const c of report.cases) {
    const bits = Object.keys(c).filter((k) => k !== 'caseId' && k !== 'title' && k !== 'timings' && k !== 'profiles')
      .map((k) => k + '=' + JSON.stringify(c[k]));
    L.push('  ' + pad(c.caseId, 20) + (bits.length ? bits.join(' ') : ''));
  }
  L.push('');
  L.push('判定  error=' + report.counts.error + '  warn=' + report.counts.warn + '  info=' + report.counts.info + '  检查项=' + report.counts.checks);
  L.push('门禁  ' + report.gate.toUpperCase() + '   耗时 ' + report.durationMs + 'ms');
  L.push('');
  const errs = report.findings.filter((f) => f.severity === 'error');
  const warns = report.findings.filter((f) => f.severity === 'warn');
  const infos = report.findings.filter((f) => f.severity === 'info');
  const show = (title, arr, limit) => {
    if (!arr.length) return;
    L.push(title + ' (' + arr.length + ')');
    for (const f of arr.slice(0, limit || o.top || 20)) {
      L.push('  ' + sevMark(f.severity) + ' [' + f.caseId + '] ' + f.title);
      L.push('      实现: ' + f.impls.join(', '));
      if (f.detail) L.push('      详情: ' + JSON.stringify(f.detail).slice(0, 400));
    }
    if (arr.length > (limit || o.top || 20)) L.push('  … 另有 ' + (arr.length - (limit || o.top || 20)) + ' 条');
    L.push('');
  };
  show('差异', errs);
  show('可疑', warns);
  show('观察', infos);
  return L.join('\n');
}

function pad(s, n) {
  const str = String(s == null ? '' : s);
  const w = 0;
  let out = str;
  // 中文按两个字符宽估算
  let width = 0;
  for (const ch of out) width += /[\u4e00-\u9fa5]/.test(ch) ? 2 : 1;
  void w;
  while (width < n) { out += ' '; width++; }
  return out;
}

function renderMarkdown(report, opts) {
  const o = opts || {};
  const L = [];
  L.push('# xdiff 差分报告');
  L.push('');
  L.push('- 算法：' + report.algorithm);
  L.push('- 生成时间：' + report.generatedAt);
  L.push('- 主种子：`' + report.masterSeed + '`');
  L.push('- 耗时：' + report.durationMs + 'ms');
  L.push('- 门禁：**' + report.gate.toUpperCase() + '**');
  L.push('');
  L.push('## 实现');
  L.push('');
  L.push('| id | 状态 | 说明 | keygen 随机消耗 |');
  L.push('|---|---|---|---|');
  for (const im of report.implementations) {
    const tag = im.status === 'ready' ? '可用' : (im.status === 'disabled' ? '已禁用' : '不可用');
    L.push('| `' + im.id + '` | ' + tag + ' | ' + (im.label || '') + (im.reason ? '（' + im.reason + '）' : '') + ' | ' + JSON.stringify(im.rngProfileKeygen || null) + ' |');
  }
  L.push('');
  L.push('## 用例');
  L.push('');
  L.push('| 用例 | 结果 |');
  L.push('|---|---|');
  for (const c of report.cases) {
    const bits = Object.keys(c).filter((k) => !['caseId', 'title', 'timings', 'profiles'].includes(k))
      .map((k) => k + '=' + JSON.stringify(c[k])).join(' ');
    L.push('| ' + c.caseId + ' | ' + (bits || '—') + ' |');
  }
  L.push('');
  const errs = report.findings.filter((f) => f.severity === 'error');
  const warns = report.findings.filter((f) => f.severity === 'warn');
  const infos = report.findings.filter((f) => f.severity === 'info');
  const section = (title, arr) => {
    L.push('## ' + title + '（' + arr.length + '）');
    L.push('');
    if (!arr.length) { L.push('无。'); L.push(''); return; }
    for (const f of arr.slice(0, o.top || 30)) {
      L.push('### [' + f.caseId + '] ' + f.title);
      L.push('');
      L.push('- 实现：' + f.impls.map((i) => '`' + i + '`').join('、'));
      if (f.detail) L.push('- 详情：```' + JSON.stringify(f.detail).slice(0, 900) + '```');
      L.push('');
    }
  };
  section('差异（error）', errs);
  section('可疑（warn）', warns);
  section('观察（info）', infos);

  if (report.observations && report.observations.ssSemantics) {
    L.push('## 共享密钥语义归类');
    L.push('');
    L.push('| 实现 | 返回 |');
    L.push('|---|---|');
    for (const [id, v] of Object.entries(report.observations.ssSemantics)) {
      const desc = v === 'kbar' ? 'K̄（未做最终哈希）'
        : v === 'k' ? 'K = SHA3-256(K̄‖H(ct))'
          : v === 'conflict' ? '同一实现内部出现两种语义（需查）' : '未判定';
      L.push('| `' + id + '` | ' + desc + ' |');
    }
    L.push('');
  }
  if (report.observations && report.observations.timing) {
    L.push('## 耗时（毫秒）');
    L.push('');
    L.push('| 实现 | keygen p50 | keygen p95 | encaps p50 | encaps p95 |');
    L.push('|---|---|---|---|---|');
    for (const [id, t] of Object.entries(report.observations.timing)) {
      L.push('| `' + id + '` | ' + n(t.keygen.p50) + ' | ' + n(t.keygen.p95) + ' | ' + n(t.encaps.p50) + ' | ' + n(t.encaps.p95) + ' |');
    }
    L.push('');
  }
  return L.join('\n');
}

function n(v) { return v == null ? '—' : String(v); }

module.exports = { renderJson, renderText, renderMarkdown };
void U;
