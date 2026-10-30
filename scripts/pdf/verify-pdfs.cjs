#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// verify-pdfs.cjs
// Text-level assertions over the printed PDFs.
// See README.md in this directory for inputs and usage.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const argOf = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const pdfDir = path.resolve(argOf('dir', path.join(__dirname, 'out')));
const PD = process.env.PDFTOTEXT_BIN || 'pdftotext';

const docs = {
  sample: path.join(pdfDir, 'verifact-sample-report.pdf'),
  intro: path.join(pdfDir, 'fibemate-intro.pdf'),
};
for (const [tag, pdf] of Object.entries(docs)) {
  if (!fs.existsSync(pdf)) {
    console.error('missing PDF: ' + pdf + ' (pass --dir <dir>, or set PDFTOTEXT_BIN)');
    process.exit(2);
  }
}
const checks = {
  sample: [
    ['@fibemate/verifact', /@fibemate\/verifact/, true],
    ['fibermate', /fibermate/i, false],
    ['xmssmt-sha2', /xmssmt-sha2/, true],
    ['xmssmt- sha2', /xmssmt-\s+sha2/, false],
    ['liboqs 是 Open Quantum Safe', /liboqs 是 Open Quantum Safe/, true],
    ['liboqs是', /liboqs是/, false],
    ['快照时间 2026-10-30 12:31', /快照时间：2026-10-30 12:31/, true],
    ['全仓配置说明', /全仓配置/, true],
    ['“已验证”', /“已验证”/, true],
    ['“未绑定”', /“未绑定”/, true],
    ['口径说明脚注', /口径说明/, true],
    ['豁免口径：19 条中 6 条 drift', /19\s*条豁免中[^。]{0,20}6\s*条/, true],
    ['豁免口径：其余 13 条保留', /其余\s*13\s*条/, true],
    ['豁免口径：不是 19 条全有问题', /不是[^。]{0,4}19\s*条全\s*有问题/, true],
    ['ASCII 引号围绕中文', /"[^"\n]{0,20}[\u4e00-\u9fff][^"\n]{0,20}"/, false],
  ],
  intro: [
    ['2026-10 快照', /2026-10\s*快照/, true],
    ['2026- 10快照', /2026-\s+10\s*快照/, false],
    ['SM2 verify 50ms', /SM2 verify 50ms/, true],
    ['SM2verify', /SM2verify/, false],
    ['X25519 keygen 5.97ms', /X25519 keygen 5\.97ms/, true],
    ['1. 后量子', /1\.\s后量子/, true],
    ['1.后量子（无空格）', /1\.[\u4e00-\u9fff]/, false],
    ['全仓扫描快照标签', /全仓扫描快照/, true],
    ['口径脚注', /口径说明/, true],
    ['侧信道措辞：硬件级物理评估', /未做全量硬件级物理侧信道评估/, true],
    ['侧信道措辞：软件级 TVLA 自评', /软件级\s*TVLA\s*自评/, true],
    ['旧措辞已消失', /未做侧信道加固/, false],
    ['附件：样例报告链接', /verifact-sample-report-20261030\.pdf/, true],
    ['附件：本文链接', /fibemate-intro-20261030\.pdf/, true],
    ['附件：工具仓库链接', /github\.com\/Lennonhaha\/fibemate-tools/, true],
    ['绑定数 137', /\b137\b/, true],
    ['分母 2,137', /\b2,137\b/, true],
    ['断言 2,347', /\b2,347\b/, true],
    ['ASCII 引号围绕中文', /"[^"\n]{0,20}[\u4e00-\u9fff][^"\n]{0,20}"/, false],
  ],
};

let bad = 0;
for (const [tag, pdf] of Object.entries(docs)) {
  const text = execFileSync(PD, ['-q', '-enc', 'UTF-8', pdf, '-'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  fs.writeFileSync(path.join(pdfDir, tag + '.txt'), text, 'utf8');
  console.log('===== ' + tag + ' (' + text.length + ' chars, ASCII quotes=' + (text.match(/"/g) || []).length + ')');
  for (const [name, re, want] of checks[tag]) {
    const hit = re.test(text);
    if (hit !== want) { bad++; console.log(`  FAIL ${name}: want=${want} got=${hit}`); }
    else console.log(`  ok   ${name}`);
  }
}
console.log('\nfailures:', bad);
process.exitCode = bad ? 1 : 0;
