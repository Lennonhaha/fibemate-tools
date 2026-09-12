'use strict';
/*
 * constant-time.js — 检测「非定常实现」启发式
 * 真实来源：计时/功率侧信道通常源于：秘密相关分支、秘密做数组下标、
 * 对秘密的非定常比较。这里聚合 ast-scanner + pattern-scanner 的产出，
 * 给出「需人工核验」而非「确定违规」的标记。
 */
const { scanFile } = require('./ast-scanner');
const { scanPatterns } = require('./pattern-scanner');

function analyzeConstantTime(source, filename) {
  const scan = scanFile(source, filename);
  const suspicious = scanPatterns(scan).filter((f) =>
    f.pattern === 'secret-dependent-branch' ||
    f.pattern === 'array-index-by-secret' ||
    f.pattern === 'switch-on-secret' ||
    f.pattern === 'declared-secure-but-branches-secret');
  const score = suspicious.filter((s) => s.severity === 'high').length * 2 +
                suspicious.filter((s) => s.severity === 'medium').length;
  return {
    file: filename,
    secretVars: scan.secretVars,
    findings: suspicious,
    score,
    verdict: score === 0 ? 'no-side-channel-smell' : 'needs-human-review',
  };
}

module.exports = { analyzeConstantTime };
