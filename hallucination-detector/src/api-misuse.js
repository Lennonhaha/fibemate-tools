'use strict';
/*
 * api-misuse.js — 检测「AI 易编造的伪 API / 错误调用」启发式
 * 方法：基于白名单（真实存在、可复核的 API）核对代码中的调用点。
 * 注意：白名单是针对「FIBEMATE 技术栈」的示例集合，非通用真理；
 * 任何新项目使用前须按自家依赖核实（这正是「不拿推测当事实」纪律的代码化）。
 * 报告模式：调用名不在白名单中、且形似「知名库 API 变体」时为 suspect。
 */
const { scanFile } = require('./ast-scanner');

// @whitelist-version 2026-09-12
// 白名单针对 FIBEMATE 技术栈（noble-ciphers/noble-hashes/@noble/curves + WebCrypto + 内部封装）。
// 新项目使用前须按自家依赖核实（这正是「不拿推测当事实」纪律的代码化）。
// 审计者可见：白名单是此日期的快照，库更新后需同步此标记。

// 示例白名单（FIBEMATE 实际依赖的真实导出，逐条可核实）
const KNOWN_OK = new Set([
  // noble (noble-ciphers / noble-hashes / @noble/curves)
  'ml_kem768', 'x25519', 'ed25519', 'sha256', 'sha3_256', 'shake256', 'hmac',
  'randomBytes', 'crypto_subtle', 'getRandomValues', 'aeadEncrypt', 'aeadDecrypt',
  'keccak_256', 'cshake256', 'mod', 'pow', 'inv', 'hashToField',
  // WebCrypto
  'crypto.subtle.encrypt', 'crypto.subtle.decrypt', 'crypto.subtle.importKey',
  'crypto.subtle.deriveBits', 'crypto.subtle.sign', 'crypto.subtle.verify',
  // Node
  'createCipheriv', 'createDecipheriv', 'timingSafeEqual', 'scryptSync',
  // FIBEMATE 内部
  'doubleRatchetAdvance', 'ratchetStep', 'symmetricEncrypt', 'symmetricDecrypt',
]);

// 常见「AI 会编出来」的伪 noble/WebCrypto API（仅作可疑标记，不判违规）
const SUSPECT_PATTERNS = [
  { re: /noble\.(kem|pqc|mlkem)/i, note: 'noble 命名空间下常见编造：noble.kem/mlkem（真实为 @noble/ciphers 的 ml_kem768）' },
  { re: /crypto\.subtle\.mlkem/i, note: 'WebCrypto 尚无 ML-KEM 标准 API，疑似编造' },
  { re: /noble\.sha3/i, note: 'noble 下无 sha3 顶层导出，真实为 noble-hashes 的 sha3_256' },
  { re: /x25519\.(derive|keyFrom)/i, note: 'x25519 在 @noble/curves 的真实方法名需注意大小写/挂载' },
  // 仅当 .open( 前接密码学对象（cipher/box/ratchet/aead/seal 等）才可疑；排除 indexedDB.open 等通用 API
  { re: /\b(cipher|box|aead|ratchet|secretbox|secretBox|symmetric)\.open\(/i, note: 'seal/open 常见于某些封装库，须确认是否真实存在' },
  { re: /\.seal\(/i, note: 'seal/open 常见于某些封装库，须确认是否真实存在' },
];

function analyzeApiMisuse(source, filename) {
  const scan = scanFile(source, filename);
  const suspects = [];
  for (const call of scan.calls) {
    const full = call.name;
    if (KNOWN_OK.has(full)) continue;
    for (const sp of SUSPECT_PATTERNS) {
      if (sp.re.test(full)) {
        suspects.push({ file: filename, line: lineOf(scan, call.index), api: full, note: sp.note });
        break;
      }
    }
  }
  // 同时扫描源码整体中的可疑 API 命名空间（成员访问链等，不限于调用名）
  // 非全局正则用单次 test 即可（启发式：每文件每模式命中一次足够），避免 exec 死循环
  for (const sp of SUSPECT_PATTERNS) {
    if (sp.re.test(source)) {
      const line = source.search(sp.re) >= 0
        ? source.slice(0, source.search(sp.re)).split('\n').length
        : 0;
      suspects.push({ file: filename, line, api: source.match(sp.re)[0], note: sp.note });
    }
  }
  return { file: filename, suspects, verdict: suspects.length ? 'needs-human-review' : 'ok' };
}

function lineOf(scan, index) { return scan.source.slice(0, index).split('\n').length; }

module.exports = { analyzeApiMisuse };
