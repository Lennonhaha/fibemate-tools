'use strict';
/*
 * domain-params.js — 类 9：参数/域错误检测（启发式）
 *
 * 方法：从源码中按「文件名或源码内容识别算法」锚定，标记「疑似参数错误」。
 *   - 文件名或文件内容含算法标识（如 ml-kem-768 / ml-dsa / slh-dsa）时才查表（减少误报）
 *   - 该文件内扫描 PARAM_NAMES（q/n/k/h/d）的常量赋值，与 NIST 白名单精确比对
 *   - 若常量值不在该算法的 NIST 标准白名单中，标记为 suspect（需人工核验，不判违规）
 *   （注：文件名或内容任一命中算法标识即视为「该文件为对应算法实现」；
 *    避免漏报；误报风险由文件名识别已挡掉大部分无关文件。）
 *
 * 设计约束（据本次起草评审）：
 *   - 找参数：正则 + 关键字（不引入 AST 解析），先简单、能跑
 *   - 查表：精确匹配，不搞 ±误差
 *   - 疑似判定：标准算法（文件名或内容命中） + 常量不在白名单 = suspicious（双条件）
 *   - 接口与 api-misuse 完全同形：{ file, suspects:[{file,line,param,value,note}], verdict }
 *
 * 白名单针对 FIBEMATE 技术栈中的 NIST 后量子算法；新项目使用前须按自家依赖核实。
 * 审计者可见：白名单是此日期的快照，库/标准更新后需同步此标记。
 */

// @whitelist-version 2026-09-13
// NIST 标准参数快照（FIBEMATE 实际依赖的真实参数，逐条可核实）。
// 数据来源：FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)。
const NIST_PARAMS = {
  'ml-kem-768':   { q: 3329,    n: 256, k: 3 },
  'ml-kem-1024':  { q: 3329,    n: 256, k: 4 },
  'ml-dsa-65':    { q: 8380417, n: 256, k: 6 },
  'slh-dsa-sha2-128f': { n: 16, h: 66, d: 22 },
  'slh-dsa-sha2-128s': { n: 16, h: 63, d: 7 },
  // TODO: SM 系列（SM2/SM3/SM4）参数白名单待补——需先与国密标准核实
};

// 文件名 → 算法 key 的识别（保守小写匹配）
const ALGO_HINTS = [
  { key: 'ml-kem-768',        re: /ml[-_]?kem[-_]?768/i },
  { key: 'ml-kem-1024',       re: /ml[-_]?kem[-_]?1024/i },
  { key: 'ml-dsa-65',         re: /ml[-_]?dsa[-_]?65/i },
  { key: 'slh-dsa-sha2-128f', re: /slh[-_]?dsa[-_]?sha2[-_]?128f/i },
  { key: 'slh-dsa-sha2-128s', re: /slh[-_]?dsa[-_]?sha2[-_]?128s/i },
];

// 参数名白名单（只在出现这些赋值名时才纳入查表，避免把任意数字当参数）
const PARAM_NAMES = ['q', 'n', 'k', 'h', 'd'];

function inferAlgorithm(filename, source) {
  const hay = filename + '\n' + (source || '');
  for (const h of ALGO_HINTS) {
    if (h.re.test(hay)) return h.key;
  }
  return null;
}

// 在密码学上下文里扫描形如 `name = <int>` / `name: <int>` 的常量赋值
function extractParamConstants(source) {
  const hits = [];
  const lines = source.split('\n');
  // 上下文判定：文件名或内容已识别为标准算法（见 analyzeDomainParams）的前提下，
  // 全文件扫描 PARAM_NAMES 的赋值（不再要求行内密码学关键词，避免过度漏报；
  // 误报风险已由「算法标识识别」这一条件挡掉大部分非密码学文件）。
  const paramRe = new RegExp('\\b(' + PARAM_NAMES.join('|') + ')\\s*[:=]\\s*([0-9]+)', 'g');
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    let m;
    while ((m = paramRe.exec(line))) {
      hits.push({ name: m[1], value: parseInt(m[2], 10), line: li + 1, snippet: line.trim() });
    }
  }
  return hits;
}

function isKnownConstantFor(algo, name, value) {
  const params = NIST_PARAMS[algo];
  if (!params) return true; // 未知算法不报（保守）
  if (!(name in params)) return true; // 该算法无此参数名不报（避免误伤无关常量）
  return params[name] === value;
}

function analyzeDomainParams(source, filename) {
  const algo = inferAlgorithm(filename, source);
  const suspects = [];
  if (!algo) {
    // 文件名未识别为标准算法：不查表（双条件之一不满足）
    return { file: filename, suspects, verdict: 'ok' };
  }
  const constants = extractParamConstants(source);
  for (const c of constants) {
    if (!isKnownConstantFor(algo, c.name, c.value)) {
      suspects.push({
        file: filename,
        line: c.line,
        param: c.name,
        value: c.value,
        note: `疑似参数错误: ${c.name}=${c.value} 不在 ${algo} 的 NIST 白名单中`,
      });
    }
  }
  return {
    file: filename,
    suspects,
    verdict: suspects.length ? 'needs-human-review' : 'ok',
  };
}

module.exports = { analyzeDomainParams, NIST_PARAMS, inferAlgorithm, extractParamConstants };
