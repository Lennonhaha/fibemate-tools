'use strict';
/*
 * ast-scanner.js — 轻量结构扫描器（零依赖）
 * 不调用完整 JS 解析器，基于「掩码源码 + 括号配平」提取：
 *   - comments: 注释文本（含 @secret 标注、constant-time/secure/FIPS 声明）
 *   - calls:    调用点（函数名 + 参数片段）
 *   - branches: 分支条件（if/else if/while/for/三元）
 *   - functions: 函数声明（name + 参数）
 *   - secretVars: 秘密变量集合（显式 @secret + 命名启发 + 赋值传播）
 * 启发式，非完整 AST。定位为「静态启发式检测器」，不宣称等效于 esprima/acorn。
 */

// 把字符串与注释替换成等宽空格，保留索引对齐，避免括号配平被串内 ( ) 干扰
function maskSource(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === '/' && c2 === '/') {
      let j = i; while (j < n && src[j] !== '\n') j++;
      out += ' '.repeat(j - i); i = j; continue;
    }
    if (c === '/' && c2 === '*') {
      let j = i + 2; while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      j = Math.min(n, j + 2); out += ' '.repeat(j - i); i = j; continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const q = c; let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === q) { j++; break; }
        j++;
      }
      out += ' '.repeat(j - i); i = j; continue;
    }
    out += c; i++;
  }
  return out;
}

function extractComments(src) {
  const comments = [];
  const lineRe = /\/\/(.*)$/gm;
  let m;
  while ((m = lineRe.exec(src))) {
    comments.push({ type: 'line', text: m[1].trim(), line: src.slice(0, m.index).split('\n').length });
  }
  const blockRe = /\/\*([\s\S]*?)\*\//g;
  while ((m = blockRe.exec(src))) {
    comments.push({ type: 'block', text: m[1].replace(/\s+/g, ' ').trim(),
      line: src.slice(0, m.index).split('\n').length });
  }
  return comments;
}

function balancedSlice(src, openIdx) {
  if (src[openIdx] !== '(') return null;
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return src.slice(openIdx + 1, i); }
  }
  return src.slice(openIdx + 1);
}

const WORD = '[A-Za-z_$][\\w$]*';

function scanFile(source, filename) {
  const masked = maskSource(source);
  const comments = extractComments(source);

  const calls = [];
  const callRe = new RegExp('(' + WORD + ')\\s*\\(', 'g');
  let m;
  while ((m = callRe.exec(masked))) {
    const name = m[1];
    const argsRaw = balancedSlice(masked, m.index + name.length);
    calls.push({ name, args: argsRaw ? argsRaw.trim() : '', index: m.index });
  }

  const branches = [];
  const branchRe = new RegExp('\\b(if|else\\s+if|while|for|switch)\\s*\\(', 'g');
  while ((m = branchRe.exec(masked))) {
    const kind = m[1].replace(/\s+/g, ' ');
    const cond = balancedSlice(masked, m.index + m[0].length - 1);
    branches.push({ kind, condition: cond ? cond.trim() : '', index: m.index });
  }
  // 三元表达式（?: 不在括号内）
  let depth = 0;
  for (let i = 0; i < masked.length; i++) {
    const c = masked[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === '?' && depth === 0) {
      // 找匹配的 :
      let d2 = depth, j = i + 1, startLine = source.slice(0, i).split('\n').length;
      while (j < masked.length) {
        if (masked[j] === '(') d2++;
        else if (masked[j] === ')') d2--;
        else if (masked[j] === ':' && d2 === 0) {
          branches.push({ kind: 'ternary', condition: source.slice(i + 1, j).trim(), index: i, line: startLine });
          break;
        }
        j++;
      }
    }
  }

  const functions = [];
  const fnRe = new RegExp('function\\s+(' + WORD + ')\\s*\\(([^)]*)\\)', 'g');
  while ((m = fnRe.exec(masked))) {
    functions.push({ name: m[1], params: m[2].trim(), index: m.index });
  }
  const arrowRe = new RegExp('(' + WORD + ')\\s*=\\s*\\(([^)]*)\\)\\s*=>', 'g');
  while ((m = arrowRe.exec(masked))) {
    functions.push({ name: m[1], params: m[2].trim(), index: m.index });
  }

  // 赋值收集（用于秘密传播）：lhs = rhs
  const assigns = [];
  const assignRe = new RegExp('(' + WORD + ')\\s*=\\s*([^;=].*?);', 'g');
  while ((m = assignRe.exec(masked))) {
    assigns.push({ lhs: m[1], rhs: m[2].trim() });
  }

  // 秘密变量初集
  const secretVars = new Set();
  // 秘密变量命名判定：白名单 + 黑名单双向，黑名单优先（避免 rootKey/chainKey 等状态键被误判为秘密）
  // 白名单：确为密码学秘密的常见命名（使用词边界，避免 section/second/privacy 等误中）
  const SECRET_WHITE = [
    /\bsecret\b/i,
    /\bprivateKey\b/i, /\bprivKey\b/i,
    /\bsharedSecret\b/i,
    /\bsk\b/i,
    /\bhmac\b/i,
    /\bpassword\b/i, /\bpasswd\b/i,
    /\btoken\b/i,
    /\bsalt\b/i,
    /\biv\b/i,
    /\bnonce\b/i,
  ];
  // 黑名单：ratchet 等状态键，虽含 key 但不是侧信道敏感秘密（长度/存在性校验非时序敏感）
  const SECRET_BLACK = [
    /\brootKey\b/i,
    /\bchainKey\b/i,
    /\breceivingChainKey\b/i,
    /\bsendingChainKey\b/i,
    /\bmessageKey\b/i,
    /\bheaderKey\b/i,
  ];
  function isSecretName(name) {
    if (!name) return false;
    if (SECRET_BLACK.some((r) => r.test(name))) return false;
    return SECRET_WHITE.some((r) => r.test(name));
  }
  for (const c of comments) {
    const mm = c.text.match(/@secret\s+([\w\s,]+)/i);
    if (mm) {
      mm[1].split(/[\s,]+/).filter(Boolean).forEach((nm) => secretVars.add(nm));
    }
  }
  // 参数/变量名启发
  for (const f of functions) {
    f.params.split(',').map((s) => s.trim().split(/\s+/)[0]).filter(Boolean)
      .forEach((p) => { if (isSecretName(p)) secretVars.add(p); });
  }

  // 赋值传播（定点迭代，小图足够）
  let changed = true, guard = 0;
  while (changed && guard++ < 20) {
    changed = false;
    for (const a of assigns) {
      if ([...secretVars].some((s) => new RegExp('\\b' + s + '\\b').test(a.rhs))) {
        if (!secretVars.has(a.lhs)) { secretVars.add(a.lhs); changed = true; }
      }
    }
  }

  // 声明中提及的声明式秘密（如 const secretKey = ...）
  for (const a of assigns) {
    if (isSecretName(a.lhs) && !secretVars.has(a.lhs)) secretVars.add(a.lhs);
  }

  return {
    filename,
    comments,
    calls,
    branches,
    functions,
    secretVars: [...secretVars],
    masked,
    source,
  };
}

// 判断某段文本是否引用了秘密变量（词边界）
function referencesSecret(text, secretVars) {
  return secretVars.some((s) => new RegExp('\\b' + s + '\\b').test(text));
}

module.exports = { scanFile, referencesSecret, maskSource, extractComments };
