'use strict';
// SPDX-License-Identifier: Apache-2.0

/**
 * 处置分类（dispositions）解析器。
 *
 * 设计来源：docs/rfc-verifact-dispositions.md（本仓，2026-10-26 合并）。
 *
 * 三条不可协商的规则：
 *  1. 非 code-artifact 的声明必须指名「这个数字由谁拥有」（artifact / owner / why），
 *     缺失即**报错**，不是静默通过 —— 豁免必须付费。
 *  2. 只有 owner 可以从所在区域继承；artifact / since / why 必须就地声明，
 *     否则一个区域头就成了几十条声明的共同借口。
 *  3. 禁止推断：本模块只读声明，绝不根据数值形状或上下文猜语义。
 *
 * 语法（HTML 注释，GitHub 渲染不可见）：
 *   <!-- verifact: disposition=narrative why="..." -->                                  文件级（前 5 行）
 *   <!-- verifact: begin disposition=progress owner=docs/CHECKLIST.md --> ... <!-- verifact: end -->
 *   | 合计 | 199/199 | <!-- verifact: disposition=progress -->                            单条级（区域里可继承 owner）
 */

const FILE_LEVEL_MAX_LINE = 5;

const DISPOSITIONS = ['code-artifact', 'measured-once', 'progress', 'narrative'];

const REQUIRED_ARGS = {
  'code-artifact': [],
  'measured-once': ['artifact'],
  progress: ['owner'],
  narrative: ['why']
};

// 只有 owner 可继承：其余参数逐条不同，继承等于把「每条都有出处」变成「整段共用一句借口」。
const INHERITABLE = new Set(['owner']);

const ANNOTATION_RE = /<!--\s*verifact:\s*([\s\S]*?)-->/;
const OWN_LINE_RE = /^\s*<!--\s*verifact:[\s\S]*?-->\s*$/;

/** 等长空白替换，保留换行，行号不变。 */
function blank(text) {
  return String(text).replace(/[^\n]/g, ' ');
}

/**
 * 遮蔽围栏代码块（``` / ~~~），保留行号。
 *
 * 理由：文档里的示例声明写在围栏里，那是**示例**，不是生效声明。
 * 本仓 claims 抽取早已这么做了（claims.js stripNoise），dispositions 之前漏了这一步：
 * `docs/rfc-verifact-dispositions.md:192` 举例 `external-snapshot`（未实现的第五类），
 * 解析器把示例当真 → 整份仓的门禁以 disposition_error 崩掉。
 * 未闭合的围栏按 CommonMark 语义一直遮到文件末尾。
 */
function blankFencedBlocks(text) {
  const lines = String(text).split('\n');
  let fence = null; // { marker: '`' | '~', len: number }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (fence) {
      lines[i] = blank(line);
      const close = new RegExp('^[ \\t]{0,3}' + fence.marker + '{' + fence.len + ',}[ \\t]*$');
      if (close.test(line)) fence = null;
      continue;
    }
    const open = /^[ \t]{0,3}(`{3,}|~{3,})[^\n]*$/.exec(line);
    if (open) {
      fence = { marker: open[1][0], len: open[1].length };
      lines[i] = blank(line);
    }
  }
  return lines.join('\n');
}

/**
 * 不可执行的散文之外：围栏代码块 + 行内代码。与 claims.js stripNoise 一致。
 * RFC 里 `- 逐行扫描时优先匹配 `<!-- verifact: ... -->`;` 这种行内示例也是示例。
 */
function maskNonProse(text) {
  return blankFencedBlocks(text).replace(/`[^`\n]*`/g, (m) => blank(m));
}

class DispositionError extends Error {
  constructor(fileRef, line, message) {
    super(fileRef + ':' + line + ': ' + message);
    this.name = 'DispositionError';
    this.file = String(fileRef);
    this.line = line;
    this.reason = 'disposition_error';
  }
}

/** 按空白切分，但保留引号内的空格（why="a b c"）。 */
function splitArgs(text) {
  const out = [];
  let cur = '';
  let quote = null;
  for (const ch of String(text)) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (/\s/.test(ch)) {
      if (cur) { out.push(cur); cur = ''; }
      continue;
    }
    cur += ch;
  }
  if (quote) throw new Error('引号未闭合');
  if (cur) out.push(cur);
  return out;
}

function parseDirective(inner, fileRef, lineNo) {
  let parts;
  try {
    parts = splitArgs(inner);
  } catch (e) {
    throw new DispositionError(fileRef, lineNo, '处置声明无法解析：' + e.message);
  }
  if (!parts.length) throw new DispositionError(fileRef, lineNo, '处置声明为空');

  let kind = 'single';
  if (parts[0] === 'begin' || parts[0] === 'end') { kind = parts.shift(); }

  if (kind === 'end') {
    if (parts.length) {
      throw new DispositionError(fileRef, lineNo, 'end 不接受参数（多余：' + parts.join(' ') + '）');
    }
    return { kind, line: lineNo };
  }

  let disposition = null;
  const args = {};
  for (const p of parts) {
    const eq = p.indexOf('=');
    if (eq < 0) {
      throw new DispositionError(fileRef, lineNo, '参数缺少 "="：' + p + '（期望 key=value）');
    }
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (!k) throw new DispositionError(fileRef, lineNo, '参数名为空：' + p);
    if (!v) throw new DispositionError(fileRef, lineNo, '参数值为空：' + k);
    if (k === 'disposition') disposition = v;
    else args[k] = v;
  }

  if (!disposition) {
    throw new DispositionError(fileRef, lineNo, '缺少 disposition=（' + DISPOSITIONS.join(' | ') + '）');
  }
  if (DISPOSITIONS.indexOf(disposition) < 0) {
    // fail closed：拼错的 narrativ 不允许退化成默认值，也不允许被猜成 narrative
    throw new DispositionError(fileRef, lineNo,
      '未知 disposition="' + disposition + '"（允许：' + DISPOSITIONS.join(' | ') + '）');
  }

  const extra = Object.keys(args);
  if (disposition === 'code-artifact' && extra.length) {
    throw new DispositionError(fileRef, lineNo, 'code-artifact 不接受参数（多余：' + extra.join(', ') + '）');
  }

  return { kind, disposition, args, line: lineNo };
}

/**
 * 必填参数校验。inherited 只提供区域里**允许继承**的那几项（当前只有 owner），
 * 其余缺失一律报错 —— 这是「豁免必须指名拥有者」的执行点。
 */
function requireArgs(directive, inherited, fileRef, lineNo) {
  const need = REQUIRED_ARGS[directive.disposition] || [];
  const args = Object.assign({}, directive.args);
  for (const key of need) {
    if (args[key]) continue;
    if (inherited && INHERITABLE.has(key) && inherited[key]) {
      args[key] = inherited[key];
      continue;
    }
    throw new DispositionError(fileRef, lineNo,
      directive.disposition + ' 必须声明 ' + key + '=（否则豁免就是无主数字）');
  }
  return Object.assign({}, directive, { args });
}

/**
 * 扫描整篇文本，建立行号 -> 处置 的映射。
 * 返回 { resolve(lineNo), regions, fileLevel, hasAny }。
 */
function buildDispositionScopes(text, fileRef) {
  const normalized = String(text).replace(/\r\n?/g, '\n');
  // 围栏 / 行内代码里的示例声明不生效（与 claims 抽取的遮蔽口径一致）
  const masked = maskNonProse(normalized);
  const lines = masked.split('\n');

  const regions = [];
  const sameLine = new Map();      // 行号 -> 声明（写在代码行尾）
  const appliesToNext = new Map(); // 行号 -> 声明（独立成行，作用于下一行）
  let fileLevel = null;
  const stack = [];

  const DEFAULT = { disposition: 'code-artifact', args: {}, source: 'default', at: null };
  const hasAny = /<!--\s*verifact:/.test(masked);

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const m = ANNOTATION_RE.exec(raw);
    if (!m) continue;

    const lineNo = i + 1;
    const own = OWN_LINE_RE.test(raw);
    const parsed = parseDirective(m[1], fileRef, lineNo);
    const top = stack.length ? stack[stack.length - 1] : null;

    if (parsed.kind === 'begin') {
      if (top && top.disposition !== parsed.disposition) {
        throw new DispositionError(fileRef, lineNo,
          '不允许嵌套不同 disposition（外层 ' + top.disposition + '，内层 ' + parsed.disposition + '）');
      }
      const d = requireArgs(parsed, null, fileRef, lineNo);
      const region = { from: lineNo, to: null, disposition: d.disposition, args: d.args, at: lineNo };
      regions.push(region);
      stack.push(region);
      continue;
    }

    if (parsed.kind === 'end') {
      if (!top) throw new DispositionError(fileRef, lineNo, 'end 没有对应的 begin');
      stack.pop().to = lineNo;
      continue;
    }

    // 单条级：允许出现在区域内，但 disposition 必须与区域一致（否则是歧义，报错而不是让某一方静默获胜）；
    // 必填参数里只有 owner 能向区域借，其余必须就地写。
    if (top && top.disposition !== parsed.disposition) {
      throw new DispositionError(fileRef, lineNo,
        '单条处置与所在区域冲突（区域 ' + top.disposition + '，本条 ' + parsed.disposition + '）');
    }
    const d = requireArgs(parsed, top ? top.args : null, fileRef, lineNo);
    const entry = { disposition: d.disposition, args: d.args, at: lineNo };

    if (own) {
      if (lineNo <= FILE_LEVEL_MAX_LINE) {
        if (fileLevel) {
          throw new DispositionError(fileRef, lineNo,
            '文件级处置重复声明（前 ' + FILE_LEVEL_MAX_LINE + ' 行只允许一条）');
        }
        fileLevel = entry;
      } else {
        appliesToNext.set(lineNo + 1, entry);
      }
    } else {
      sameLine.set(lineNo, entry);
    }
  }

  if (stack.length) {
    const open = stack[stack.length - 1];
    throw new DispositionError(fileRef, open.at,
      'begin 没有配对的 end（区域从第 ' + open.at + ' 行开始）');
  }

  function resolve(lineNo) {
    const same = sameLine.get(lineNo);
    const prev = appliesToNext.get(lineNo);
    let region = null;
    for (let r = regions.length - 1; r >= 0; r--) {
      if (lineNo > regions[r].from && lineNo < regions[r].to) { region = regions[r]; break; }
    }

    // 区域 vs 单条：单条更具体，优先（单条的 disposition 已校验与区域一致）
    if (same) return { disposition: same.disposition, args: same.args, source: 'inline', at: same.at };
    if (prev) return { disposition: prev.disposition, args: prev.args, source: 'inline', at: prev.at };
    if (region) return { disposition: region.disposition, args: region.args, source: 'region', at: region.at };
    if (fileLevel) return { disposition: fileLevel.disposition, args: fileLevel.args, source: 'file', at: fileLevel.at };
    return Object.assign({}, DEFAULT);
  }

  return { resolve, regions, fileLevel, hasAny };
}

module.exports = {
  DISPOSITIONS,
  REQUIRED_ARGS,
  INHERITABLE,
  FILE_LEVEL_MAX_LINE,
  DispositionError,
  blankFencedBlocks,
  maskNonProse,
  buildDispositionScopes,
  parseDirective,
  requireArgs,
  splitArgs
};
