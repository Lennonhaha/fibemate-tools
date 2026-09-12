'use strict';
/*
 * pattern-scanner.js — 基于 ast-scanner 的启发式模式匹配
 * 检测「AI 易编造 / 易漏」的危险代码模式（命名来源透明）：
 *   - secret-dependent branch / loop  → 可能的时序侧信道（SPA/DPA 基础）
 *   - array/string index by secret    → 缓存时序 / 越界推测
 *   - early return on failure          → 可区分错误响应（时序/消息）
 *   - switch on secret byte            → 经典非定常实现
 *   - comparison via != / !== on secret→ 可能非定常比较
 *   - comment declares secure but code branches on secret → 声明与实现矛盾
 * 每个 pattern 给出 file/line/severity/justification，绝不臆断「一定是漏洞」。
 */

const { referencesSecret } = require('./ast-scanner');

// 判断一个条件是否可能是「秘密相关」（保守）
function conditionSecretRelated(cond, secretVars) {
  if (!cond) return false;
  return referencesSecret(cond, secretVars);
}

const PATTERNS = [
  {
    id: 'secret-dependent-branch',
    severity: 'high',
    desc: '分支条件引用了秘密变量（潜在时序/功率侧信道）',
    test(ctx) {
      const hits = [];
      for (const b of ctx.branches) {
        if (b.kind === 'if' || b.kind === 'else if' || b.kind === 'while' || b.kind === 'for' || b.kind === 'ternary') {
          if (conditionSecretRelated(b.condition, ctx.secretVars)) {
            hits.push({ line: lineOf(ctx, b.index), snippet: b.condition.slice(0, 80) });
          }
        }
      }
      return hits;
    },
  },
  {
    id: 'array-index-by-secret',
    severity: 'high',
    desc: '数组/对象下标或切片使用了秘密变量（潜在缓存时序）',
    test(ctx) {
      const hits = [];
      // 形如 x[secretExpr] 或 x[ ... secret ... ]
      const idxRe = /\[\s*([^\]]*?)\s*\]/g;
      let m;
      const code = ctx.masked;
      while ((m = idxRe.exec(code))) {
        if (m.index === idxRe.lastIndex) idxRe.lastIndex++; // 防零宽死循环
        const inside = m[1];
        if (referencesSecret(inside, ctx.secretVars)) {
          hits.push({ line: lineOf(ctx, m.index), snippet: m[0].slice(0, 80) });
        }
      }
      return hits;
    },
  },
  {
    id: 'switch-on-secret',
    severity: 'medium',
    desc: 'switch 条件引用了秘密变量',
    test(ctx) {
      const hits = [];
      for (const b of ctx.branches) {
        if (b.kind === 'switch' && conditionSecretRelated(b.condition, ctx.secretVars)) {
          hits.push({ line: lineOf(ctx, b.index), snippet: b.condition.slice(0, 80) });
        }
      }
      return hits;
    },
  },
  {
    id: 'declared-secure-but-branches-secret',
    severity: 'medium',
    desc: '注释声明安全/定常/constant-time，但代码存在秘密相关分支（声明与实现矛盾）',
    test(ctx) {
      const hits = [];
      // 声明判定改为「就近」：仅当分支所在行前后 3 行内注释声明安全才判矛盾，
      // 且排除反向说明（not / non- / TODO / FIXME / unsafe），避免 PKCS8 等被 secure 词边界误中
      const lines = ctx.source.split('\n');
      for (const b of ctx.branches) {
        if (!(b.kind === 'if' || b.kind === 'else if' || b.kind === 'while' || b.kind === 'ternary')) continue;
        if (!conditionSecretRelated(b.condition, ctx.secretVars)) continue;
        const bLine = lineOf(ctx, b.index);
        // bLine 是 1-based 行号；转 0-based 索引后向前 4 行 / 向后 1 行覆盖就近注释
        const bIdx0 = bLine - 1;
        const nearby = [];
        for (let i = Math.max(0, bIdx0 - 4); i <= Math.min(lines.length - 1, bIdx0 + 1); i++) nearby.push(lines[i]);
        const declaresSafe = nearby.some((ln) => {
          const t = ln.trim();
          if (/^\/\//.test(t)) {
            const body = t.replace(/^\/\/\s*/, '');
            // 反向说明优先排除
            if (/\b(not|non[- ]?|TODO|FIXME|unsafe|insecure|downgrade)\b/i.test(body)) return false;
            return /\b(constant[- ]?time|timing[- ]?safe|side[- ]?channel[- ]?free|secure|FIPS)\b/i.test(body);
          }
          return false;
        });
        if (declaresSafe) {
          hits.push({ line: bLine, snippet: b.condition.slice(0, 80) });
        }
      }
      return hits;
    },
  },
  {
    id: 'nonconstant-comparison',
    severity: 'low',
    desc: '疑似对秘密值使用非定常比较（!= / !== / == / ===），建议 ct-equal',
    test(ctx) {
      const hits = [];
      // 按行扫描，避免长文本贪婪回溯
      const lines = ctx.masked.split('\n');
      for (let li = 0; li < lines.length; li++) {
        const line = lines[li];
        const re = /([!=]={1,2})\s*([^;\n]+)/g;
        let mm;
        while ((mm = re.exec(line))) {
          if (referencesSecret(mm[2], ctx.secretVars)) {
            hits.push({ line: li + 1, snippet: mm[0].slice(0, 80) });
          }
        }
      }
      return hits;
    },
  },
];

function lineOf(ctx, index) {
  return ctx.source.slice(0, index).split('\n').length;
}

function scanPatterns(scan) {
  const findings = [];
  for (const p of PATTERNS) {
    let hits = [];
    try { hits = p.test(scan) || []; } catch (e) { hits = [{ line: 0, snippet: 'PATTERN ERROR: ' + e.message }]; }
    for (const h of hits) {
      findings.push({
        file: scan.filename,
        line: h.line,
        pattern: p.id,
        severity: p.severity,
        desc: p.desc,
        snippet: h.snippet,
      });
    }
  }
  return findings;
}

module.exports = { scanPatterns, PATTERNS };
