'use strict';
// SPDX-License-Identifier: Apache-2.0

/**
 * 用语 / 绝对化检测。规则来自 FIBEMATE 自有投稿纪律，默认全开、可逐条关闭。
 * 输出的是「需人工复核的写作信号」，不是漏洞，也不是定稿判决。
 */

const RULES = [
  {
    id: 'V-A001', severity: 'high', title: '绝对化全球性主张',
    re: /全球(首个|第一|唯一|最先|领先)|世界(首个|第一|唯一)|业界(首个|唯一)|国际上首个/g,
    hint: '绝对化范围主张需要可核验来源；若无法核验，改写为限定范围的表述'
  },
  {
    id: 'V-A002', severity: 'high', title: '安全性绝对断言',
    re: /(绝对安全|完全安全|不可能被破解|无法被破解|不可被攻破|零风险|100%\s*安全|never\s+be\s+broken|unbreakable)/gi,
    hint: '密码学结论不存在绝对性，改为给出攻击模型与边界条件'
  },
  {
    id: 'V-A003', severity: 'medium', title: '未标注依据的最高级/唯一性表述',
    re: /(最强|最快|最安全|最领先|唯一能够|唯一实现|首个实现|首创)/g,
    hint: '最高级需绑到具体对比对象与指标；无依据时降级为陈述'
  },
  {
    id: 'V-S001', severity: 'medium', title: '禁用词',
    re: /(坑|其实|值得一提|恰恰|有点|挺|蛮|话说回来)/g,
    hint: 'FIBEMATE 稿规：虚词与口语直接删'
  },
  {
    id: 'V-S002', severity: 'medium', title: '禁用「值得X」句式',
    re: /值得(?!注意|警惕|说明的)(\S{0,4})/g,
    hint: '稿规：动词直接接宾语，去掉「值得」'
  },
  {
    id: 'V-D001', severity: 'low', title: '未完成占位',
    re: /(TODO|FIXME|XXX|<\s*待补[^>]*>|\?\?\?)/g,
    hint: '发稿前清除占位标记'
  }
];

function lintText(text, fileRef, opts) {
  const options = opts || {};
  const disabled = new Set((options.lint && options.lint.disable) || []);
  const extra = (options.lint && options.lint.extra) || [];
  const active = RULES.filter((r) => !disabled.has(r.id)).concat(extra);
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
  const findings = [];

  // 命中词出现在「不要 / 并非 / 幻觉」这类否定或讨论语境里时，是论证对象而非主张本身：
  // 降级为 low，避免把自查文档自己打成高危。
  const NEGATION_CUE = /(不要|不能|并非|绝非|不代表|不等同|避免|警惕|幻觉|而非|并非的)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of active) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        if (!m[0]) { rule.re.lastIndex++; continue; }
        const ahead = line.slice(Math.max(0, m.index - 14), m.index);
        const quoted = /[「“"']\s*$/.test(line.slice(Math.max(0, m.index - 2), m.index));
        const negated = NEGATION_CUE.test(ahead);
        findings.push({
          id: (String(fileRef).split('/').pop()) + ':L' + (i + 1) + ':' + rule.id,
          file: fileRef,
          line: i + 1,
          ruleId: rule.id,
          severity: negated ? 'low' : rule.severity,
          baseSeverity: rule.severity,
          downgraded: negated,
          quoted,
          title: rule.title,
          matched: m[0],
          sentence: line.trim().slice(0, 200),
          hint: negated ? '命中词处于否定/讨论语境（' + (NEGATION_CUE.exec(ahead) || [''])[0] + '），已降级为 low：确认它不是主张本身' : rule.hint
        });
      }
    }
  }
  return findings;
}

/** 代码块需要跳过：把 ``` 段落按行号记录，供上层过滤。 */
function codeLineRanges(text) {
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
  const ranges = [];
  let open = false, start = 0;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (/^(```|~~~)/.test(t)) {
      if (!open) { open = true; start = i + 1; }
      else { ranges.push([start, i + 1]); open = false; }
    }
  }
  if (open) ranges.push([start, lines.length]);
  return ranges;
}

function inRanges(n, ranges) {
  for (const r of ranges) if (n >= r[0] && n <= r[1]) return true;
  return false;
}

function lintDoc(text, fileRef, opts) {
  const raw = lintText(text, fileRef, opts);
  if (opts && opts.lint && opts.lint.includeCodeBlocks) return raw;
  const ranges = codeLineRanges(text);
  return raw.filter((f) => !inRanges(f.line, ranges));
}

module.exports = { RULES, lintDoc, lintText, codeLineRanges };
