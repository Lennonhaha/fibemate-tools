#!/usr/bin/env node
'use strict';
// SPDX-License-Identifier: Apache-2.0

const path = require('path');
const fs = require('fs');
const { loadConfig } = require('../src/config');
const engine = require('../src/engine');
const logger = require('../src/logger');
const { readRuns, diffRuns } = require('../src/history');
const { UsageError } = require('../src/errors');

const HELP = `verifact — 事实哨兵：把文档里的硬数字声明绑定到真实产出物上逐条核验

用法:
  verifact verify [--config <file>] [--cwd <dir>] [选项]     扫描并核验，按门禁策略给出退出码
  verifact explain <claimId> [--config <file>]               打印单条声明的判定依据与候选
  verifact diff [--since <n>] [--top <n>]                    对比两次运行之间的状态迁移
  verifact serve [--config <file>] [--port <n>]              启动本地看板与 API
  verifact init [--dir <dir>]                                生成一份 verifact.json 样例配置

verify 选项:
  --cwd <dir>          工作目录（配置中的相对路径以此为基准），默认当前目录
  --config <file>      配置文件路径，默认依次查找 verifact.json / .verifact.json
  --docs <dir|file>    追加文档根（可多次，覆盖配置里的 docs.roots）
  --artifacts <dir>    追加产出物根（可多次）
  --fail-on <policy>   none | drift | review | lint-high   （默认 drift）
  --format <fmt>       text | json | md                     （默认 text）
  --out <file>         结果写入文件（json/md 时尤其有用）
  --top <n>            文本摘要里展示的 drift 条数，默认 20
  --deep               启用激进抽取（含裸大数字，误报率更高）
  --no-cache           跳过产出物增量缓存，强制重建索引
  --concurrency <n>    worker 数上限
  --quiet              不输出 stderr 结构化日志

退出码:
  0  核验通过 / 无命中门禁条件
  1  命中门禁条件（存在 drift 等）
  2  用法或配置错误
`;

function parseArgs(argv) {
  const out = { _: [], flags: {} };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { out.flags.help = true; i++; continue; }
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      const booleanFlags = ['deep', 'no-cache', 'quiet', 'version'];
      if (booleanFlags.indexOf(key) >= 0 || next === undefined || next.startsWith('--')) {
        out.flags[key] = true;
        i++;
        continue;
      }
      out.flags[key] = next;
      i += 2;
      continue;
    }
    out._.push(a);
    i++;
  }
  return out;
}

function collectRepeated(argv, name) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--' + name && argv[i + 1]) out.push(argv[i + 1]);
  }
  return out;
}

function buildOverrides(rawArgv, flags) {
  const o = {};
  const docs = collectRepeated(rawArgv, 'docs');
  const arts = collectRepeated(rawArgv, 'artifacts');
  if (docs.length) o.docs = { roots: docs };
  if (arts.length) o.artifacts = { roots: arts };
  if (flags['fail-on']) o.gate = { failOn: flags['fail-on'] };
  if (flags.port) o.server = { port: Number(flags.port) };
  return o;
}

function pad(s, n) {
  const str = String(s == null ? '' : s);
  const w = [...str].reduce((acc, ch) => acc + (/[\u4e00-\u9fff\uff00-\uffef]/.test(ch) ? 2 : 1), 0);
  return str + ' '.repeat(Math.max(0, n - w));
}

function valueText(v) {
  if (!v) return '-';
  if (v.type === 'ref') return v.raw;
  if (v.type === 'ratio') return v.raw;
  return v.raw;
}

const STATUS_LABEL = {
  verified: '✔ 已核验',
  drift: '✖ 漂移',
  ambiguous: '? 候选冲突',
  unbound: '· 未绑定',
  'ref-found': '✔ 产出物存在',
  'ref-missing': '✖ 产出物缺失',
  ignored: '- 已忽略'
};

function renderText(report, top) {
  const L = [];
  const c = report.counts;
  L.push('verifact — 事实哨兵');
  L.push('─'.repeat(78));
  L.push(`生成时间   ${report.generatedAt}   耗时 ${report.durationMs}ms   cache=${report.meta.cache}${report.meta.cacheReason ? '(' + report.meta.cacheReason + ')' : ''}   workers=${report.meta.workers}`);
  L.push(`文档       ${c.docs} 份      产出物条目 ${c.artifacts} 条      缓存 ${report.meta.cache}`);
  L.push('');
  const reviewable = c.verified + c.drift + c.ambiguous + c.unbound + c.refFound + c.refMissing;
  const rate = reviewable ? ((c.verified + c.refFound) / reviewable * 100).toFixed(1) : '0.0';
  L.push(`声明总数 ${pad(c.claims, 6)}   已核验 ${pad(c.verified, 5)}   漂移 ${pad(c.drift, 5)}   候选冲突 ${pad(c.ambiguous, 5)}   未绑定 ${pad(c.unbound, 5)}`);
  L.push(`引用型   ${pad(c.refFound + c.refMissing, 6)}   存在 ${pad(c.refFound, 5)}   缺失 ${pad(c.refMissing, 5)}   忽略 ${pad(c.ignored, 5)}   核验率 ${rate}%`);
  L.push(`用语线索 high ${pad(report.lintCounts.high, 4)} medium ${pad(report.lintCounts.medium, 4)} low ${pad(report.lintCounts.low, 4)}`);
  L.push('');

  const drifts = report.claims.filter((x) => x.status === 'drift');
  if (drifts.length) {
    L.push(`漂移明细（${drifts.length} 条，展示前 ${top} 条）`);
    L.push('─'.repeat(78));
    for (const d of drifts.slice(0, top)) {
      L.push(`${pad(d.file + ':' + d.line, 46)} ${pad(d.module || '-', 12)} ${d.key}`);
      L.push(`    文档值 ${valueText(d.value)}`);
      L.push(`    产出物 ${d.best ? d.best.source + ' :: ' + d.best.path : '-'}`);
      L.push(`    实际值 ${d.best ? valueText(d.best.value) : '-'}   score=${d.score != null ? Number(d.score).toFixed(2) : '-'}   ${d.cmp ? d.cmp.reason : ''}`);
      L.push(`    原文   ${d.sentence}`);
      L.push('');
    }
  } else {
    L.push('漂移明细：无');
  }

  const missing = report.claims.filter((x) => x.status === 'ref-missing');
  if (missing.length) {
    L.push('引用型产出物缺失');
    L.push('─'.repeat(78));
    for (const m of missing.slice(0, top)) {
      L.push(`  ${pad(m.file + ':' + m.line, 46)} ${valueText(m.value)}`);
    }
    L.push('');
  }

  const high = report.lint.filter((f) => f.severity === 'high');
  if (high.length) {
    L.push('用语线索 · high');
    L.push('─'.repeat(78));
    for (const f of high.slice(0, top)) {
      L.push(`  ${pad(f.file + ':' + f.line, 46)} ${pad(f.ruleId, 8)} ${f.matched}`);
    }
    L.push('');
  }

  L.push('─'.repeat(78));
  L.push(`门禁策略 ${report.gate.policy} → ${report.gate.failed ? 'FAILED' : 'PASSED'}`);
  if (report.meta.docsMissing.length) {
    L.push(`注意：以下 root 不存在，已跳过 → ${report.meta.docsMissing.join(', ')}`);
  }
  return L.join('\n');
}

function renderMarkdown(report, top) {
  const L = [];
  const c = report.counts;
  L.push('# verifact 核验报告');
  L.push('');
  L.push(`- 生成时间：${report.generatedAt}`);
  L.push(`- 耗时：${report.durationMs} ms（缓存 ${report.meta.cache}，worker ${report.meta.workers}）`);
  L.push(`- 文档 ${c.docs} 份 / 产出物条目 ${c.artifacts} 条 / 声明 ${c.claims} 条`);
  L.push(`- 已核验 ${c.verified} · 漂移 ${c.drift} · 候选冲突 ${c.ambiguous} · 未绑定 ${c.unbound} · 引用存在 ${c.refFound} · 引用缺失 ${c.refMissing}`);
  L.push(`- 用语线索：high ${report.lintCounts.high} / medium ${report.lintCounts.medium} / low ${report.lintCounts.low}`);
  L.push(`- 门禁：${report.gate.policy} → ${report.gate.failed ? '**FAILED**' : 'PASSED'}`);
  L.push('');
  const drifts = report.claims.filter((x) => x.status === 'drift');
  L.push('## 漂移明细');
  L.push('');
  if (!drifts.length) {
    L.push('无。');
  } else {
    L.push('| 位置 | 模块 | 键 | 文档值 | 产出物 | 实际值 | 评分 |');
    L.push('|---|---|---|---|---|---|---|');
    for (const d of drifts.slice(0, top)) {
      L.push(`| ${d.file}:${d.line} | ${d.module || '-'} | \`${d.key}\` | ${valueText(d.value)} | \`${d.best ? d.best.source : '-'}\` | ${d.best ? valueText(d.best.value) : '-'} | ${d.score != null ? Number(d.score).toFixed(2) : '-'} |`);
    }
  }
  L.push('');
  L.push('## high 级用语线索');
  L.push('');
  const high = report.lint.filter((f) => f.severity === 'high');
  if (!high.length) L.push('无。');
  else {
    L.push('| 位置 | 规则 | 命中 | 原文 |');
    L.push('|---|---|---|---|');
    for (const f of high.slice(0, top)) {
      L.push(`| ${f.file}:${f.line} | ${f.ruleId} | ${f.matched} | ${String(f.sentence).replace(/\|/g, '\\|').slice(0, 80)} |`);
    }
  }
  L.push('');
  L.push('> 本报告只陈述「文档写的值」与「产出物里的值」是否一致，以及两者的位置。');
  L.push('> 它不判定哪一方正确，也不声明任何漏洞。');
  return L.join('\n');
}

async function cmdVerify(rawArgv, args) {
  const flags = args.flags;
  const cwd = path.resolve(flags.cwd || process.cwd());
  const cfg = loadConfig({ cwd, configPath: flags.config, overrides: buildOverrides(rawArgv, flags) });
  const log = logger.create({ quiet: !!flags.quiet });
  const report = await engine.run(cfg, {
    deep: !!flags.deep,
    noCache: !!flags['no-cache'],
    concurrency: flags.concurrency ? Number(flags.concurrency) : undefined,
    logger: log
  });

  const fmt = flags.format || 'text';
  const top = flags.top ? Number(flags.top) : 20;
  let rendered;
  if (fmt === 'json') rendered = JSON.stringify(report, null, 2);
  else if (fmt === 'md') rendered = renderMarkdown(report, top);
  else rendered = renderText(report, top);

  if (flags.out) {
    fs.mkdirSync(path.dirname(path.resolve(cwd, flags.out)), { recursive: true });
    fs.writeFileSync(path.resolve(cwd, flags.out), rendered, 'utf8');
    if (fmt !== 'text') process.stdout.write('written: ' + flags.out + '\n');
    else process.stdout.write(rendered + '\n');
  } else {
    process.stdout.write(rendered + '\n');
  }
  return report.gate.failed ? 1 : 0;
}

async function cmdExplain(rawArgv, args) {
  const id = args._[1];
  if (!id) throw new UsageError('explain 需要声明 id，例如 README.md:L28:ratio:kat');
  const flags = args.flags;
  const cwd = path.resolve(flags.cwd || process.cwd());
  const cfg = loadConfig({ cwd, configPath: flags.config, overrides: buildOverrides(rawArgv, flags) });
  const report = await engine.run(cfg, { noCache: !!flags['no-cache'], logger: logger.create({ quiet: true }) });
  const hit = report.claims.find((c) => c.id === id || (c.file + ':' + c.line) === id);
  if (!hit) {
    process.stdout.write('未找到声明 ' + id + '\n');
    process.stdout.write('可用 id 示例：\n');
    for (const c of report.claims.slice(0, 10)) process.stdout.write('  ' + c.id + '\n');
    return 2;
  }
  const L = [];
  L.push('声明 ' + hit.id);
  L.push('  文件行  ' + hit.file + ':' + hit.line);
  L.push('  模块    ' + (hit.module || '-'));
  L.push('  键      ' + hit.key + '  tokens=' + JSON.stringify(hit.keyTokens));
  L.push('  类型    ' + hit.kind + (hit.subtype ? '/' + hit.subtype : ''));
  L.push('  文档值  ' + valueText(hit.value) + '  ' + JSON.stringify(hit.value));
  L.push('  判定    ' + (STATUS_LABEL[hit.status] || hit.status) + '  score=' + (hit.score != null ? Number(hit.score).toFixed(3) : '-'));
  L.push('  依据    ' + (hit.note || '-'));
  if (hit.best) {
    L.push('  命中产出物');
    L.push('    source ' + hit.best.source);
    L.push('    path   ' + hit.best.path);
    L.push('    value  ' + valueText(hit.best.value) + '  ' + JSON.stringify(hit.best.value));
  }
  if (hit.alternatives && hit.alternatives.length) {
    L.push('  其他候选');
    for (const a of hit.alternatives) {
      L.push('    ' + Number(a.score).toFixed(3) + '  ' + a.source + ' :: ' + a.path + '  = ' + valueText(a.value));
    }
  }
  L.push('  原文    ' + hit.sentence);
  process.stdout.write(L.join('\n') + '\n');
  return 0;
}

async function cmdDiff(rawArgv, args) {
  const flags = args.flags;
  const cwd = path.resolve(flags.cwd || process.cwd());
  const cfg = loadConfig({ cwd, configPath: flags.config, overrides: buildOverrides(rawArgv, flags) });
  const runs = readRuns(cfg, cwd, 60);
  if (runs.length < 2) {
    process.stdout.write('历史里不足两次运行，先跑两次 verify 再 diff。当前：' + runs.length + ' 次\n');
    return 0;
  }
  const back = flags.since ? Number(flags.since) : 1;
  const curr = runs[runs.length - 1];
  const prev = runs[Math.max(0, runs.length - 1 - back)];
  const d = diffRuns(prev, curr);

  const L = [];
  L.push('verifact diff');
  L.push('─'.repeat(78));
  L.push(`基准 ${String(prev.generatedAt).replace('T', ' ').slice(0, 19)}   对比 ${String(curr.generatedAt).replace('T', ' ').slice(0, 19)}`);
  L.push(`drift ${pad(prev.counts.drift, 5)} → ${pad(curr.counts.drift, 5)}    verified ${pad(prev.counts.verified, 5)} → ${pad(curr.counts.verified, 5)}    unbound ${pad(prev.counts.unbound, 5)} → ${pad(curr.counts.unbound, 5)}`);
  if (!prev.states) {
    L.push('注意：基准那次运行没有逐条状态快照（v0.1 之前写的，或首次运行）。');
    L.push('      未收录的条目一律按 unbound 解释，所以会显示一大批「新增」。本次结果即为新基线。');
  }
  L.push('');

  const section = (title, list) => {
    L.push(`${title}（${list.length}）`);
    if (!list.length) { L.push('  无。'); L.push(''); return; }
    for (const c of list.slice(0, Number(flags.top) || 30)) {
      L.push('  ' + pad(c.from, 12) + ' → ' + pad(c.to, 12) + '  ' + c.id);
    }
    L.push('');
  };
  section('新增 drift', d.newDrift);
  section('已消除的 drift', d.resolvedDrift);
  section('新增 verified', d.newVerified);
  section('verified 退化为其他', d.lostVerified);
  section('新增 ref-missing', d.newMissingRef);

  if (!d.all.length) L.push('两次运行之间没有状态变化。');
  process.stdout.write(L.join('\n') + '\n');
  return 0;
}

async function cmdServe(rawArgv, args) {
  const flags = args.flags;
  const cwd = path.resolve(flags.cwd || process.cwd());
  const cfg = loadConfig({ cwd, configPath: flags.config, overrides: buildOverrides(rawArgv, flags) });
  const server = require('../src/server/api');
  await server.start(cfg, logger.create({ quiet: !!flags.quiet }));
  // 服务已在监听：这里必须挂住进程，否则 main() 立刻返回 0 会把进程退出
  return new Promise(() => {});
}

function cmdInit(args) {
  const dir = path.resolve(args.flags.dir || process.cwd());
  const target = path.join(dir, 'verifact.json');
  if (fs.existsSync(target)) {
    process.stdout.write('已存在 ' + target + '，未覆盖\n');
    return 0;
  }
  const sample = {
    docs: { roots: ['../README.md', '../docs'] },
    artifacts: { roots: ['../tools', '../reports'] },
    modules: ['ML-KEM-768', 'SM2', 'SM3', 'SM4', 'VWZ'],
    resolve: { minScore: 0.45 },
    bindings: [],
    ignore: [],
    gate: { failOn: 'drift' }
  };
  fs.writeFileSync(target, JSON.stringify(sample, null, 2) + '\n', 'utf8');
  process.stdout.write('written: ' + target + '\n');
  return 0;
}

async function main() {
  const rawArgv = process.argv.slice(2);
  const args = parseArgs(rawArgv);
  if (args.flags.help || !args._.length) {
    process.stdout.write(HELP);
    return args._.length ? 0 : 2;
  }
  const cmd = args._[0];
  try {
    if (cmd === 'verify') return await cmdVerify(rawArgv, args);
    if (cmd === 'explain') return await cmdExplain(rawArgv, args);
    if (cmd === 'diff') return await cmdDiff(rawArgv, args);
    if (cmd === 'serve') return await cmdServe(rawArgv, args);
    if (cmd === 'init') return cmdInit(args);
    if (cmd === 'version') { process.stdout.write(require('../package.json').version + '\n'); return 0; }
    throw new UsageError('未知子命令: ' + cmd);
  } catch (e) {
    if (e && e.code) {
      process.stderr.write(JSON.stringify(e.toJSON ? e.toJSON() : { error: 'error', message: e.message }) + '\n');
      return e.code === 'usage_error' || e.code === 'config_error' ? 2 : 1;
    }
    process.stderr.write(JSON.stringify({ error: 'internal_error', message: (e && e.message) || String(e) }) + '\n');
    return 1;
  }
}

if (require.main === module) {
  main().then((code) => process.exit(code)).catch(() => process.exit(1));
}

module.exports = { main, renderText, renderMarkdown, parseArgs };
