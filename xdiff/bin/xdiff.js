#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('fs');
const path = require('path');
const { loadConfig, DEFAULTS } = require('../src/config');
const { create: createLogger } = require('../src/logger');
const engine = require('../src/engine');
const report = require('../src/report');
const { UsageError, ConfigError, toEnvelope } = require('../src/errors');

const USAGE = `xdiff — 跨实现差分哨兵

用法:
  xdiff run [--config <file>] [--seed <str>] [--samples <n>] [--format text|md|json]
            [--out <file>] [--fail-on error|warn|none] [--quiet]
  xdiff list [--config <file>]                 列出已注册实现及其可用性
  xdiff init [--dir <dir>]                     生成 xdiff.json 配置样例
  xdiff explain <findingId> [--file <report>]  打印某条差异的完整详情

判定:
  error   有客观答案的检查未通过（长度、往返、互操作、确定性、隐式拒绝）
  warn    可疑但可能合理（拒绝值未绑定密文等）
  info    观察记录（语义归类、随机消耗指纹、耗时）
`;

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { positional.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) { flags[key] = next; i++; }
    else flags[key] = true;
  }
  return { flags, positional };
}

async function cmdRun(argv) {
  const { flags } = parseFlags(argv);
  const log = createLogger({ quiet: !!flags.quiet, level: flags.quiet ? 'silent' : 'info' });
  const overrides = {};
  if (flags.seed) overrides.masterSeed = String(flags.seed);
  if (flags.samples) {
    const n = Number(flags.samples);
    if (!Number.isFinite(n) || n < 1) throw new UsageError('--samples 必须是正整数');
    overrides.cases = {};
    for (const k of Object.keys(DEFAULTS.cases)) {
      if (DEFAULTS.cases[k] && typeof DEFAULTS.cases[k] === 'object' && 'samples' in DEFAULTS.cases[k]) {
        overrides.cases[k] = Object.assign({}, DEFAULTS.cases[k], { samples: n });
      }
    }
  }
  const cfg = loadConfig({ cwd: process.cwd(), configPath: flags.config, overrides });
  const rep = await engine.run(cfg, { log });

  const format = String(flags.format || 'text');
  let body;
  if (format === 'json') body = report.renderJson(rep);
  else if (format === 'md') body = report.renderMarkdown(rep, { top: flags.top ? Number(flags.top) : 30 });
  else body = report.renderText(rep, { top: flags.top ? Number(flags.top) : 20 });

  if (flags.out) {
    const outAbs = path.resolve(process.cwd(), String(flags.out));
    fs.mkdirSync(path.dirname(outAbs), { recursive: true });
    fs.writeFileSync(outAbs, body, 'utf8');
    if (!flags.quiet) process.stderr.write('报告已写入 ' + outAbs + '\n');
  } else {
    process.stdout.write(body + '\n');
  }

  const failOn = String(flags['fail-on'] || cfg.output.failOn || 'error');
  if (failOn === 'none') return 0;
  if (failOn === 'warn' && (rep.counts.error > 0 || rep.counts.warn > 0)) return 1;
  if (rep.counts.error > 0) return 1;
  return 0;
}

async function cmdList(argv) {
  const { flags } = parseFlags(argv);
  const log = createLogger({ quiet: true });
  const cfg = loadConfig({ cwd: process.cwd(), configPath: flags.config });
  const impls = await require('../src/impls/registry').loadAll(cfg, null);
  const L = [];
  L.push('算法 ' + cfg.algorithm + '  期望尺寸 pk=' + cfg.sizes.pk + ' sk=' + cfg.sizes.sk + ' ct=' + cfg.sizes.ct + ' ss=' + cfg.sizes.ss);
  L.push('');
  for (const im of impls) {
    L.push(pad(im.id, 8) + pad(im.status, 12) + (im.label || ''));
    L.push('        路径 ' + im.path);
    if (im.reason) L.push('        原因 ' + im.reason);
    if (im.rngProfileKeygen) L.push('        keygen 随机消耗 ' + JSON.stringify(im.rngProfileKeygen));
    if (im.probeOk) L.push('        探测 keygen ' + im.readyMs + 'ms');
  }
  process.stdout.write(L.join('\n') + '\n');
  void log;
  return impls.some((i) => i.status === 'ready') ? 0 : 1;
}

async function cmdInit(argv) {
  const { flags } = parseFlags(argv);
  const dir = path.resolve(process.cwd(), String(flags.dir || '.'));
  const target = path.join(dir, 'xdiff.json');
  if (fs.existsSync(target) && flags.force !== true) {
    throw new UsageError('已存在 ' + target + '（加 --force 覆盖）');
  }
  const sample = {
    version: 1,
    algorithm: DEFAULTS.algorithm,
    sizes: DEFAULTS.sizes,
    masterSeed: 'xdiff-default-master-seed-v1',
    implementations: DEFAULTS.implementations,
    cases: DEFAULTS.cases,
    pool: DEFAULTS.pool,
    output: DEFAULTS.output
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, JSON.stringify(sample, null, 2) + '\n', 'utf8');
  process.stdout.write('已生成 ' + target + '\n');
  return 0;
}

async function cmdExplain(argv) {
  const { flags, positional } = parseFlags(argv);
  const id = positional[0];
  if (!id) throw new UsageError('需要提供 finding id');
  const file = String(flags.file || path.join(process.cwd(), '.xdiff', 'report.json'));
  if (!fs.existsSync(file)) throw new UsageError('报告文件不存在: ' + file);
  const rep = JSON.parse(fs.readFileSync(file, 'utf8'));
  const hit = rep.findings.find((f) => f.id === id) || rep.findings.find((f) => f.id.indexOf(id) >= 0);
  if (!hit) throw new UsageError('未找到 finding: ' + id);
  process.stdout.write(JSON.stringify(hit, null, 2) + '\n');
  return 0;
}

function pad(s, n) {
  let out = String(s == null ? '' : s);
  let w = 0;
  for (const ch of out) w += /[\u4e00-\u9fa5]/.test(ch) ? 2 : 1;
  void w;
  return out + ' '.repeat(Math.max(0, n - out.length));
}

async function main(rawArgv) {
  const argv = rawArgv.slice(2);
  const cmd = argv[0] || 'run';
  const rest = argv.slice(1);
  switch (cmd) {
    case 'run': return await cmdRun(rest);
    case 'list': return await cmdList(rest);
    case 'init': return await cmdInit(rest);
    case 'explain': return await cmdExplain(rest);
    case 'help': case '-h': case '--help': process.stdout.write(USAGE); return 0;
    default:
      if (cmd.startsWith('--')) return await cmdRun(argv);
      throw new UsageError('未知命令: ' + cmd + '\n\n' + USAGE);
  }
}

if (require.main === module) {
  main(process.argv).then((code) => {
    process.exitCode = code;
  }).catch((err) => {
    const env = toEnvelope(err);
    process.stderr.write(JSON.stringify(env) + '\n');
    if (err instanceof UsageError) process.stderr.write(USAGE + '\n');
    process.exitCode = err instanceof ConfigError || err instanceof UsageError ? 2 : 1;
  });
}

module.exports = { main };
