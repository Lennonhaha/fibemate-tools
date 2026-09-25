'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const { ConfigError } = require('./errors');
const { dekey } = require('./core/normalize');
const { DEFAULT_EXCLUDE } = require('./core/walk');

const DEFAULT_MODULES = [
  'ML-KEM-768', 'ML-KEM-1024', 'ML-KEM', 'ML-DSA', 'SLH-DSA',
  'SM2', 'SM3', 'SM4', 'SM4-GCM', 'HMAC-SM3', 'P-256/ECDH',
  'FPGA NTT', 'FPGA v5', 'NTT', 'VWZ', 'LookingGlass',
  'TLS 1.3 Hybrid', 'Path C-2', 'C-2', 'OPK', 'TLA+', 'Double-Ratchet',
  'Jasmin', 'liboqs', 'ADLA', 'TVLA'
  // 注意：CARS / CBOM / SBOM 是评估框架不是模块，不要放进这张表——
  // 否则 cars-scorecard.json 这类文件名会被当成模块，凭空制造「跨模块绑定」。
];

const DEFAULTS = {
  docs: {
    roots: [],
    include: ['**/*.md'],
    exclude: DEFAULT_EXCLUDE.concat(['**/CHANGELOG.md']),
    maxFileBytes: 2 * 1024 * 1024,
    maxFiles: 4000,
    maxDepth: 12
  },
  artifacts: {
    roots: [],
    // 只登记「文件是否存在」的目录：TSR/TSQ/SHA256 这类二进制凭证不解析内容，
    // 但文档常常引用它们的编号（TSR lg-069），存在性本身就是可核验的事实。
    presenceRoots: [],
    include: ['**/*.json', '**/*.md', '**/*.log', '**/*.csv', '**/*.rpt', '**/*.twr'],
    exclude: DEFAULT_EXCLUDE.concat(['**/*.min.json']),
    maxFileBytes: 8 * 1024 * 1024,
    maxFiles: 6000,
    maxDepth: 12
  },
  resolve: { minScore: 0.45, relTolerance: 0.005, absTolerance: 0, locTolerance: 0.05 },
  crossDoc: { enabled: true, warnRatio: 10 },
  lint: { enabled: true, disable: [], includeCodeBlocks: false },
  modules: DEFAULT_MODULES,
  bindings: [],
  ignore: [],
  gate: { failOn: 'drift' },
  cache: { enabled: true, dir: '.verifact', maxHistory: 200 },
  server: { host: '127.0.0.1', port: 8787 }
};

/** 去掉值为 undefined 的键：deepMerge 遇到显式 undefined 会把默认值覆盖掉。 */
function stripUndefined(obj) {
  const out = {};
  for (const k of Object.keys(obj)) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}

function isPlainObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

function deepMerge(base, over) {
  if (!isPlainObject(over)) return over == null ? base : over;
  const out = Object.assign({}, base);
  for (const k of Object.keys(over)) {
    out[k] = isPlainObject(base[k]) || Array.isArray(base[k])
      ? (Array.isArray(over[k]) ? over[k] : deepMerge(base[k] || {}, over[k]))
      : over[k];
  }
  return out;
}

function buildModules(list) {
  return (list || []).map((name) => ({ name, dekey: dekey(name) })).filter((m) => m.dekey.length >= 2);
}

function findConfigFile(explicit, cwd) {
  if (explicit) {
    const p = path.resolve(cwd, explicit);
    if (!fs.existsSync(p)) throw new ConfigError('config file not found', { path: p });
    return p;
  }
  for (const name of ['verifact.json', '.verifact.json', 'verifact.config.json']) {
    const p = path.join(cwd, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/**
 * 集中配置加载 + 校验。启动即失败，不让错误配置跑到半路。
 */
function loadConfig(opts) {
  const options = opts || {};
  const cwd = path.resolve(options.cwd || process.cwd());
  const file = findConfigFile(options.configPath, cwd);
  let fileCfg = {};
  if (file) {
    try {
      fileCfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      throw new ConfigError('config file is not valid JSON', { path: file, detail: e.message });
    }
  }

  // 环境变量覆盖（服务端运行场景）
  const envCfg = {
    server: stripUndefined({
      host: process.env.VERIFACT_HOST,
      port: process.env.VERIFACT_PORT ? Number(process.env.VERIFACT_PORT) : undefined
    })
  };
  if (process.env.VERIFACT_CACHE === '0') envCfg.cache = { enabled: false };

  const merged = deepMerge(deepMerge(DEFAULTS, fileCfg), deepMerge(envCfg, options.overrides || {}));
  merged.__cwd = cwd;
  merged.__configFile = file;

  // --- 校验 ---
  const errs = [];
  if (!Array.isArray(merged.docs.roots) || !merged.docs.roots.length) {
    errs.push('docs.roots 不能为空');
  }
  if (!Array.isArray(merged.artifacts.roots)) {
    errs.push('artifacts.roots 必须是数组');
  }
  if (!(merged.resolve.minScore >= 0 && merged.resolve.minScore <= 1)) {
    errs.push('resolve.minScore 必须在 [0,1]');
  }
  if (Number.isNaN(merged.server.port)) errs.push('server.port 必须是数字');
  if (errs.length) throw new ConfigError('配置校验未通过', { problems: errs, file: merged.__configFile });

  for (const r of merged.docs.roots.concat(merged.artifacts.roots)) {
    if (typeof r !== 'string') throw new ConfigError('root 必须是字符串路径', { root: r });
  }
  return merged;
}

/** root 既可以是目录也可以是单个文件，这里分开处理。 */
function partitionRoots(roots, cwd) {
  const dirs = [];
  const files = [];
  const missing = [];
  for (const r of roots) {
    const abs = path.resolve(cwd, r);
    let st = null;
    try { st = fs.statSync(abs); } catch (_) { missing.push(r); continue; }
    if (st.isDirectory()) dirs.push({ input: r, abs });
    else if (st.isFile()) files.push({ input: r, abs, rel: path.basename(abs) });
  }
  return { dirs, files, missing };
}

module.exports = { loadConfig, buildModules, partitionRoots, DEFAULTS, DEFAULT_MODULES, deepMerge };
