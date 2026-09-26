// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { ConfigError } = require('./errors');

const FILE_NAME = 'xdiff.json';

const DEFAULTS = {
  version: 1,
  algorithm: 'ML-KEM-768',
  // 期望尺寸，来自 FIPS 203 对 ML-KEM-768 的规定
  sizes: { pk: 1184, sk: 2400, ct: 1088, ss: 32 },
  // 算法参数，供密钥派生根因定位使用（k 是域分隔符，768 → 3）
  params: { k: 3, eta1: 2, eta2: 2 },

  masterSeed: 'xdiff-default-master-seed-v1',

  implementations: [
    {
      id: 'cp',
      label: 'fibemate-core 纯 JS',
      type: 'js-mlkem',
      path: 'D:/FIBEMATE/fibemate-core/index.js',
      note: '独立发布的纯 JS 包，Keccak 为 32 位字实现'
    },
    {
      id: 'main',
      label: '主仓 packages/pqc-kem',
      type: 'js-mlkem',
      path: 'D:/FIBEMATE/fibemate/packages/pqc-kem/src/ml-kem-768.js',
      note: '主仓副本，453 行，与 cp 已分叉'
    },
    {
      id: 'noble',
      label: '@noble/post-quantum ml_kem768',
      type: 'noble-mlkem',
      path: 'D:/FIBEMATE/fibemate/node_modules/@noble/post-quantum',
      note: '第三方独立实现，作为交叉参考'
    },
    {
      id: 'liboqs',
      label: 'liboqs 0.16 (C)',
      type: 'liboqs-bridge',
      path: 'D:/FIBEMATE/fibemate-tools/xdiff/tools/oqsbridge.exe',
      note: 'C 参考实现；本地构建为算法全禁用的空壳，实测不可用',
      enabled: true
    }
  ],

  cases: {
    lengthCompliance: { enabled: true },
    roundtrip: { enabled: true, samples: 8 },
    crossInterop: { enabled: true, samples: 8 },
    determinism: { enabled: true, samples: 4 },
    seedAlignment: { enabled: true },
    keySchedule: { enabled: true },
    kat: { enabled: true, rsp: null, vectors: 16 },
    katFileHygiene: { enabled: true },
    entropy: { enabled: true, samples: 8 },
    implicitRejection: { enabled: true, samples: 4 },
    rngProfile: { enabled: true },
    timing: { enabled: true, samples: 20 }
  },

  matrix: {
    // 互操作矩阵里允许「已知不同且已接受」的组合，避免噪声
    allowSemanticGroups: true,
    // 已确认的预期差异（例如 draft Kyber 与 FIPS 203 的 ss 语义不同）
    expectedDivergence: []
  },

  pool: { workers: 0, timeoutMs: 120000 },   // workers: 0 = 自动

  output: { dir: '.xdiff', failOn: 'error' },

  cache: { enabled: true }
};

function isPlainObject(v) {
  return Object.prototype.toString.call(v) === '[object Object]';
}

function deepMerge(base, patch) {
  if (!isPlainObject(patch)) return base;
  const out = Array.isArray(base) ? base.slice() : Object.assign({}, base);
  for (const k of Object.keys(patch)) {
    const pv = patch[k];
    if (pv === undefined) continue;
    if (isPlainObject(pv) && isPlainObject(out[k])) out[k] = deepMerge(out[k], pv);
    else out[k] = Array.isArray(pv) ? pv.slice() : pv;
  }
  return out;
}

function findConfigFile(startDir) {
  let cur = path.resolve(startDir);
  for (let i = 0; i < 8; i++) {
    const p = path.join(cur, FILE_NAME);
    if (fs.existsSync(p)) return p;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

function loadConfig(opts) {
  const o = opts || {};
  const cwd = path.resolve(o.cwd || process.cwd());
  let fileCfg = {};
  const configPath = o.configPath || findConfigFile(cwd);
  if (configPath) {
    let raw;
    try { raw = fs.readFileSync(configPath, 'utf8'); } catch (e) {
      throw new ConfigError('配置文件读取失败', { configPath, message: e.message });
    }
    try { fileCfg = JSON.parse(raw); } catch (e) {
      throw new ConfigError('配置文件不是合法 JSON', { configPath, message: e.message });
    }
  }

  const envCfg = {
    masterSeed: process.env.XDIFF_SEED || undefined
  };
  const stripped = {};
  for (const k of Object.keys(envCfg)) if (envCfg[k] !== undefined) stripped[k] = envCfg[k];

  let cfg = deepMerge(DEFAULTS, fileCfg);
  cfg = deepMerge(cfg, stripped);
  cfg = deepMerge(cfg, o.overrides || {});

  cfg.__cwd = cwd;
  cfg.__configPath = configPath;

  validate(cfg);
  return cfg;
}

function validate(cfg) {
  if (!cfg.algorithm) throw new ConfigError('algorithm 不能为空');
  const impls = cfg.implementations;
  if (!Array.isArray(impls) || !impls.length) throw new ConfigError('implementations 至少需要一项');
  const seen = new Set();
  for (const im of impls) {
    if (!im.id) throw new ConfigError('每项 implementation 需要 id');
    if (seen.has(im.id)) throw new ConfigError('implementation id 重复: ' + im.id);
    seen.add(im.id);
    if (!im.type) throw new ConfigError('implementation 需要 type: ' + im.id);
    if (!im.path) throw new ConfigError('implementation 需要 path: ' + im.id);
    if (im.enabled === false) continue;
    if (!fs.existsSync(im.path)) {
      // 路径不存在不算致命：适配器会把它标成 unavailable
      im.__missingPath = true;
    }
  }
  if (!cfg.sizes || typeof cfg.sizes.pk !== 'number') throw new ConfigError('sizes.pk 必须是数字');
}

function cpuCount() {
  try { return os.cpus().length || 4; } catch (_) { return 4; }
}

module.exports = { loadConfig, DEFAULTS, deepMerge, cpuCount, FILE_NAME };
