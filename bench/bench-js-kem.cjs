#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
//
// ML-KEM-768 pure-JS benchmark -> machine-readable artifact.
//
// 为什么存在：docs 里的性能数字此前没有可复核的产出物，verifact 只能靠
// `ignore` 把它们藏起来（#106）。这个脚本把造出数字的那次运行原样落成 JSON，
// 让「文档声明 ↔ 产出物」能真正对上，而不是拿文档自己证明自己。
//
// 用法:
//   node bench/bench-js-kem.cjs                       # 默认 200 轮
//   node bench/bench-js-kem.cjs --rounds 500 --out bench/bench-js-results.json
//   node bench/bench-js-kem.cjs --module ../fibemate/packages/pqc-kem/src/ml-kem-768.js
//
// 退出码: 0 成功 / 1 自检失败（KEM 往返不一致）/ 2 用法错误

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

const args = process.argv.slice(2);
function flag(name, dflt) {
  const i = args.indexOf('--' + name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
}

const ROUNDS = parseInt(flag('rounds', '200'), 10);
const WARMUP = parseInt(flag('warmup', '20'), 10);
const MODULE_REL = flag('module', '../../fibemate/packages/pqc-kem/src/ml-kem-768.js');
const OUT = flag('out', path.join(__dirname, 'bench-js-results.json'));

if (!Number.isInteger(ROUNDS) || ROUNDS < 10) {
  console.error('--rounds 必须是 >=10 的整数');
  process.exit(2);
}

const modulePath = path.resolve(__dirname, MODULE_REL);
const kem = require(modulePath);
const moduleSha256 = crypto.createHash('sha256').update(fs.readFileSync(modulePath)).digest('hex');

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function measure(label, fn) {
  const samples = [];
  for (let i = 0; i < WARMUP; i++) fn();
  let total = 0;
  for (let i = 0; i < ROUNDS; i++) {
    const t0 = performance.now();
    fn();
    const dt = performance.now() - t0;
    samples.push(dt);
    total += dt;
  }
  samples.sort((a, b) => a - b);
  const avg = total / ROUNDS;
  return {
    label,
    minMs: samples[0],
    avgMs: avg,
    p50Ms: percentile(samples, 50),
    p90Ms: percentile(samples, 90),
    p99Ms: percentile(samples, 99),
    maxMs: samples[samples.length - 1],
    opsPerSec: avg > 0 ? 1000 / avg : null
  };
}

// 自检：先证明这次跑的是能用的 KEM（否则测出来的数字毫无意义）
const probe = kem.generateKeypair();
const enc = kem.encapsulate(probe.publicKey);
// 注意参数顺序：decapsulate(secretKey, ciphertext)
const dec = kem.decapsulate(probe.secretKey, enc.ciphertext);
if (Buffer.compare(Buffer.from(dec), Buffer.from(enc.sharedSecret)) !== 0) {
  console.error('SELF-CHECK FAILED: 往返共享密钥不一致，拒绝产出基准数字');
  process.exit(1);
}

console.log('ML-KEM-768 pure JS benchmark: rounds=' + ROUNDS + ' warmup=' + WARMUP);
const keygen = measure('keygen', () => kem.generateKeypair());
const encaps = measure('encaps', () => kem.encapsulate(probe.publicKey));
const decaps = measure('decaps', () => kem.decapsulate(probe.secretKey, enc.ciphertext));

const cpus = os.cpus() || [];
// 结构约束（verifact 绑定用）：
//   ML-KEM-768.pure-js.<op>.*  —— 带模块名的路径，才能通过 verifact 的模块硬约束
//   run.*                      —— 运行元数据，在 verifact.json 的 artifacts.deny 里排除，
//                                 否则 rounds/warmup 这类通用键会被误绑到别处的声明上
const artifact = {
  schema: 'fibemate-bench/1',
  run: {
    algorithm: 'ML-KEM-768',
    backend: 'pure-js',
    module: path.relative(path.resolve(__dirname, '..'), modulePath).split(path.sep).join('/'),
    moduleSha256,
    selfCheck: 'encaps/decaps shared secret equal',
    startedAt: new Date().toISOString(),
    rounds: ROUNDS,
    warmup: WARMUP,
    host: {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      cpuModel: cpus.length ? cpus[0].model.trim() : null,
      cpuCount: cpus.length,
      totalMemGB: Math.round((os.totalmem() / 1024 / 1024 / 1024) * 10) / 10,
      node: process.version
    }
  },
  'ML-KEM-768': {
    'pure-js': {
      keygen,
      encaps,
      decaps
    }
  }
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(artifact, null, 2) + '\n', 'utf8');

for (const op of [keygen, encaps, decaps]) {
  console.log('  ' + op.label.padEnd(7) +
    ' min=' + op.minMs.toFixed(3) + 'ms' +
    ' avg=' + op.avgMs.toFixed(3) + 'ms' +
    ' p50=' + op.p50Ms.toFixed(3) + 'ms' +
    ' p90=' + op.p90Ms.toFixed(3) + 'ms' +
    ' p99=' + op.p99Ms.toFixed(3) + 'ms' +
    ' max=' + op.maxMs.toFixed(3) + 'ms' +
    ' throughput=' + op.opsPerSec.toFixed(1) + '/s');
}
console.log('written: ' + OUT);
