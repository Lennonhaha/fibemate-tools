// SPDX-License-Identifier: Apache-2.0
'use strict';

/** 零依赖回归：只测工具自身的确定性语义，不测密码学实现的正确性。 */

const assert = require('assert');
const U = require('../src/util');
const { Drbg, installRng, subSeed } = require('../src/rng');
const { loadConfig } = require('../src/config');
const { ConfigError } = require('../src/errors');

let pass = 0;
let fail = 0;
function test(name, fn) {
  try { fn(); pass++; console.log('  ok   ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
}
async function atest(name, fn) {
  try { await fn(); pass++; console.log('  ok   ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
}

(async function main() {
  console.log('xdiff 回归');

  // ---- 随机源注入 ----
  test('Drbg: 同种子产出同一字节流', () => {
    const a = new Drbg(Buffer.from('seed-a'), 'L');
    const b = new Drbg(Buffer.from('seed-a'), 'L');
    assert.strictEqual(a._next(64).toString('hex'), b._next(64).toString('hex'));
  });

  test('Drbg: 不同种子产出不同字节流', () => {
    const a = new Drbg(Buffer.from('seed-a'), 'L');
    const b = new Drbg(Buffer.from('seed-b'), 'L');
    assert.notStrictEqual(a._next(64).toString('hex'), b._next(64).toString('hex'));
  });

  test('Drbg: 标签参与派生（keygen 与 encaps 不共用同一段流）', () => {
    const a = new Drbg(Buffer.from('s'), 'keygen#0');
    const b = new Drbg(Buffer.from('s'), 'encaps#0');
    assert.notStrictEqual(a._next(32).toString('hex'), b._next(32).toString('hex'));
  });

  test('Drbg: 跨块读取连续且无重复', () => {
    const d = new Drbg(Buffer.from('s'), 'L');
    const first = d._next(70);
    const d2 = new Drbg(Buffer.from('s'), 'L');
    const p1 = d2._next(32);
    const p2 = d2._next(38);
    assert.strictEqual(Buffer.concat([p1, p2]).toString('hex'), first.toString('hex'));
  });

  test('installRng: 记录调用序列并在结束后还原', () => {
    const before = globalThis.crypto;
    const h = installRng({ seed: Buffer.from('s'), label: 't' });
    const out = new Uint8Array(32);
    globalThis.crypto.getRandomValues(out);
    globalThis.crypto.getRandomValues(new Uint8Array(16));
    assert.deepStrictEqual(h.drbg.calls, [32, 16]);
    h.restore();
    assert.strictEqual(globalThis.crypto, before);
  });

  test('subSeed: 同参数稳定，异参数不同', () => {
    const a = subSeed(Buffer.from('m'), 0, 'keygen');
    const b = subSeed(Buffer.from('m'), 0, 'keygen');
    const c = subSeed(Buffer.from('m'), 1, 'keygen');
    assert.strictEqual(a.toString('hex'), b.toString('hex'));
    assert.notStrictEqual(a.toString('hex'), c.toString('hex'));
  });

  // ---- 工具函数 ----
  test('util: finalK 等于 SHA3-256(K̄‖H(ct))', () => {
    const kbar = Buffer.alloc(32, 1);
    const ct = Buffer.alloc(1088, 2);
    const expect = U.sha3_256(kbar, U.sha3_256(ct));
    assert.strictEqual(U.finalK(kbar, ct).toString('hex'), expect.toString('hex'));
  });

  test('util: flipBit 只改一位', () => {
    const b = Buffer.alloc(4);
    const f = U.flipBit(b, 0);
    assert.strictEqual(f[0], 0x01);
    assert.strictEqual(f.length, 4);
    const f2 = U.flipBit(b, 11);
    assert.strictEqual(f2[1], 0x08);
  });

  test('util: shortHex 同时接受 Buffer 与 hex 字符串', () => {
    const buf = Buffer.alloc(40, 7);
    const hex = buf.toString('hex');
    assert.strictEqual(U.shortHex(buf, 8), U.shortHex(hex, 8));
    assert.ok(U.shortHex(hex, 8).endsWith('…'));
  });

  test('util: equalBytes 长度不同返回 false 而不抛', () => {
    assert.strictEqual(U.equalBytes(Buffer.alloc(32), Buffer.alloc(31)), false);
    assert.strictEqual(U.equalBytes(Buffer.alloc(32, 5), Buffer.alloc(32, 5)), true);
  });

  // ---- 配置 ----
  test('config: implementations 为空立即失败', () => {
    assert.throws(() => loadConfig({ cwd: __dirname, overrides: { implementations: [] } }), ConfigError);
  });

  test('config: 未知 JSON 立即失败', () => {
    const fs = require('fs');
    const p = require('path').join(require('os').tmpdir(), 'xdiff-bad-config-test.json');
    fs.writeFileSync(p, '{oops');
    assert.throws(() => loadConfig({ cwd: __dirname, configPath: p }), ConfigError);
    fs.unlinkSync(p);
  });

  test('config: 默认值不会被 undefined 覆盖', () => {
    const cfg = loadConfig({ cwd: __dirname });
    assert.strictEqual(cfg.algorithm, 'ML-KEM-768');
    assert.strictEqual(cfg.sizes.pk, 1184);
    assert.strictEqual(cfg.params.k, 3);
  });

  // ---- 引擎冒烟（用真实实现，最小样本）----
  await atest('engine: 最小样本可跑通并给出结构化报告', async () => {
    const cfg = loadConfig({
      cwd: require('path').join(__dirname, '..'),
      overrides: {
        masterSeed: 'unit-test-seed',
        cases: {
          lengthCompliance: { enabled: true },
          roundtrip: { enabled: true, samples: 1 },
          crossInterop: { enabled: true, samples: 1 },
          determinism: { enabled: true, samples: 1 },
          seedAlignment: { enabled: true },
          keySchedule: { enabled: true },
          kat: { enabled: false },
          entropy: { enabled: true, samples: 2 },
          implicitRejection: { enabled: true, samples: 1 },
          rngProfile: { enabled: true },
          timing: { enabled: false }
        }
      }
    });
    const engine = require('../src/engine');
    const rep = await engine.run(cfg, { log: null });
    assert.ok(rep.generatedAt, '缺少 generatedAt');
    assert.ok(Array.isArray(rep.findings));
    assert.ok(rep.counts && typeof rep.counts.error === 'number');
    const caseIds = rep.cases.map((c) => c.caseId);
    for (const id of ['lengthCompliance', 'roundtrip', 'crossInterop', 'seedAlignment']) {
      assert.ok(caseIds.includes(id), '缺少用例 ' + id);
    }
    assert.ok(rep.observations.ssSemantics, '缺少共享密钥语义归类');
  });

  // ---- KAT 解析与卫生分析 ----
  test('kat.parseRsp: 解析字段、长度校验、count 分段', () => {
    const kat = require('../src/core/kat');
    const hex = (n, fill) => Buffer.alloc(n, fill).toString('hex');
    const text = [
      '# comment',
      'count = 0',
      'seed = ' + hex(32, 1),
      'm = ' + hex(32, 2),
      'ek = ' + hex(1184, 3),
      'dk = ' + hex(2400, 4),
      'c = ' + hex(1088, 5),
      'k = ' + hex(32, 6),
      '',
      'count = 1',
      'seed = ' + hex(32, 7),
      'm = ' + hex(32, 8),
      'ek = ' + hex(1184, 9),
      'dk = ' + hex(100, 10),   // 长度不对
      'c = ' + hex(1088, 11),
      'k = ' + hex(32, 12)
    ].join('\n');
    const vs = kat.parseRsp(text);
    assert.strictEqual(vs.length, 2);
    assert.strictEqual(vs[0].seed.length, 32);
    assert.strictEqual(vs[0].ekLenOk, true);
    assert.strictEqual(vs[1].dkLenOk, false);
    const bad = kat.checkStructure(vs);
    assert.strictEqual(bad.length, 1);
    assert.strictEqual(bad[0].field, 'dk');
    assert.strictEqual(bad[0].problem, 'length');
  });

  test('kat.analyzeHygiene: 全零尾部报 allZero，内存残留报 nonZero + ASCII', () => {
    const kat = require('../src/core/kat');
    const seed = Buffer.alloc(32, 1);
    const ek = Buffer.alloc(1184, 2);
    const h = U.sha3_256(ek);
    const mkDk = (zFill, tail) => Buffer.concat([
      seed, ek, h, Buffer.alloc(32, zFill), tail
    ]);
    const vClean = { count: 0, seed, ek, dk: mkDk(0, Buffer.alloc(1120, 0)) };
    const vDirty = { count: 1, seed, ek, dk: mkDk(9, Buffer.from('internal/stream_ garbage!!' + 'x'.repeat(1120 - 26))) };
    const hy = kat.analyzeHygiene([vClean, vDirty]);
    assert.strictEqual(hy.compact.of, 2);
    assert.strictEqual(hy.compact.dMatch, 2);
    assert.strictEqual(hy.compact.ekMatch, 2);
    assert.strictEqual(hy.compact.hMatch, 2);
    assert.strictEqual(hy.tail.allZero, 1);
    assert.strictEqual(hy.tail.nonZero, 1);
    assert.strictEqual(hy.tail.asciiReadable, 1);
    assert.strictEqual(hy.z.allZero, 1);
  });

  test('installExplicitRng: 按序供字节，取空或长度不符即抛错', () => {
    const { installExplicitRng } = require('../src/rng');
    const h = installExplicitRng([Buffer.alloc(32, 7)]);
    const b = Buffer.alloc(32);
    globalThis.crypto.getRandomValues(b);
    assert.ok(b.every((x) => x === 7));
    assert.deepStrictEqual(h.calls, [32]);
    let threw = 0;
    try { globalThis.crypto.getRandomValues(Buffer.alloc(32)); } catch (_) { threw++; }
    assert.strictEqual(threw, 1);
    h.restore();
    const h2 = installExplicitRng([Buffer.alloc(16, 1)]);
    try { globalThis.crypto.getRandomValues(Buffer.alloc(32)); } catch (_) { threw++; }
    assert.strictEqual(threw, 2);
    h2.restore();
  });

  await atest('engine: KAT 三件套在真实向量上给出 provenance 与 perImpl 计数', async () => {
    const path = require('path');
    const rsp = 'D:/FIBEMATE/fibemate/packages/pqc-kem/test/kat/mlkem-768-KAT.rsp';
    if (!require('fs').existsSync(rsp)) { console.log('       (跳过：KAT 向量文件不在本机)'); return; }
    const cfg = loadConfig({
      cwd: path.join(__dirname, '..'),
      overrides: {
        masterSeed: 'unit-test-seed',
        cases: {
          lengthCompliance: { enabled: false },
          roundtrip: { enabled: false },
          crossInterop: { enabled: false },
          determinism: { enabled: false },
          seedAlignment: { enabled: false },
          keySchedule: { enabled: false },
          entropy: { enabled: false },
          implicitRejection: { enabled: false },
          rngProfile: { enabled: false },
          timing: { enabled: false },
          kat: { enabled: true, rsp, vectors: 4 },
          katFileHygiene: { enabled: true }
        }
      }
    });
    const engine = require('../src/engine');
    const rep = await engine.run(cfg, { log: null });
    const katCase = rep.cases.find((c) => c.caseId === 'kat');
    const provCase = rep.cases.find((c) => c.caseId === 'katProvenance');
    const hyCase = rep.cases.find((c) => c.caseId === 'katFileHygiene');
    assert.ok(katCase && provCase && hyCase, '缺少 KAT 三件套用例记录');
    assert.strictEqual(provCase.provenance, 'missingDomainSep');
    assert.strictEqual(katCase.perImpl.main.cOk, 4, 'main 的 c 应对拍通过');
    assert.strictEqual(katCase.perImpl.main.ekOk, 0, 'main 的 ek 与非标准文件不一致');
    assert.strictEqual(katCase.perImpl.cp.ekOk, 0);
    assert.strictEqual(hyCase.tail.nonZero, 100, '尾部应检出内存残留');
    // 门禁语义：provenance error 计入 error，perImpl 的 info 不计
    const provFinding = rep.findings.find((f) => f.caseId === 'katProvenance');
    assert.ok(provFinding && provFinding.severity === 'error');
    const mainFinding = rep.findings.find((f) => f.caseId === 'kat' && f.impls[0] === 'main');
    assert.ok(mainFinding && mainFinding.severity === 'info', '非标准文件下 main 的不一致应记 info');
  });

  console.log('');
  console.log(pass + ' 通过, ' + fail + ' 失败');
  process.exit(fail ? 1 : 0);
})();
