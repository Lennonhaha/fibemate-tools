'use strict';
// SPDX-License-Identifier: Apache-2.0

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { compilePatterns } = require('../src/core/walk');
const { extractClaims } = require('../src/core/claims');
const { collectArtifacts, buildIndex } = require('../src/core/artifacts');
const { resolveClaim } = require('../src/core/resolve');
const { lintDoc } = require('../src/core/lint');
const { loadConfig, buildModules } = require('../src/config');
const engine = require('../src/engine');
const { diffRuns } = require('../src/history');
const { compareValues, valueFromString, mkValue, mkRatio } = require('../src/core/normalize');

const FIX = path.join(__dirname, 'fixtures');
const MODULES = buildModules(['ML-KEM-768', 'SM2']);

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function read(rel) { return fs.readFileSync(path.join(FIX, rel), 'utf8'); }

// ---------- 单位测试 ----------

test('normalize: 单位换算后等价 (78.5ms === 78500000ns)', () => {
  const cmp = compareValues(mkValue('78.5', 'ms'), mkValue('78500000', 'ns'), {});
  assert.strictEqual(cmp.equal, true, '应判定相等');
  assert.strictEqual(cmp.comparable, true, '应可跨单位比较');
});

test('normalize: 比率相等判定', () => {
  const cmp = compareValues(mkRatio('10,000', '10,000'), mkRatio('10000', '10000'), {});
  assert.strictEqual(cmp.equal, true);
  const bad = compareValues(mkRatio('9999', '10000'), mkRatio('10000', '10000'), {});
  assert.strictEqual(bad.equal, false);
});

test('walk: glob 编译支持 ** 与 *', () => {
  const re = compilePatterns(['**/*.md']);
  assert.ok(re[0].test('a/b/c.md'));
  assert.ok(!re[0].test('a/b/c.txt'));
});

// ---------- 抽取 ----------

test('claims: 从表格行抽出比率声明并识别模块', () => {
  const claims = extractClaims(read('docs/report.md'), 'docs/report.md', { modules: MODULES });
  const kat = claims.find((c) => c.key === 'kat');
  assert.ok(kat, '应抽到 KAT 声明，实际 keys=' + claims.map((c) => c.key).join(','));
  assert.strictEqual(kat.kind, 'ratio');
  assert.strictEqual(kat.value.numerator, 10000);
  assert.strictEqual(kat.module, 'ML-KEM-768');
});

test('claims: kv 型声明抽出单位', () => {
  const claims = extractClaims(read('docs/report.md'), 'docs/report.md', { modules: MODULES });
  const p95 = claims.find((c) => c.key === 'p95');
  assert.ok(p95, '应抽到 p95');
  assert.strictEqual(p95.value.number, 78.5);
  assert.strictEqual(p95.value.unit, 'ms');
  const cov = claims.find((c) => c.key === 'coverage');
  assert.ok(cov, '应抽到 coverage');
  assert.strictEqual(cov.value.number, 99.1);
});

test('claims: 引用型声明抽出 TSR 编号', () => {
  const claims = extractClaims(read('docs/report.md'), 'docs/report.md', { modules: MODULES });
  const refs = claims.filter((c) => c.kind === 'ref' && c.subtype === 'tsr');
  assert.strictEqual(refs.length, 2, '应有两条 TSR 引用');
  assert.deepStrictEqual(refs.map((r) => r.value.ref), ['lg-069', 'lg-999']);
});

test('claims: 良好样例零 finding（不误报优先）', () => {
  const text = read('docs/good.md');
  const claims = extractClaims(text, 'docs/good.md', { modules: MODULES });
  assert.strictEqual(claims.length, 0, '干净文本必须零声明，实际：' + JSON.stringify(claims.map((c) => c.id)));
  const lint = lintDoc(text, 'docs/good.md', {});
  assert.strictEqual(lint.length, 0, '干净文本必须零用语线索');
});

test('claims: 行号准确（代码块/链接清洗后不漂移）', () => {
  const text = read('docs/report.md');
  const claims = extractClaims(text, 'docs/report.md', { modules: MODULES });
  const kat = claims.find((c) => c.key === 'kat');
  const lines = text.split(/\r?\n/);
  assert.ok(kat.line >= 1 && kat.line <= lines.length);
  assert.ok(/KAT 10,000\/10,000/.test(lines[kat.line - 1]), '行号应对到真实原文行；实际行内容=' + lines[kat.line - 1]);
});

// ---------- 产出物 ----------

test('artifacts: JSON 字符串叶子被拆成可比对子条目', () => {
  const arts = collectArtifacts({
    __cwd: FIX,
    artifacts: { roots: ['artifacts'], exclude: ['**/node_modules/**'], maxDepth: 8, maxFileBytes: 1e6, maxFiles: 500 }
  }, MODULES);
  const paths = arts.entries.map((e) => e.path);
  assert.ok(paths.indexOf('ml_kem_768.verification#kat') >= 0, '应有 #kat 子条目；实际=' + paths.join(','));
  assert.ok(paths.indexOf('latency.p95_ms') >= 0);
  assert.ok(paths.indexOf('coverage') >= 0);
  assert.ok(paths.indexOf('cross_validation') >= 0);
  assert.ok(arts.presence.some((p) => p.indexOf('lg-069') >= 0), '存在性名录应包含 tsr 文件');
});

// ---------- 解析 ----------

test('resolve: 已核验 / 漂移 / 引用存在 / 引用缺失 / 未绑定 五态可达', () => {
  const arts = collectArtifacts({
    __cwd: FIX,
    artifacts: { roots: ['artifacts'], exclude: ['**/node_modules/**'], maxDepth: 8, maxFileBytes: 1e6, maxFiles: 500 }
  }, MODULES);
  const index = buildIndex(arts);
  const claims = extractClaims(read('docs/report.md'), 'docs/report.md', { modules: MODULES });

  const byKey = (k) => claims.find((c) => c.key === k);
  const rCov = resolveClaim(byKey('coverage'), index, { minScore: 0.45 });
  assert.strictEqual(rCov.status, 'verified', 'coverage 应已核验');

  const rP95 = resolveClaim(byKey('p95'), index, { minScore: 0.45 });
  assert.strictEqual(rP95.status, 'drift', 'p95 应为漂移（文档 78.5 vs 产出物 81.2）');

  const refs = claims.filter((c) => c.kind === 'ref' && c.subtype === 'tsr');
  assert.strictEqual(resolveClaim(refs[0], index, { minScore: 0.45 }).status, 'ref-found');
  assert.strictEqual(resolveClaim(refs[1], index, { minScore: 0.45 }).status, 'ref-missing');

  const size = claims.find((c) => c.value.unit === 'bytes');
  if (size) {
    assert.strictEqual(resolveClaim(size, index, { minScore: 0.45 }).status, 'drift', 'SIZE 1,024 bytes 应对上 signature_bytes=80 → 漂移');
  }
});

// ---------- 用语 ----------

test('lint: 抓到绝对化主张与禁用词', () => {
  const lint = lintDoc(read('docs/report.md'), 'docs/report.md', {});
  assert.ok(lint.some((f) => f.ruleId === 'V-A001' && f.severity === 'high'), '应抓到「全球首个」');
  assert.ok(lint.some((f) => f.ruleId === 'V-S001'), '应抓到禁用词');
  assert.ok(lint.every((f) => !/```/.test(f.sentence)), '代码块不应计入');
});

// ---------- 服务层端到端 ----------

test('engine: 端到端跑通并给出门禁结果', async () => {
  const cfg = loadConfig({
    cwd: FIX,
    overrides: {
      docs: { roots: ['docs'], exclude: ['**/node_modules/**'], maxFiles: 200 },
      artifacts: { roots: ['artifacts'], exclude: ['**/node_modules/**'], maxFiles: 500 },
      modules: ['ML-KEM-768', 'SM2'],
      cache: { enabled: false },
      gate: { failOn: 'drift' }
    }
  });
  const report = await engine.run(cfg, {});
  assert.ok(report.counts.claims > 0, '应有声明');
  assert.ok(report.counts.verified >= 1, '应有已核验项');
  assert.strictEqual(report.counts.drift >= 1, true, 'p95 应判漂移');
  assert.strictEqual(report.gate.failed, true, '存在 drift 时门禁应失败');
  assert.strictEqual(report.schema, 'verifact-report/1');

  const soft = await engine.run(Object.assign({}, cfg, { gate: { failOn: 'none' } }), {});
  assert.strictEqual(soft.gate.failed, false, 'policy=none 时不应失败');
});

test('history.diff: 识别新增 / 消除的 drift', () => {
  const A = { states: { 'a:1:ratio:kat': 'drift', 'b:2:kv:p95': 'verified', 'c:3:ratio:tvla': 'verified' } };
  const B = { states: { 'a:1:ratio:kat': 'verified', 'b:2:kv:p95': 'drift', 'd:4:count:samples': 'drift' } };
  const d = diffRuns(A, B);
  assert.strictEqual(d.newDrift.length, 2, 'p95 由 verified 退化为 drift，samples 新增');
  assert.strictEqual(d.resolvedDrift.length, 1, 'kat 已修复');
  assert.strictEqual(d.resolvedDrift[0].id, 'a:1:ratio:kat');
  assert.strictEqual(d.lostVerified.length, 2, 'p95 与 tvla 都不再 verified');
});

test('config: 缺 docs.roots 立即失败', () => {
  let threw = false;
  try {
    loadConfig({ cwd: FIX, configPath: 'does-not-exist.json', overrides: { docs: { roots: [] } } });
  } catch (e) {
    threw = e.code === 'config_error';
  }
  assert.strictEqual(threw, true, '应抛 config_error');
});

test('gate: review 策略把未绑定也算失败', () => {
  const nonePolicy = engine.evaluateGate({ drift: 0, ambiguous: 0, unbound: 3, refMissing: 0 }, 'none');
  assert.strictEqual(nonePolicy.failed, false);
  const review = engine.evaluateGate({ drift: 0, ambiguous: 0, unbound: 3, refMissing: 0 }, 'review');
  assert.strictEqual(review.failed, true);
});

// ---------- loc 行数核验 ----------

test('claims: loc 行数声明抽取（过滤「第N行」与过小数值）', () => {
  const text = [
    '| **ML-KEM-768** | FIPS 203 | 自研纯 JS（654 行） | 恒定时间硬化参考实现 |',
    '细节见第 45 行的定义。',
    '这段共 5 行注释。'
  ].join('\n');
  const claims = extractClaims(text, 'docs/a.md', { modules: MODULES });
  const locs = claims.filter((c) => c.kind === 'loc');
  assert.strictEqual(locs.length, 1, '应只抽 1 条 loc，实际=' + JSON.stringify(claims.map((c) => c.kind + ':' + c.value.raw)));
  assert.strictEqual(locs[0].value.number, 654);
  assert.ok(/ML-KEM-768/.test(locs[0].locPrefix), 'locPrefix 应含数字前的文件名上下文');
});

test('resolve: loc 行数核验 verified / drift / ambiguous / unbound 四态', () => {
  const mk = (num, prefix) => ({
    kind: 'loc', key: 'js', keyTokens: ['js'], file: 'docs/a.md', line: 1,
    value: { type: 'scalar', raw: num + ' 行', number: num, unit: '行', dim: 'loc', base: num },
    locPrefix: prefix
  });
  // 真实案例：fibemate-core README 称 654 行，实测 841 行
  const index = { fileLines: [['src/kem/ml-kem-768.js', 841]] };
  const drift = resolveClaim(mk(654, '| **ML-KEM-768** | FIPS 203 | 自研纯 JS（'), index, {});
  assert.strictEqual(drift.status, 'drift', '654 vs 841 应判漂移');
  assert.strictEqual(drift.best.value.number, 841);

  const ok = resolveClaim(mk(820, 'ml-kem-768.js 自研纯 JS（'), index, {});
  assert.strictEqual(ok.status, 'verified', '820 vs 841 在 ±5% 容差内应核验通过');

  const ub = resolveClaim(mk(654, '自研纯 JS 实现（'), index, {});
  assert.strictEqual(ub.status, 'unbound', '窗口内无文件名主干应未绑定');

  const idx2 = { fileLines: [['a/kyber-core.js', 100], ['b/kyber-core.js', 200]] };
  const amb = resolveClaim(mk(500, 'kyber-core.js 实现（'), idx2, {});
  assert.strictEqual(amb.status, 'ambiguous', '两个候选都不符应判歧义');
});

test('resolve: loc 远距离提及不绑定（防误报）', () => {
  const mk = (num, prefix) => ({
    kind: 'loc', key: 'js', keyTokens: ['js'], file: 'docs/a.md', line: 1,
    value: { type: 'scalar', raw: num + ' 行', number: num, unit: '行', dim: 'loc', base: num },
    locPrefix: prefix
  });
  // 文件名距数字超过 60 个有效字符 → 不绑
  // 注：距离在 squash 后的串上度量（CJK 不参与），故用 ASCII 填充构造距离
  const far = 'ml-kem-768.js ' + 'x'.repeat(70) + ' end';
  const index = { fileLines: [['src/kem/ml-kem-768.js', 841]] };
  const r = resolveClaim(mk(654, far), index, {});
  assert.strictEqual(r.status, 'unbound', '距数字太远的文件名不应绑定，实际=' + r.status);
});

// ---------- 跨文档互证 ----------

test('crossDoc: 同键不同值聚类，通用键 / 短键 / 单文件过滤', () => {
  const { crossDocCheck } = require('../src/core/crossdoc');
  const mkScalar = (file, key, num, dim) => ({
    kind: 'kv', file, line: 1, key, keyTokens: [key], module: 'M',
    value: { type: 'scalar', raw: String(num), number: num, dim: dim || null, base: num }
  });
  const out = crossDocCheck([
    // p95 两文档差 48.65 倍 → warn
    mkScalar('a.md', 'p95', 204.97, 'time'),
    mkScalar('b.md', 'p95', 9971.14, 'time'),
    // 同值不聚类
    mkScalar('c.md', 'kat', 10000),
    mkScalar('d.md', 'kat', 10000),
    // 通用键 max 过滤
    mkScalar('e.md', 'max', 1),
    mkScalar('f.md', 'max', 999),
    // 单字符键 q 过滤
    mkScalar('g.md', 'q', 3329),
    mkScalar('h.md', 'q', 8380417),
    // 同一文件内的两个值不聚类
    mkScalar('i.md', 'wns', 9.755, 'time'),
    mkScalar('i.md', 'wns', 0.204, 'time'),
    // 小倍数差 → info
    mkScalar('j.md', 'latency', 100, 'time'),
    mkScalar('k.md', 'latency', 150, 'time')
  ], { warnRatio: 10 });
  const keys = out.map((g) => g.key);
  const p95 = out.find((g) => g.key === 'p95');
  assert.ok(p95, 'p95 簇应存在；实际 keys=' + keys.join(','));
  assert.strictEqual(p95.severity, 'warn');
  assert.strictEqual(p95.distinctValues, 2);
  assert.strictEqual(out.find((g) => g.key === 'latency').severity, 'info', '1.5 倍差应只记 info');
  assert.ok(keys.indexOf('kat') < 0, '同值不聚类');
  assert.ok(keys.indexOf('max') < 0, '通用键应过滤');
  assert.ok(keys.indexOf('q') < 0, '单字符键应过滤');
  assert.ok(keys.indexOf('wns') < 0, '单文件不聚类');
});

// ---------- 运行 ----------

(async function main() {
  let pass = 0;
  const failures = [];
  for (const t of tests) {
    try {
      await t.fn();
      pass++;
      process.stdout.write('  PASS  ' + t.name + '\n');
    } catch (e) {
      failures.push({ name: t.name, err: e });
      process.stdout.write('  FAIL  ' + t.name + '\n        ' + (e && e.message) + '\n');
    }
  }
  process.stdout.write('\n' + pass + '/' + tests.length + ' passed\n');
  if (failures.length) process.exit(1);
})();
