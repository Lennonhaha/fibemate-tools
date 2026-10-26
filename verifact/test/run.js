'use strict';
// SPDX-License-Identifier: Apache-2.0

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { compilePatterns } = require('../src/core/walk');
const { extractClaims } = require('../src/core/claims');
const { buildDispositionScopes, DispositionError } = require('../src/core/dispositions');
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
  assert.strictEqual(report.schema, 'verifact-report/2');

  const soft = await engine.run(Object.assign({}, cfg, { gate: { failOn: 'none' } }), {});
  assert.strictEqual(soft.gate.failed, false, 'policy=none 时不应失败');
});

test('history.diff: 识别新增 / 消除的 drift（键为 stableKey）', () => {
  const A = { states: { 'a.md:ratio:kat:aaaaaaaaaaaa': 'drift', 'b.md:kv:p95:bbbbbbbbbbbb': 'verified', 'c.md:ratio:tvla:cccccccccccc': 'verified' } };
  const B = { states: { 'a.md:ratio:kat:aaaaaaaaaaaa': 'verified', 'b.md:kv:p95:bbbbbbbbbbbb': 'drift', 'd.md:count:samples:dddddddddddd': 'drift' } };
  const d = diffRuns(A, B);
  assert.strictEqual(d.newDrift.length, 2, 'p95 由 verified 退化为 drift，samples 新增');
  assert.strictEqual(d.resolvedDrift.length, 1, 'kat 已修复');
  assert.strictEqual(d.resolvedDrift[0].key, 'a.md:ratio:kat:aaaaaaaaaaaa');
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

// ---------- 配置基准目录 / deny ----------

test('config: 相对 root 以配置文件目录为基准，不随 cwd 漂移', () => {
  const os = require('os');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'verifact-base-'));
  const cfgDir = path.join(base, 'cfg');
  const docDir = path.join(base, 'docroot');
  fs.mkdirSync(cfgDir, { recursive: true });
  fs.mkdirSync(docDir, { recursive: true });
  fs.writeFileSync(path.join(docDir, 'a.md'), '# a\n', 'utf8');
  const cfgFile = path.join(cfgDir, 'verifact.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ docs: { roots: ['../docroot'] }, artifacts: { roots: ['../docroot'] } }), 'utf8');

  // 故意从一个与配置无关的 cwd 加载
  const cfg = loadConfig({ cwd: FIX, configPath: cfgFile });
  assert.strictEqual(cfg.__baseDir, cfgDir, '__baseDir 应是配置文件目录');
  const listed = engine.listDocFiles(cfg);
  assert.strictEqual(listed.files.length, 1, 'root 应解析到 ../docroot，实际=' + JSON.stringify(listed.files.map((f) => f.full)));
  assert.deepStrictEqual(listed.missing, [], '不应有落空的 root');
  fs.rmSync(base, { recursive: true, force: true });
});

test('deny: 命中 file+key 改为拒绑，仍留在声明总数里且不进门禁', async () => {
  const cfg = loadConfig({
    cwd: FIX,
    overrides: {
      docs: { roots: ['docs'], exclude: ['**/node_modules/**'], maxFiles: 200 },
      artifacts: { roots: ['artifacts'], exclude: ['**/node_modules/**'], maxFiles: 500 },
      modules: ['ML-KEM-768', 'SM2'],
      cache: { enabled: false },
      gate: { failOn: 'drift' },
      ignore: [],
      deny: [{ file: '**/docs/report.md', key: 'p95', kind: 'kv', note: '测试：该行绑错了产出物' }]
    }
  });
  const report = await engine.run(cfg, {});
  const p95 = report.claims.find((c) => c.key === 'p95');
  assert.ok(p95, '声明应仍存在');
  assert.strictEqual(p95.status, 'denied', '应判 denied，实际=' + p95.status);
  assert.ok(/绑错了产出物/.test(p95.note), 'note 应带出理由，实际=' + p95.note);
  assert.strictEqual(report.counts.denied >= 1, true, '应有 denied 计数');
  assert.strictEqual(report.claims.some((c) => c.status === 'drift' && c.key === 'p95'), false, 'p95 不应再算 drift');
});


test('reference: 标准编号单列计数，不进判定也不进覆盖率分母', async () => {
  const root = tmpProject({
    'doc.md': [
      '# 合规',
      '- 遵循 NIST FIPS 203/205 标准',
      '当前实现 keygen = 103µs'
    ].join('\n')
  });
  const report = await engine.run(dispConfig(root), {});
  const ref = report.claims.find((c) => c.status === 'reference');
  assert.ok(ref, '应有 status=reference 的声明，实际=' + JSON.stringify(report.claims.map((c) => [c.key, c.status])));
  assert.ok(/standard-prefix/.test(ref.note), 'note 应带原因，实际=' + ref.note);
  assert.strictEqual(report.counts.standardRefs, 1, '应计数 1 条标准编号，实际=' + report.counts.standardRefs);
  assert.strictEqual(report.counts.claims, 1, '只有 keygen 进入判定，实际=' + report.counts.claims);
  assert.strictEqual(report.counts.codeArtifactClaims, 1, '分母不应包含标准编号');
  assert.strictEqual(report.counts.allJudgedClaims, 1, '受判总数也不应包含标准编号');
  assert.strictEqual(report.counts.drift, 0, '不得产生漂移');
  // 报告的书面输出要能看到这一条，否则就是「静默删掉」
  const text = require('../bin/verifact').renderText(report, 3);
  assert.ok(/标准编号\s+1/.test(text), '报告应单列标准编号条数，实际=\n' + text);
  fs.rmSync(root, { recursive: true, force: true });
});

// ---------- 处置分类（dispositions，RFC docs/rfc-verifact-dispositions.md） ----------

const os = require('os');

function tmpProject(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifact-disp-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return root;
}

function dispConfig(root, extra) {
  return loadConfig({
    cwd: root,
    overrides: Object.assign({
      docs: { roots: ['.'], exclude: ['**/node_modules/**'], maxFiles: 50 },
      artifacts: { roots: ['.'], exclude: ['**/node_modules/**'], maxFiles: 50 },
      modules: ['ML-KEM-768', 'SM2'],
      cache: { enabled: false },
      gate: { failOn: 'drift' },
      ignore: [],
      deny: []
    }, extra || {})
  });
}

function expectDispositionError(fn, pattern) {
  let threw = null;
  try { fn(); } catch (e) { threw = e; }
  assert.ok(threw, '应当抛错，但没有');
  assert.strictEqual(threw.name, 'DispositionError', '错误类型应为 DispositionError，实际=' + threw.name + '：' + threw.message);
  assert.ok(pattern.test(threw.message), '错误信息应匹配 ' + pattern + '，实际=' + threw.message);
}

test('disposition: 区域内声明一次 owner，区域内单条 progress 可以省略 owner', () => {
  const text = [
    '<!-- verifact: begin disposition=progress owner=docs/CHECKLIST.md -->',
    '| 合计 | 199/199 | ✅ |',
    '| 元数据 | 8/10 | <!-- verifact: disposition=progress --> |',
    '<!-- verifact: end -->'
  ].join('\n');
  const scopes = buildDispositionScopes(text, 'docs/a.md');
  const first = scopes.resolve(2);
  assert.strictEqual(first.disposition, 'progress');
  assert.strictEqual(first.source, 'region');
  assert.strictEqual(first.args.owner, 'docs/CHECKLIST.md');
  const second = scopes.resolve(3);
  assert.strictEqual(second.source, 'inline');
  assert.strictEqual(second.args.owner, 'docs/CHECKLIST.md', 'owner 应从区域继承');
});

test('disposition: 区域里的单条声明不能借用区域以外的参数（artifact 不可继承）', () => {
  const text = [
    '<!-- verifact: begin disposition=measured-once artifact=docs/bench.json -->',
    '| keygen | 103µs | <!-- verifact: disposition=measured-once --> |',
    '<!-- verifact: end -->'
  ].join('\n');
  expectDispositionError(() => buildDispositionScopes(text, 'docs/a.md'), /必须声明 artifact=/);
});

test('disposition: progress 缺 owner 必须报错，不允许无主数字', () => {
  expectDispositionError(
    () => buildDispositionScopes('| 合计 | 199/199 | <!-- verifact: disposition=progress -->\n', 'docs/a.md'),
    /progress 必须声明 owner=/
  );
});

test('disposition: 未知取值报错，不退化成默认值', () => {
  expectDispositionError(
    () => buildDispositionScopes('<!-- verifact: begin disposition=narrativ why="typo" -->\n<!-- verifact: end -->\n', 'docs/a.md'),
    /未知 disposition="narrativ"/
  );
});

test('disposition: begin 没有 end 报错（不允许延伸到文件末尾）', () => {
  expectDispositionError(
    () => buildDispositionScopes('<!-- verifact: begin disposition=narrative why="x" -->\n103µs\n', 'docs/a.md'),
    /没有配对的 end/
  );
});

test('disposition: end 没有 begin 报错', () => {
  expectDispositionError(
    () => buildDispositionScopes('103µs\n<!-- verifact: end -->\n', 'docs/a.md'),
    /end 没有对应的 begin/
  );
});

test('disposition: 不允许嵌套不同 disposition', () => {
  const text = [
    '<!-- verifact: begin disposition=progress owner=x.md -->',
    '<!-- verifact: begin disposition=narrative why="y" -->',
    '<!-- verifact: end -->',
    '<!-- verifact: end -->'
  ].join('\n');
  expectDispositionError(() => buildDispositionScopes(text, 'docs/a.md'), /不允许嵌套不同 disposition/);
});

test('disposition: code-artifact 不接受参数（防止用声明伪装成默认值）', () => {
  expectDispositionError(
    () => buildDispositionScopes('<!-- verifact: disposition=code-artifact owner=x.md -->\n', 'docs/a.md'),
    /code-artifact 不接受参数/
  );
});

test('disposition: 引号内的空格保留（why="a b c"）', () => {
  const scopes = buildDispositionScopes('<!-- verifact: disposition=narrative why="LLL and BKZ snapshot" -->\n40 行\n', 'docs/a.md');
  const d = scopes.resolve(2);
  assert.strictEqual(d.disposition, 'narrative');
  assert.strictEqual(d.args.why, 'LLL and BKZ snapshot');
  assert.strictEqual(d.source, 'file');
});

test('disposition: 普通 HTML 注释不被误伤', () => {
  const scopes = buildDispositionScopes('<!-- TODO: 这是普通注释 -->\n103µs\n', 'docs/a.md');
  assert.strictEqual(scopes.hasAny, false);
  assert.strictEqual(scopes.resolve(2).disposition, 'code-artifact');
});

test('disposition: 声明过的数字不进判定，只进 disposition 计数（分母分开）', async () => {
  const root = tmpProject({
    'doc.md': [
      '# 实验快照',
      '<!-- verifact: begin disposition=measured-once artifact=log.txt -->',
      'p95 = 78.5ms',
      '<!-- verifact: end -->',
      '当前实现 keygen = 103µs'
    ].join('\n')
  });
  const report = await engine.run(dispConfig(root), {});
  const measured = report.claims.filter((c) => c.disposition === 'measured-once');
  assert.ok(measured.length >= 1, '应有一条被分类的声明，实际 claims=' + JSON.stringify(report.claims.map((c) => [c.key, c.disposition, c.status])));
  assert.ok(measured.every((c) => c.status === 'disposition'), '被分类的声明不应进入判定');
  assert.strictEqual(report.counts.dispositioned >= 1, true, '应有 dispositioned 计数');
  assert.strictEqual(report.counts.dispositionCounts['measured-once'] >= 1, true, '处置分布应含 measured-once');
  assert.strictEqual(report.counts.codeArtifactClaims + report.counts.dispositioned, report.counts.allJudgedClaims, '双分母应自洽');
  assert.strictEqual(report.counts.claims, report.counts.codeArtifactClaims, 'claims 仍等于进入判定的条数');
  fs.rmSync(root, { recursive: true, force: true });
});

test('deny: 被拒绑的声明不落进 code-artifact 桶，报告两个数必须相等（#102）', async () => {
  const root = tmpProject({
    'doc.md': [
      '# 状态',
      '| p95 | 78.5 ms |',
      '当前实现 keygen = 103µs'
    ].join('\n')
  });
  const report = await engine.run(dispConfig(root, {
    deny: [{ file: '**/doc.md', key: 'p95', kind: 'measure', note: '测试：该行绑错了产出物' }]
  }), {});
  const c = report.counts;
  assert.strictEqual(c.denied, 1, '应有一条被拒绑，实际=' + c.denied);
  assert.strictEqual(c.dispositionCounts['code-artifact'], c.claims,
    'code-artifact 桶应等于进入判定的条数，实际桶=' + c.dispositionCounts['code-artifact'] + ' claims=' + c.claims);
  assert.strictEqual(c.codeArtifactClaims, c.claims, '覆盖率分母应与 claims 同源');
  assert.strictEqual(c.allJudgedClaims, c.codeArtifactClaims + c.dispositioned + c.denied,
    '受判总数 = 判定 + 分类 + 拒绑');

  // 报告的书面输出也不允许两个数各说一套：处置分类行与核验率行必须是同一个分母。
  const text = require('../bin/verifact').renderText(report, 3);
  const bucket = text.match(/处置分类\s+code-artifact\s+(\d+)/);
  const denom = text.match(/\(code-artifact (\d+) 条\)/);
  assert.ok(bucket && denom, '报告应同时打印处置分类与分母，实际=\n' + text);
  assert.strictEqual(bucket[1], denom[1],
    '处置分类 code-artifact 与核验率分母必须是同一个数，实际 ' + bucket[1] + ' vs ' + denom[1]);
  fs.rmSync(root, { recursive: true, force: true });
});

test('disposition: 整份文件都不是 code-artifact 时给出文件级警示', async () => {
  const root = tmpProject({
    'all-narrative.md': [
      '<!-- verifact: disposition=narrative why="设计方案，不是产物属性" -->',
      'k = 8, q = 65537'
    ].join('\n'),
    'mixed.md': [
      '<!-- verifact: begin disposition=progress owner=board.md -->',
      '合计 199/199',
      '<!-- verifact: end -->',
      '当前实现 keygen = 103µs'
    ].join('\n')
  });
  const report = await engine.run(dispConfig(root), {});
  const w = report.counts.dispositionWarnings;
  assert.ok(w, '应输出 dispositionWarnings');
  const files = w.fullyDispositionedFiles.map((f) => f.file);
  assert.strictEqual(files.length, 1, '只有 all-narrative.md 应被列出，实际=' + JSON.stringify(files));
  assert.ok(/all-narrative\.md$/.test(files[0]), '列出的应是 all-narrative.md，实际=' + files[0]);
  assert.strictEqual(w.fullyDispositionedFiles[0].claims >= 1, true, '应带出条数');
  fs.rmSync(root, { recursive: true, force: true });
});

test('disposition: 写错声明让整次运行失败（不允许静默丢文档）', async () => {
  const root = tmpProject({
    'doc.md': '# 状态\n| 合计 | 199/199 | <!-- verifact: disposition=progress -->\n'
  });
  let threw = null;
  try { await engine.run(dispConfig(root), {}); } catch (e) { threw = e; }
  assert.ok(threw, '应当让整次运行失败，但没有');
  assert.ok(/处置声明解析失败/.test(threw.message), '错误信息应指明处置声明解析失败，实际=' + threw.message);
  fs.rmSync(root, { recursive: true, force: true });
});

// ---------- 标准编号不是比值（#101） ----------

test('claims: FIPS 203/205 被认成标准编号，不是命中率', () => {
  const text = '# 合规\n- 密码实现遵循 NIST FIPS 203/205 标准\n';
  const claims = extractClaims(text, 'docs/a.md', { modules: MODULES });
  const r = claims.find((c) => c.kind === 'ratio');
  assert.ok(r, '应抽到一条 ratio 形状的声明，实际=' + JSON.stringify(claims.map((c) => [c.kind, c.value && c.value.raw])));
  assert.strictEqual(r.notMeasurement, 'standard-prefix', '原因应为 standard-prefix，实际=' + r.notMeasurement);
});

test('claims: GB/T、ISO/IEC 与 ePrint 编号同样不当比值', () => {
  const text = [
    '- 遵循 GB/T 32918/32905 规范',
    '- 对齐 ISO/IEC 18033/18032 系列',
    '- 参考文献 ePrint 2025/1986'
  ].join('\n');
  const claims = extractClaims(text, 'docs/a.md', { modules: MODULES });
  const ratios = claims.filter((c) => c.kind === 'ratio');
  assert.ok(ratios.length >= 1, '应抽到比值形状，实际=' + JSON.stringify(claims.map((c) => c.value && c.value.raw)));
  assert.ok(ratios.every((c) => c.notMeasurement),
    '这些必须全部被认成标准编号，实际=' + JSON.stringify(ratios.map((c) => [c.value.raw, c.notMeasurement])));
  const ep = ratios.find((c) => c.value.raw === '2025/1986');
  assert.strictEqual(ep.notMeasurement, 'standard-prefix', 'ePrint 编号应由前缀识别，实际=' + ep.notMeasurement);
});

test('claims: 年份区间 2021/2022 不当比值', () => {
  const claims = extractClaims('# 时间线\n2021/2022 两年间的迁移记录\n', 'docs/a.md', { modules: MODULES });
  const r = claims.filter((c) => c.kind === 'ratio');
  assert.ok(r.length >= 1, '应抽到比值形状');
  assert.strictEqual(r[0].notMeasurement, 'year-pair', '实际=' + r[0].notMeasurement);
});

test('claims: 真正的通过率紧跟着 NIST 字样也不能被误杀（防假阴性）', () => {
  const claims = extractClaims('# 结果\nNIST 测试集通过 10/10\n', 'docs/a.md', { modules: MODULES });
  const r = claims.find((c) => c.kind === 'ratio');
  assert.ok(r, '应抽到 10/10');
  assert.strictEqual(r.notMeasurement, undefined,
    'NIST … 10/10 是真声明，不得被标准名误杀（窗口必须贴着数字）');
});

// ---------- stableKey（内容寻址身份，#96） ----------

const { assignStableKeys, normalizeContext } = require('../src/core/stable-key');

function keysOf(doc, file) {
  const claims = extractClaims(doc, file || 'docs/a.md', { modules: MODULES });
  assignStableKeys(claims);
  return claims;
}

function byKey(claims, key) {
  return claims.filter((c) => c.key === key);
}

test('stableKey: 在声明上方插入一行，身份不变（而 id 会变）', () => {
  const before = ['# 状态', '', '| KAT | 10,000/10,000 |'].join('\n');
  const after = ['# 状态', '', '<!-- 新增的一行说明 -->', '', '| KAT | 10,000/10,000 |'].join('\n');
  const a = byKey(keysOf(before), 'kat')[0];
  const b = byKey(keysOf(after), 'kat')[0];
  assert.ok(a && b, '两次都应抽到 KAT 声明');
  assert.notStrictEqual(a.id, b.id, 'id 含行号，插行后必然改变（这是要修的问题本身）');
  assert.strictEqual(a.stableKey, b.stableKey, 'stableKey 必须不变，实际 ' + a.stableKey + ' vs ' + b.stableKey);
});

test('stableKey: CRLF 与 LF 得到同一个键（Windows 本地与 Actions Linux 必须一致）', () => {
  const lf = ['# 状态', '', '| KAT | 10,000/10,000 |', '| p95 | 78.5ms |'].join('\n');
  const crlf = lf.replace(/\n/g, '\r\n');
  const a = keysOf(lf).map((c) => c.stableKey).sort();
  const b = keysOf(crlf).map((c) => c.stableKey).sort();
  assert.deepStrictEqual(b, a, 'CRLF 与 LF 的身份必须一致');
});

test('stableKey: 行首缩进变化不改变身份', () => {
  const a = byKey(keysOf('| KAT | 10,000/10,000 |'), 'kat')[0];
  const b = byKey(keysOf('    | KAT | 10,000/10,000 |'), 'kat')[0];
  assert.strictEqual(a.stableKey, b.stableKey, '缩进属于排版，不该改身份');
});

test('stableKey: 行尾追加 disposition 注释不改变身份（否则标注动作本身制造假迁移）', () => {
  const plain = '| KAT | 10,000/10,000 |';
  const annotated = '| KAT | 10,000/10,000 | <!-- verifact: disposition=progress owner=board.md -->';
  const a = byKey(keysOf(plain), 'kat')[0];
  const b = byKey(keysOf(annotated), 'kat')[0];
  assert.strictEqual(b.disposition, 'progress', '注释应被处置层识别');
  assert.strictEqual(a.stableKey, b.stableKey, 'stableKey 不该把注释算进上下文');
  assert.strictEqual(normalizeContext(annotated), '| KAT | 10,000/10,000 |', '注释必须被剥掉');
});

test('stableKey: 改数字本身必须换身份（不能拿旧历史冒充同一条）', () => {
  const a = byKey(keysOf('| KAT | 10,000/10,000 |'), 'kat')[0];
  const b = byKey(keysOf('| KAT | 9,999/10,000 |'), 'kat')[0];
  assert.notStrictEqual(a.stableKey, b.stableKey, '值变了就不该复用同一个身份');
});

test('stableKey: 同一文件两条完全相同的声明给两个身份，并有 #2 后缀', () => {
  const doc = ['| KAT | 10,000/10,000 |', '| KAT | 10,000/10,000 |'].join('\n');
  const claims = keysOf(doc);
  assert.strictEqual(claims.length, 2, '应抽到两条，实际 ' + claims.length);
  assert.notStrictEqual(claims[0].stableKey, claims[1].stableKey, '完全相同的两行也必须是两个身份');
  assert.ok(!/#/.test(claims[0].stableKey), '第一条不带后缀，实际 ' + claims[0].stableKey);
  assert.ok(/#2$/.test(claims[1].stableKey), '第二条应带 #2，实际 ' + claims[1].stableKey);
  assert.strictEqual(claims[0].stableKeyGroupSize, 2, '两条都应标记组大小，供报告告警');
  assert.strictEqual(claims[1].stableKeyIndex, 2);
});

test('stableKey: 重复声明的后缀在无关行插入后保持稳定', () => {
  const base = ['| KAT | 10,000/10,000 |', '| KAT | 10,000/10,000 |'];
  const shifted = ['# 标题', ''].concat(base);
  const a = keysOf(base.join('\n')).map((c) => c.stableKey);
  const b = keysOf(shifted.join('\n')).map((c) => c.stableKey);
  assert.deepStrictEqual(b, a, '插入无关行不应让 #2 变成 #1');
});

test('stableKey: normalizeContext 剥注释、压空白、统一换行', () => {
  assert.strictEqual(normalizeContext('  a\tb  \r\nc  '), 'a b c');
  assert.strictEqual(normalizeContext('| K | 1 | <!-- verifact: disposition=narrative why="x" -->'), '| K | 1 |');
  assert.strictEqual(normalizeContext('x\r\ny'), normalizeContext('x\ny'), 'CRLF 与 LF 必须等价');
  assert.strictEqual(normalizeContext('    | K | 1 |'), normalizeContext('| K | 1 |'), '缩进必须被吃掉');
});

test('stableKey: 形状为 file:kind:key:12位十六进制', () => {
  const c = byKey(keysOf('| KAT | 10,000/10,000 |', 'docs/sub/a.md'), 'kat')[0];
  assert.ok(/^docs\/sub\/a\.md:ratio:kat:[0-9a-f]{12}$/.test(c.stableKey), '实际 ' + c.stableKey);
});

// ---------- history schema 2：稳定键与迁移（#96） ----------

const os2 = require('os');
const { readRuns, appendRun, HISTORY_SCHEMA } = require('../src/history');

function projectForHistory(files, extra) {
  const root = tmpProject(files);
  const cfg = loadConfig({
    cwd: root,
    overrides: Object.assign({
      docs: { roots: ['.'], exclude: ['**/node_modules/**'], maxFiles: 20, maxFileBytes: 1048576 },
      artifacts: { roots: ['.'], exclude: ['**/node_modules/**'], maxFiles: 20, maxFileBytes: 1048576 },
      modules: ['ML-KEM-768', 'SM2'],
      cache: { enabled: true, dir: '.verifact', maxHistory: 20 },
      gate: { failOn: 'none' },
      ignore: [],
      deny: [],
      // 用错值做人工绑定：状态恒为 drift —— 既非 unbound，也不依赖产出物
      bindings: [{ kind: 'ratio', expect: '10000/10000' }]
    }, extra || {})
  });
  return { root, cfg };
}

test('history: schema 1 记录被丢弃并计数，不做启发式映射', () => {
  const { root, cfg } = projectForHistory({ 'doc.md': '| KAT | 9,999/10,000 |\n' });
  const dir = path.join(root, '.verifact');
  fs.mkdirSync(dir, { recursive: true });
  const legacy = { generatedAt: '2026-10-01T00:00:00.000Z', counts: {}, states: { 'doc.md:L1:ratio:kat': 'drift' } };
  fs.writeFileSync(path.join(dir, 'history.jsonl'), JSON.stringify(legacy) + '\n', 'utf8');
  const runs = readRuns(cfg, root, 10);
  assert.strictEqual(runs.length, 0, 'schema 1 记录不应被当作可比基准，实际=' + runs.length);
  assert.strictEqual(runs.legacyDropped, 1, '应报告被丢弃的旧记录条数，实际=' + runs.legacyDropped);
  fs.rmSync(root, { recursive: true, force: true });
});

test('history: 在声明上方插入 N 行，diffRuns 产生零迁移（#96 的 DoD）', async () => {
  const base = [
    '| KAT | 9,999/10,000 |',
    '| TVLA | 9,999/10,000 |'
  ].join('\n');
  const shifted = ['# 标题', '', '<!-- 三行新注释之一 -->', '', '<!-- 又一行 -->', '', base].join('\n');
  const { root, cfg } = projectForHistory({ 'doc.md': base });

  const first = await engine.run(cfg, {});
  assert.ok(first.claims.length >= 2, '第一次运行应抽到声明，实际=' + first.claims.length);
  assert.strictEqual(first.claims.every((c) => c.status !== 'unbound'), true, '测试前提：声明必须非 unbound');

  // 在原文件上方插入 6 行（含标题、空行、注释），行号整体位移
  fs.writeFileSync(path.join(root, 'doc.md'), shifted, 'utf8');
  const second = await engine.run(cfg, {});

  const runs = readRuns(cfg, root, 10);
  assert.strictEqual(runs.length, 2, '两次运行都应进历史，实际=' + runs.length);
  assert.strictEqual(runs[0].schema, HISTORY_SCHEMA, '历史记录应标记 schema 2');
  const d = diffRuns(runs[0], runs[1]);
  assert.strictEqual(d.all.length, 0, '插入无关行不应产生任何迁移，实际=' + JSON.stringify(d.all.map((c) => c.key + ' ' + c.from + '->' + c.to)));

  // 对照：如果用行号 id 当键，同一份改动会显示成迁移 —— 证明这条测试有辨别力
  const asIdStates = (r) => { const m = {}; for (const c of r.claims) if (c.status !== 'unbound') m[c.id] = c.status; return m; };
  const byId = diffRuns({ states: asIdStates(first) }, { states: asIdStates(second) });
  assert.ok(byId.all.length > 0, '按行号 id 比对应当出现迁移（否则测试无辨别力）');

  fs.rmSync(root, { recursive: true, force: true });
});

test('stableKey: 同一行写了两次同一个数时，报告列出重复声明', async () => {
  const { root, cfg } = projectForHistory({
    'doc.md': '| KeyGen | 1.58 ms | **2.04 ms** | 1.71 ms | 2.77 ms | 11.77 ms | 11.77 ms | **489/s** |\n'
  });
  const report = await engine.run(cfg, {});
  const dups = report.duplicateClaims || [];
  assert.strictEqual(dups.length, 1, '应报告 1 组重复声明，实际=' + JSON.stringify(dups.map((d) => d.key)));
  assert.strictEqual(dups[0].lines.length, 2, '该组应含两处，实际=' + JSON.stringify(dups[0].lines));
  assert.strictEqual(report.counts.duplicateClaimGroups, 1, '计数应与列表一致');
  fs.rmSync(root, { recursive: true, force: true });
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
