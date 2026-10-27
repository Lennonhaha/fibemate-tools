#!/usr/bin/env node
'use strict';
/*
 * contract.test.js —— 检测器自身的契约测试（不依赖任何外部库）
 *
 * 三个问题，缺一不可：
 *   1) 假阳性：完全合规的密码学代码必须零报告；
 *   2) 真阳性：编造的 noble / WebCrypto API 必须被点名；
 *   3) 门禁能不能变红：把检测逻辑故意改坏，上面的断言必须失败。
 *
 * 第 3 条是本文件的重点。一个永远不会失败的测试等于没有测试，
 * 所以每次运行都会在临时目录里造三个「坏掉的检测器」，验证契约确实会红。
 *
 * 运行：node test/contract.test.js [--json]
 * 退出码：0 = 全部通过；1 = 契约失败或门禁无法变红；2 = 用法错误
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const FIXTURES = path.join(__dirname, 'fixtures');

const results = [];
function check(name, fn) {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail: detail || '' });
    console.log(`PASS ${name}  [${detail || 'ok'}]`);
  } catch (err) {
    results.push({ name, ok: false, detail: err.message });
    console.log(`FAIL ${name}  [${err.message}]`);
  }
}

function loadDetector(dir) {
  return require(path.join(dir, 'index.js'));
}

function readFixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name), 'utf8');
}

// 证据：对给定检测器实现的四个可观察事实。契约断言全部建立在这四个数上，
// 而不是「跑完没抛异常」这种自我安慰。
function evidence(detector) {
  const compliant = detector.analyzeFile(readFixture('compliant-noble.js'), 'compliant-noble.js');
  const fabricated = detector.analyzeFile(readFixture('fabricated-api.js'), 'fabricated-api.js');
  const bad = detector.analyzeFile(fs.readFileSync(path.join(__dirname, 'sample.bad.js'), 'utf8'), 'sample.bad.js');
  return {
    compliantFindings: compliant.constantTime.findings.length + compliant.apiMisuse.suspects.length,
    fabricatedApis: fabricated.apiMisuse.suspects.map((s) => s.api),
    badPatterns: bad.constantTime.findings.map((f) => f.pattern),
    badApi: bad.apiMisuse.suspects.map((s) => s.api),
  };
}

function assertCleanCompliant(e) {
  if (e.compliantFindings !== 0) throw new Error(`compliant code produced ${e.compliantFindings} finding(s)`);
}
function assertFabricatedFlagged(e) {
  const need = ['noble.mlkem', 'crypto.subtle.mlkem', 'noble.sha3', 'secretbox.open'];
  const missing = need.filter((n) => !e.fabricatedApis.some((a) => a.includes(n)));
  if (missing.length) throw new Error('not flagged: ' + missing.join(', '));
}
function assertBadFlagged(e) {
  if (!e.badPatterns.includes('secret-dependent-branch')) throw new Error('bad sample lost secret-dependent-branch');
  if (!e.badApi.some((a) => /noble\.kem/i.test(a))) throw new Error('bad sample lost the noble.kem suspect');
}

const detector = loadDetector(SRC);
const base = evidence(detector);

check('false-positive: compliant noble/WebCrypto code is clean', () => {
  assertCleanCompliant(base);
  return '0 findings';
});

check('true-positive: fabricated APIs are named', () => {
  assertFabricatedFlagged(base);
  return base.fabricatedApis.join(', ');
});

check('true-positive: the bad sample still trips the high patterns', () => {
  assertBadFlagged(base);
  return base.badPatterns.join(', ');
});

// ---- 变异自检：门禁必须能红 ----------------------------------------------
function mutate(label, file, from, to, contract) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hd-mut-'));
  for (const f of fs.readdirSync(SRC)) {
    if (f.endsWith('.js')) fs.copyFileSync(path.join(SRC, f), path.join(dir, f));
  }
  const target = path.join(dir, file);
  const src = fs.readFileSync(target, 'utf8');
  const mutated = src.replace(from, to);
  if (mutated === src) throw new Error(`mutation "${label}" did not apply to ${file}`);
  fs.writeFileSync(target, mutated, 'utf8');

  const mutatedEvidence = evidence(loadDetector(dir));
  let wentRed = false;
  let why = '';
  try {
    contract(mutatedEvidence);
  } catch (err) {
    wentRed = true;
    why = err.message;
  }
  fs.rmSync(dir, { recursive: true, force: true });
  if (!wentRed) throw new Error(`gate stayed green under "${label}"`);
  return `${label} -> ${why}`;
}

check('gate can fail: constant-time detector reports nothing', () =>
  mutate('M1 constant-time suppresses findings', 'constant-time.js',
    'const suspicious = scanPatterns(scan).filter((f) =>',
    'const suspicious = scanPatterns(scan).filter((f) => false &&',
    assertBadFlagged));

check('gate can fail: api whitelist swallows the suspects', () =>
  mutate('M2 api suspects disabled', 'api-misuse.js',
    'const SUSPECT_PATTERNS = [',
    'const SUSPECT_PATTERNS = []; const DISABLED_SUSPECTS = [',
    assertFabricatedFlagged));

check('gate can fail: pattern scanner returns nothing', () =>
  mutate('M3 patterns disabled', 'pattern-scanner.js',
    'const PATTERNS = [',
    'const PATTERNS = []; const DISABLED_PATTERNS = [',
    assertBadFlagged));

// ---- CLI 行为 -------------------------------------------------------------
function cli(args) {
  const r = spawnSync(process.execPath, [path.join(SRC, 'cli.js'), ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

check('cli: compliant fixture passes --fail-on high', () => {
  const r = cli([path.join(FIXTURES, 'compliant-noble.js'), '.', '--fail-on', 'high']);
  if (r.code !== 0) throw new Error(`exit ${r.code}: ${r.err.trim().slice(0, 200)}`);
  return 'exit 0';
});

check('cli: fabricated fixture fails --fail-on medium', () => {
  const r = cli([path.join(FIXTURES, 'fabricated-api.js'), '.', '--fail-on', 'medium']);
  if (r.code !== 1) throw new Error(`expected exit 1, got ${r.code}`);
  if (!/\[fail-on\]/.test(r.err)) throw new Error('no fail-on message');
  return 'exit 1 with fail-on message';
});

const failed = results.filter((r) => !r.ok);
const summary = { total: results.length, passed: results.length - failed.length, failed: failed.length };
if (process.argv.includes('--json')) console.log(JSON.stringify(summary));
console.log(`\n${summary.passed}/${summary.total} checks passed`);
process.exit(failed.length ? 1 : 0);
