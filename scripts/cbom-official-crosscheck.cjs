#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-official-crosscheck.cjs — 用 CycloneDX 官方实现独立交叉验证 cbom-tools 的产物
//
// 为什么需要：cbom-tools 自带的 schema 测试 = Ajv + 自 vendored 的 bom-1.6.schema.json，
// 属「自己验自己」闭环（自己写的测试只证明「代码按我的理解运行」，不证明「符合标准」）。
// 本脚本引入第二重独立参照 —— CycloneDX 官方实现 @cyclonedx/cyclonedx-library：
//   1) schema 来源独立：断言 vendored schema 与官方库自带副本语义等价
//      （容忍 $ref 文件名里的 SNAPSHOT 标记与 description 文案差异）；
//   2) 装配独立：用官方库的 JsonValidator 重验真产物（现有产物 + 现码新生成）。
// 并含阴性对照：本该失败的样本必须失败，否则「通过」不算数。
// 阴性对照再收紧一层（2026-10-25）：José 的两个非法夹具不仅要「被拒」，还必须以
// **README 写明的那个原因**被拒（keyword + instancePath + 具体违规值）。否则「少个括号/
// 解析失败」也会被当成 schema 门禁生效 —— 另一种假绿。配套两条元自检：
//   a) 校验器抛错不得计为「正确拒绝」（基础设施故障 ≠ 判定）；
//   b) 把诊断条件故意写错后，必须匹配不上 —— 防「断言恒真」。
//
// 注意：官方库由 CI ad-hoc 安装，**不是本仓依赖** —— cbom-tools 对外宣称
// "Zero external dependencies"，本脚本只在验证时用库，不给包引入依赖。
//
// 用法：
//   NODE_PATH=<装有官方库的 node_modules> node scripts/cbom-official-crosscheck.cjs
//
// 退出码：0 = 全部如预期；1 = 有断言不符（含「本该失败却通过」的对照）；2 = 环境缺失。

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');

const REPO = path.resolve(__dirname, '..');
const CBOM = path.join(REPO, 'cbom-tools');
const FIXTURES = path.join(CBOM, 'test', 'fixtures');
const VENDORED_SCHEMA = path.join(FIXTURES, 'bom-1.6.schema.json');

const rows = [];
let failures = 0;

function record(label, ok, detail) {
  rows.push([label, ok ? 'OK' : 'FAIL', detail || '']);
  if (!ok) failures += 1;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function loadOfficial() {
  let mainPath;
  try {
    mainPath = require.resolve('@cyclonedx/cyclonedx-library');
  } catch (e) {
    console.error('[xcheck] 官方库未安装：' + e.message);
    console.error('[xcheck] 需要 NODE_PATH 指向装有 @cyclonedx/cyclonedx-library 的 node_modules。');
    process.exit(2);
  }
  let dir = path.dirname(mainPath);
  let libRoot = null;
  for (let i = 0; i < 8 && dir; i += 1) {
    const pj = path.join(dir, 'package.json');
    if (fs.existsSync(pj)) {
      try {
        const j = JSON.parse(fs.readFileSync(pj, 'utf8'));
        if (j.name === '@cyclonedx/cyclonedx-library') { libRoot = dir; break; }
      } catch (_) { /* keep walking */ }
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  if (!libRoot) {
    console.error('[xcheck] 已解析到包入口但定位不到 @cyclonedx/cyclonedx-library 的 package.json');
    process.exit(2);
  }
  for (const dep of ['ajv', 'ajv-formats', 'ajv-formats-draft2019']) {
    try { require.resolve(dep); } catch (e) {
      console.error('[xcheck] 官方库的 JSON 校验可选依赖缺失：' + dep + '（官方库把 JSON 校验委托给 ajv）');
      process.exit(2);
    }
  }
  const lib = require('@cyclonedx/cyclonedx-library');
  if (!lib.Spec || !lib.Spec.Spec1dot6 || !lib.Validation || !lib.Validation.JsonValidator) {
    console.error('[xcheck] 官方库导出不符合预期（需要 Spec.Spec1dot6 + Validation.JsonValidator）');
    process.exit(2);
  }
  const libVersion = JSON.parse(fs.readFileSync(path.join(libRoot, 'package.json'), 'utf8')).version;
  const validator = new lib.Validation.JsonValidator(lib.Spec.Spec1dot6.version, lib.Spec.Spec1dot6);
  return { libVersion, libRoot, validator };
}

// 官方库把 $ref 指向 spdx.SNAPSHOT.schema.json / jsf-0.82.SNAPSHOT.schema.json，
// 发布版 schema 指向 spdx.schema.json / jsf-0.82.schema.json —— 归一化后再比对。
function stripSnapshotRefs(node) {
  if (Array.isArray(node)) return node.map(stripSnapshotRefs);
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = (k === '$ref' && typeof v === 'string') ? v.replace(/SNAPSHOT\./g, '') : stripSnapshotRefs(v);
    }
    return out;
  }
  return node;
}

function walkDiff(x, y, p, acc) {
  if (typeOf(x) !== typeOf(y)) { acc.push([p, JSON.stringify(x).slice(0, 60), JSON.stringify(y).slice(0, 60)]); return acc; }
  if (x && typeof x === 'object') {
    const keys = Array.from(new Set([...Object.keys(x), ...Object.keys(y)])).sort();
    for (const k of keys) {
      if (!(k in x)) acc.push([p + '/' + k, '<absent>', JSON.stringify(y[k]).slice(0, 60)]);
      else if (!(k in y)) acc.push([p + '/' + k, JSON.stringify(x[k]).slice(0, 60), '<absent>']);
      else walkDiff(x[k], y[k], p + '/' + k, acc);
    }
    return acc;
  }
  if (x !== y) acc.push([p, JSON.stringify(x).slice(0, 60), JSON.stringify(y).slice(0, 60)]);
  return acc;
}

function typeOf(v) {
  if (Array.isArray(v)) return 'array';
  if (v === null) return 'null';
  return typeof v;
}

// 官方 JsonValidator：合法返回 null，非法返回 Ajv 错误数组，自身故障则抛错。
async function runValidator(validator, text) {
  try {
    const err = await validator.validate(text);
    if (err === null || err === undefined) return { threw: null, errors: [] };
    return { threw: null, errors: Array.isArray(err) ? err : [err] };
  } catch (e) {
    return { threw: e, errors: [] };
  }
}

// 判定与取值分离，便于对「抛错」这一情形做纯函数自检。
function judge(run, expectValid) {
  if (run.threw) {
    return {
      ok: false,
      valid: false,
      detail: 'validator threw (infrastructure failure, not a verdict): ' +
        String(run.threw && run.threw.message).slice(0, 140),
    };
  }
  const errors = run.errors || [];
  const valid = errors.length === 0;
  return {
    ok: valid === expectValid,
    valid,
    detail: (valid ? 'VALID' : 'INVALID') + (errors.length ? ' | ' + JSON.stringify(errors).slice(0, 200) : ''),
  };
}

async function validateText(validator, text, label, expectValid) {
  const v = judge(await runValidator(validator, text), expectValid);
  record(label, v.ok, v.detail);
  return v.valid;
}

function summarizeError(e) {
  return String((e && e.instancePath) || '/') + ' ' + String((e && e.keyword) || '?') +
    ' : ' + String((e && e.message) || '').slice(0, 80);
}

// 期望的诊断必须在同一批错误里被逐项命中（不是「有一个错误就算」）。
function matchesDiagnostic(errors, spec) {
  return (errors || []).some((e) => {
    if (!e || typeof e !== 'object') return false;
    if (spec.keyword && e.keyword !== spec.keyword) return false;
    if (spec.pathSuffix && !String(e.instancePath || '').endsWith(spec.pathSuffix)) return false;
    if (spec.messageIncludes && !String(e.message || '').includes(spec.messageIncludes)) return false;
    if (spec.additionalProperty && !(e.params && e.params.additionalProperty === spec.additionalProperty)) return false;
    if (spec.allowedValuesInclude &&
      !(e.params && Array.isArray(e.params.allowedValues) && e.params.allowedValues.includes(spec.allowedValuesInclude))) return false;
    return true;
  });
}

function scanTo(dir, outFile) {
  const r = cp.spawnSync(process.execPath, [path.join(CBOM, 'cbom-scan.cjs'), '--dir', dir, '--out', outFile], { encoding: 'utf8' });
  return { status: r.status, stderr: (r.stderr || '').trim().slice(0, 200) };
}

function mutate(base, fn) {
  const copy = JSON.parse(JSON.stringify(base));
  fn(copy);
  return JSON.stringify(copy);
}

(async () => {
  const { libVersion, libRoot, validator } = loadOfficial();
  console.log('official: @cyclonedx/cyclonedx-library@' + libVersion + '  (spec 1.6)');
  console.log('repo:     ' + REPO);
  console.log('');

  // --- 0) 元自检：校验器崩溃不得被记成「正确拒绝」---
  {
    const v = judge({ threw: new Error('injected validator crash'), errors: [] }, false);
    record('self-check: validator crash must not count as a rejection', v.ok === false,
      'judge() on a throw → ok=' + v.ok + ' (must be false)');
  }

  // --- 1) schema 来源独立 ---
  const schemaDir = path.join(libRoot, 'res', 'schema');
  const libSchema = fs.existsSync(schemaDir)
    ? fs.readdirSync(schemaDir).filter((f) => /^bom-1\.6.*\.schema\.json$/.test(f)).map((f) => path.join(schemaDir, f))[0]
    : null;
  if (!libSchema) {
    record('schema equivalence', false, '官方库未提供 bom-1.6 schema（res/schema 缺失）');
  } else {
    const a = stripSnapshotRefs(JSON.parse(fs.readFileSync(libSchema, 'utf8')));
    const b = stripSnapshotRefs(JSON.parse(fs.readFileSync(VENDORED_SCHEMA, 'utf8')));
    const diffs = walkDiff(a, b, '', []);
    const nonDesc = diffs.filter((d) => !/\/description$/.test(d[0]));
    record(
      'schema: vendored vs official (modulo $ref SNAPSHOT + description)',
      nonDesc.length === 0,
      'sha256(vendored)=' + sha256(VENDORED_SCHEMA).slice(0, 16) +
      ' diffs=' + diffs.length + ' non-description=' + nonDesc.length +
      (nonDesc.length ? ' first=' + nonDesc[0][0] : '')
    );
  }

  // --- 2) 真产物 ---
  const artifact = path.join(CBOM, 'cbom-cyclonedx.json');
  const artifactText = fs.readFileSync(artifact, 'utf8');
  const artifactJson = JSON.parse(artifactText);
  await validateText(validator, artifactText, 'committed cbom-cyclonedx.json (' + (artifactJson.components || []).length + ' components)', true);
  console.log('note: committed artifact metadata.tool = ' + JSON.stringify(artifactJson.metadata && artifactJson.metadata.tools));

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-xcheck-'));
  const freshRepo = path.join(tmp, 'fresh-repo.json');
  const r1 = scanTo(REPO, freshRepo);
  if (r1.status === 0 && fs.existsSync(freshRepo)) {
    const t = fs.readFileSync(freshRepo, 'utf8');
    const n = (JSON.parse(t).components || []).length;
    await validateText(validator, t, 'fresh scan of this repository (' + n + ' components)', true);
  } else {
    record('fresh scan of this repository', false, 'scan failed: ' + JSON.stringify(r1));
  }

  const freshFix = path.join(tmp, 'fresh-fixture.json');
  const r2 = scanTo(path.join(FIXTURES, 'jose-regression'), freshFix);
  if (r2.status === 0 && fs.existsSync(freshFix)) {
    await validateText(validator, fs.readFileSync(freshFix, 'utf8'), 'fresh scan of test/fixtures/jose-regression', true);
  } else {
    record('fresh scan of test/fixtures/jose-regression', false, 'scan failed: ' + JSON.stringify(r2));
  }

  // --- 3) 阴性对照：本该失败必须失败 ---
  await validateText(validator, mutate(artifactJson, (o) => {
    const c = (o.components || []).find((x) => x.cryptoProperties && x.cryptoProperties.algorithmProperties);
    if (c) c.cryptoProperties.algorithmProperties.primitive = 'HASH';
  }), 'control: primitive "HASH" (uppercase) must be rejected', false);

  await validateText(validator, mutate(artifactJson, (o) => {
    if (o.components && o.components[0]) delete o.components[0].type;
  }), 'control: component without "type" must be rejected', false);

  // 已核事实：1.6 schema 里 specVersion 是普通 string（非 const/enum），故这一对照「预期通过」。
  // 保留它是为了把「schema 层不校验 specVersion」写成显式断言，防止误当作被校验。
  await validateText(validator, mutate(artifactJson, (o) => { o.specVersion = '9.9'; }),
    'control: specVersion "9.9" is NOT constrained by the 1.6 schema (documented)', true);

  // --- 4) José 三回归夹具（CycloneDX 1.6 standalone）---
  // 期望值出处：cbom-tools/test/fixtures/jose-regression/README.md
  //   invalid-uppercase-primitive.json → 大小写敏感的 primitive enum 违规
  //   invalid-misplaced-field.json     → cryptoProperties 下的多余属性
  // 故断言落到 keyword + instancePath + 具体违规值，而非「结果为 invalid / 退出码非零」。
  const JOSE_CASES = [
    { file: 'valid-sha256.json', expectValid: true },
    {
      file: 'invalid-uppercase-primitive.json',
      expectValid: false,
      diagnostic: {
        keyword: 'enum',
        pathSuffix: '/cryptoProperties/algorithmProperties/primitive',
        messageIncludes: 'must be equal to one of the allowed values',
        allowedValuesInclude: 'hash',
      },
    },
    {
      file: 'invalid-misplaced-field.json',
      expectValid: false,
      diagnostic: {
        keyword: 'additionalProperties',
        pathSuffix: '/cryptoProperties',
        messageIncludes: 'must NOT have additional properties',
        additionalProperty: 'implementationPlatform',
      },
    },
  ];
  const jose = path.join(FIXTURES, 'jose-regression');
  if (!fs.existsSync(jose)) {
    record('jose fixtures dir', false, 'missing: ' + jose);
  } else {
    for (const c of JOSE_CASES) {
      const p = path.join(jose, c.file);
      const label = 'jose fixture: ' + c.file;
      if (!fs.existsSync(p)) { record(label, false, 'missing'); continue; }
      const frag = JSON.parse(fs.readFileSync(p, 'utf8'));
      const wrapped = frag.bomFormat ? frag : { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [frag] };
      if (c.expectValid) { await validateText(validator, JSON.stringify(wrapped), label, true); continue; }

      const run = await runValidator(validator, JSON.stringify(wrapped));
      if (run.threw) {
        record(label, false, 'validator threw (infrastructure failure, not a verdict): ' +
          String(run.threw.message).slice(0, 140));
        continue;
      }
      if (run.errors.length === 0) { record(label, false, 'expected rejection, but the sample validated'); continue; }

      const hit = matchesDiagnostic(run.errors, c.diagnostic);
      record(label, hit,
        (hit ? 'rejected for the documented reason | ' : 'rejected, but NOT for the documented reason | ') +
        summarizeError(run.errors[0]));

      // 元自检：把诊断条件故意写错（只改 keyword），同一批真实错误必须匹配不上。
      // 若这条变绿，说明 matchesDiagnostic 恒真，上面那条断言等于没写。
      const wrongSpec = Object.assign({}, c.diagnostic, {
        keyword: c.diagnostic.keyword === 'enum' ? 'type' : 'enum',
      });
      record('  ^ self-check: wrong diagnostic spec must not match',
        matchesDiagnostic(run.errors, wrongSpec) === false, 'mutated keyword=' + wrongSpec.keyword);
    }
  }

  // --- 报告 ---
  console.log('');
  const width = Math.max(...rows.map((r) => r[0].length));
  for (const [label, status, detail] of rows) {
    console.log('  ' + label.padEnd(width) + '  ' + status + (detail ? '  ' + detail : ''));
  }
  console.log('');
  if (failures === 0) {
    console.log('ALL AS EXPECTED (' + rows.length + ' checks)');
    process.exit(0);
  }
  console.log('FAILURES: ' + failures + ' / ' + rows.length);
  process.exit(1);
})().catch((e) => {
  console.error('[xcheck] unexpected failure: ' + (e && e.stack ? e.stack : String(e)));
  process.exit(1);
});
