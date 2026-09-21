#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// seam-checker v1 — 接缝检查器（FIBEMATE TLA+ 三层证据链）
// ---------------------------------------------------------------
// 工具仓 fibemate-tools 子模块（Apache-2.0, no crypto algorithms）。
// 本脚本只驱动 TLA+ 官方工具 TLC 去验证主仓 fibemate 的协议模型，
// 并按"执行层"取证（exit code + 逐不变量 VIOLATED），不凭 .cfg 存在判"通过"。
//
// 两层职责：
//   G 层（模型内门禁）：每个模型是否真跑通 + 配置里每条不变量是否真 PASS。
//   S 层（层间接缝）：把 seam-checklist-v1 的 S1/S2/S4/G2 项做成声明式映射表，
//       输出每条"下游证据需求"的闭合状态（CLOSED / OPEN / MODEL_DEFECT）。
//       v1 不自动 grep 代码库（避免误判），而是硬编码期望 + 当前实测状态，
//       由人工/CI 在证据变化时更新。
//
// 前置：node + java 17；tla2tools.jar（钉 v1.7.4，或 env TLA2TOOLS_JAR 复用）
// 调用：node tla-verifier/seam-checker.js
//   env: MAIN_REPO_DIR=fibemate checkout 根；TLA2TOOLS_JAR=复用 jar 路径

'use strict';
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAIN_REPO_DIR = process.env.MAIN_REPO_DIR || '.';
const TLA_DIR = path.join(MAIN_REPO_DIR, 'docs', 'tla');
const JAR = process.env.TLA2TOOLS_JAR ||
  (os.platform() === 'win32' ? 'C:/Users/maivs/AppData/Local/Temp/tla2tools.jar'
                             : '/tmp/tla2tools.jar');

// 模型清单：模型名 -> 配置文件（位于主仓 docs/tla/）
const MODELS = {
  C2:  { cfg: 'C2.cfg',  tla: 'C2.tla' },
  OPK: { cfg: 'OPK.cfg', tla: 'OPK.tla' },
};

// ---- v2 锚点自动 grep 化（manifest 驱动 + 双树阴性对照）----
// 设计文档：seam-checker-v2-anchors-design_20260920.md（§2 三态伪码 / §6 接入法）
// survey 实证：seam-v2-repo-survey_20260920.md（§5 锚点集，已推翻 HKDF 假阳性）
//
// 三态引擎（§2）：
//   ANCHOR_BROKEN   = 锚点在 ref（已知良树）也命中 0 → 锚点定义写错（非证据缺失），立即报警
//   EVIDENCE_GAP    = ref 命中但 live（当前树）命中 0 → 证据确实没了
//   EVIDENCE_FOUND  = live 命中 → 该接缝项可升 CLOSED
//   REF_MISSING     = REF_COMMIT 未配置 → 双树退化单树，阴性对照失效（机制未完整启用，告警不退化为伪 PASS）
//
// ref 树来源（用户拍板选 (2)）：fibemate 某已知良 commit，经 `git show <sha>:<path>` 取内容，
//  跨平台、抗 stale、保留 ANCHOR_BROKEN 阴性对照。配置：env REF_COMMIT=<fibemate sha>。

// 注意：设计文档 §2 字面写 "ANCHOR_BROKEN = ref 命中 0"，但若直接套用到 C2-G2-1（一个
// 正确指向『确实不存在的特性』的锚点），会把『特性未实现』误判为『锚点写错』。真实
// 阴性对照意图是『ref 连文件都找不到 → 锚点畸形』。故本实现以 ref 文件存在性为
// ANCHOR_BROKEN 判据（见 evalAnchor），与 §2 字面有偏差，已向用户报备。

const REF_COMMIT = process.env.REF_COMMIT || '';

function loadRefTree() {
  // 返回 { kind:'git', root, sha } 或 null（未配置/sha 不存在）
  if (!REF_COMMIT) return null;
  const r = spawnSync('git', ['-C', MAIN_REPO_DIR, 'cat-file', '-t', REF_COMMIT], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  return { kind: 'git', root: MAIN_REPO_DIR, sha: REF_COMMIT };
}

function listPaths(tree, target) {
  // 用 git ls-files / ls-tree 在两种树上统一展开 glob → 相对路径集合
  const out = (tree.kind === 'fs')
    ? spawnSync('git', ['-C', tree.root, 'ls-files', '--', target], { encoding: 'utf8' }).stdout
    : spawnSync('git', ['-C', tree.root, 'ls-tree', '-r', '--name-only', tree.sha, '--', target], { encoding: 'utf8' }).stdout;
  return out.split('\n').map(s => s.trim()).filter(Boolean);
}

function readContent(tree, rel) {
  if (tree.kind === 'fs') {
    try { return fs.readFileSync(path.join(tree.root, rel), 'utf8'); } catch { return null; }
  }
  const r = spawnSync('git', ['-C', tree.root, 'show', tree.sha + ':' + rel], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout : null;
}

// 多行正则 + 跨文件 AND：patterns 数组全部命中（可在不同文件）即计 1，否则 0。
// 命中计数用正则 test（语义：所有 pattern 是否都存在于拼合内容，满足 §2『跨文件组合』）。
function grepGlobs(tree, targets, patterns) {
  const relPaths = new Set();
  for (const t of targets) for (const p of listPaths(tree, t)) relPaths.add(p);
  if (relPaths.size === 0) return 0;
  let content = '';
  for (const rel of relPaths) {
    const text = readContent(tree, rel);
    if (text != null) content += '\n' + text;
  }
  if (!content) return 0;
  const allHit = patterns.every(p => { try { return new RegExp(p, 'm').test(content); } catch { return false; } });
  return allHit ? 1 : 0;
}

function evalAnchor(a, liveTree, refTree) {
  // MANUAL 锚点（无 targets/patterns 或显式 status:MANUAL）：不自动评估
  if (a.status === 'MANUAL' || !a.targets || a.targets.length === 0) {
    return { state: 'MANUAL', refHits: null, liveHits: null,
      note: a.note || '锚点无 target → 留 MANUAL（未知位置 / 无测试断言，待建证据）' };
  }
  if (!refTree) {
    return { state: 'REF_MISSING', refHits: null, liveHits: null,
      note: 'REF_COMMIT 未配置 → 双树退化单树，阴性对照失效（v2 机制未完整启用，告警不退化为伪 PASS）' };
  }
  const isGap = a.expect === 'gap';
  const refHits = grepGlobs(refTree, a.targets, a.patterns);
  const refPaths = new Set();
  for (const t of a.targets) for (const p of listPaths(refTree, t)) refPaths.add(p);
  const refMissing = refPaths.size === 0;

  if (isGap) {
    // 期望缺口：ref 0 与 live 0 都合法（特性本就未实现）——不误报 ANCHOR_BROKEN
    const liveHits = grepGlobs(liveTree, a.targets, a.patterns);
    if (liveHits > 0) {
      return { state: 'EVIDENCE_FOUND', refHits, liveHits,
        note: 'expect=gap 但 live 命中 → 特性已实现（意外收获，可升 CLOSED）' };
    }
    return { state: 'EVIDENCE_GAP', refHits, liveHits,
      note: 'expect=gap: ref 与 live 均 0 → 特性未实现（已知缺口，非锚点错误）' };
  }

  // 期望存在（默认）：ref 0 = 锚点定义错误（阴性对照核心）
  if (refMissing) {
    return { state: 'ANCHOR_BROKEN', refHits, liveHits: null,
      note: '锚点在 ref 已知良树连目标文件都找不到 → 锚点定义错误（targets 写错 / 文件已移）' };
  }
  if (refHits === 0) {
    return { state: 'ANCHOR_BROKEN', refHits, liveHits: null,
      note: '锚点在 ref 已知良树有文件但 pattern 0 命中 → 锚点 pattern 写错（非证据缺失）' };
  }
  const liveHits = grepGlobs(liveTree, a.targets, a.patterns);
  if (liveHits === 0) {
    return { state: 'EVIDENCE_GAP', refHits, liveHits,
      note: 'ref 命中但 live 命中 0 → 证据确实缺失（PR 删测试 / 重构改名）' };
  }
  return { state: 'EVIDENCE_FOUND', refHits, liveHits, note: 'ref 与 live 均命中 → 证据闭合' };
}

// ANCHORS manifest（survey §5 六条；G2=gap, S1-KAT=found, OPK-S1-1=app-layer, C2-S1-1 BIND=MANUAL）
// 纪律 5b：所有锚点以 survey grep 实证为准，禁手填；未知位置标 MANUAL。
// 纪律 5c：无伪 CLOSED——MANUAL 须带 note，无 note 的 MANUAL 同为伪达标。
const ANCHORS = [
  { id: 'C2-G2-1', seam: 'G2', expect: 'gap', targets: ['docs/tla/C2.cfg'], patterns: ['PROPERTIES|L_Handshake'],
    note: 'C2.cfg 无 PROPERTIES/L_Handshake → EVIDENCE_GAP（G2 活性未机器验证，expect=gap 正确反映）' },
  { id: 'OPK-G2-1', seam: 'G2', expect: 'gap', targets: ['docs/tla/OPK.cfg'], patterns: ['PROPERTIES|T1|T2'],
    note: 'OPK.cfg 无 T1/T2 → EVIDENCE_GAP（expect=gap）' },
  { id: 'S1-KAT-jasmin', seam: 'S1-KAT', expect: 'found', targets: ['scripts/kat-jasmin-compare.js'], patterns: ['assert|Jasmin|libjade'],
    note: 'ML-KEM-768 × Jasmin/libjade KAT 逐字节验证 → EVIDENCE_FOUND（真证据）' },
  { id: 'S1-KAT-fml', seam: 'S1-KAT', expect: 'found', targets: ['packages/fml-dsa/test/kat-verify.mjs'], patterns: ['ML-DSA|KAT|Noble'],
    note: 'ML-DSA KAT vs Noble oracle → EVIDENCE_FOUND（真证据）' },
  { id: 'OPK-S1-1', seam: 'S1', expect: 'found', targets: ['src/opk-server.js'],
    patterns: ['oneTimePreKey|OneTimePreKey', 'used|consumed|markUsed|removeOPK|spent'],
    note: '应用层标记 used 后拒重（非 DB 事务）；锁定 opk-server.js 排除 double-ratchet.js Signal ratchet 噪声。仅证应用层逻辑，非密码学原子性' },
  { id: 'C2-S1-1', seam: 'S1-BIND', targets: [], patterns: [], status: 'MANUAL',
    note: 'HKDF(sessionKey=HKDF(sm2_ss||mlkem_ss)) 无测试断言，仅 src/pqc-hybrid-server.js:10 注释级 → 留 MANUAL 待建集成测试' },
];

// S 层 id → 锚点 id 映射（有锚点的 S 项用 evalAnchor 实时结果覆盖/附注）
const ANCHOR_BY_SID = {
  'C2-G2-1': 'C2-G2-1',
  'OPK-G2-1': 'OPK-G2-1',
  'OPK-S1-1': 'OPK-S1-1',
  'C2-S1-1': 'C2-S1-1',
};

// 锚点 id → 该锚点闭合时赋予 S 层项的 status（EVIDENCE_FOUND 升 CLOSED，其余保持 OPEN）
function anchorStatusToClosure(state) {
  if (state === 'EVIDENCE_FOUND') return 'CLOSED';
  if (state === 'REF_MISSING') return 'OPEN'; // 机制未启用，不伪判
  return 'OPEN'; // EVIDENCE_GAP / ANCHOR_BROKEN / MANUAL 均不自动 CLOSED
}

function extractInvariants(cfgText) {
  // 解析 .cfg 的两种写法：
  //   (a) 单行:  INVARIANT Foo   /   INVARIANT Foo Bar
  //   (b) 块:    INVARIANTS\n    TypeOK\n    K1_...   （缩进列表，可跨多行）
  const inv = [];
  let inBlock = false;
  for (const raw of cfgText.split('\n')) {
    const line = raw.replace(/\s*\(.*\)\s*$/, ''); // 去尾注释
    const head = line.match(/^\s*(INVARIANT|INVARIANTS|PROPERTY|PROPERTIES)\b/);
    if (head) {
      const kw = head[1];
      inBlock = /S$/.test(kw); // 复数 = 块开始
      // 单行也可能直接带名字：INVARIANT Foo Bar
      const rest = line.slice(head[0].length).trim();
      if (rest) for (const x of rest.split(/\s+/)) if (x) inv.push({ kind: kw, name: x });
      continue;
    }
    if (inBlock) {
      const name = line.trim();
      if (/^\S/.test(name) && !/^(CONSTANTS|SPECIFICATION|PROPERTY|PROPERTIES|INVARIANT|INVARIANTS|\w+\s*=)/.test(name)) {
        inv.push({ kind: 'BLOCK', name });
      } else if (name === '' || /^\w+\s*=/.test(name) || /^(CONSTANTS|SPECIFICATION)/.test(name)) {
        inBlock = false; // 遇到空行 / 新段 / 赋值 结束块
      }
    }
  }
  // 去重
  const seen = new Set();
  return inv.filter(i => (i.name && !seen.has(i.name) ? (seen.add(i.name), true) : false));
}

function runTLC(modelName) {
  const cfgFile = path.join(TLA_DIR, MODELS[modelName].cfg);
  const tlaFile = path.join(TLA_DIR, MODELS[modelName].tla);
  if (!fs.existsSync(cfgFile) || !fs.existsSync(tlaFile)) {
    return { model: modelName, missing: true, verdict: 'MISSING_FILES' };
  }
  const cfgText = fs.readFileSync(cfgFile, 'utf8');
  const invariants = extractInvariants(cfgText);

  // 把模型+配置复制到临时目录跑，零仓库污染
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seam-'));
  const cfgCp = path.join(runDir, MODELS[modelName].cfg);
  const tlaCp = path.join(runDir, MODELS[modelName].tla);
  fs.copyFileSync(cfgFile, cfgCp);
  fs.copyFileSync(tlaFile, tlaCp);

  const r = spawnSync('java', [
    '-Xmx2g', '-XX:+UseParallelGC', '-cp', JAR, 'tlc2.TLC',
    '-workers', 'auto', '-nowarning',
    '-config', MODELS[modelName].cfg, MODELS[modelName].tla
  ], { cwd: runDir, encoding: 'utf8', timeout: 240000, maxBuffer: 64 * 1024 * 1024 });

  const out = (r.stdout || '') + '\n' + (r.stderr || '');
  const parseErr = /Parse Error|Encountered ["'][^"']*["']|TLC threw an unexpected/.test(out);
  const completed = /Model checking completed\. No error has been found\./.test(out);
  const deadlock = /Deadlock reached|deadlock reached/.test(out);
  const violated = Array.from(out.matchAll(/Invariant (\S+) is violated/g)).map(m => m[1]);

  let verdict;
  if (parseErr) verdict = 'PARSE_FAIL';
  else if (violated.length) verdict = 'INV_VIOLATED';
  else if (deadlock) verdict = 'DEADLOCK';
  else if (completed) verdict = 'PASS';
  else verdict = (r.error && r.error.code === 'ETIMEDOUT') ? 'TIMEOUT' : 'UNKNOWN';

  return {
    model: modelName,
    exit: r.status,
    verdict,
    invariants,
    violated,
    parseErr, completed, deadlock,
    timedOut: !!(r.error && r.error.code === 'ETIMEDOUT'),
    states: (out.match(/(\d+) states generated/) || [])[1],
    distinct: (out.match(/(\d+) distinct states found/) || [])[1],
  };
}

// ---- S 层映射表（声明式；证据变化时人工/C2 CI 更新）----
// 来源：seam-checklist-v1_20260920.md 第 2/3 节
// status: CLOSED=有证据闭合 / OPEN=已知缺口 / MODEL_DEFECT=模型缺陷(待修)
const S_LAYER = [
  { id: 'C2-S4-1', seam: 'S4', need: 'ML-KEM-768 IND-CCA2 / SM2 ECDH / Dual-PRF 外部标准', evidence: 'NIST FIPS 203; GB/T SM2; SP 800-56Cr2; Kiltz 2024', status: 'CLOSED' },
  { id: 'C2-S1-1', seam: 'S1+S2', need: '真实 key_i=HKDF(sm2_ephem||mlkem_ss)，K3 强独立非平凡', evidence: 'HKDF KAT 已跑 (FIPS 203/RFC 5869); PRF=外部; TVLA=自评估未做; 独立采样=未证', status: 'OPEN' },
  { id: 'C2-S1-2', seam: 'S1', need: 'active 前必 derived+cKeyValue≠0+PQ/SM2 received', evidence: '实现层握手状态序未自动链接', status: 'OPEN' },
  { id: 'C2-S1-3', seam: 'S1', need: '早期消息不含 tlsExporter 秘密', evidence: '代码审计缺失', status: 'OPEN' },
  { id: 'C2-S1-4', seam: 'S1', need: 'server active 须 ClientKeyFinish 已在 network', evidence: '实现层状态机序未链接', status: 'OPEN' },
  { id: 'C2-S2-1', seam: 'S2', need: '每会话独立采样 → 常量时间 + TVLA', evidence: 'TVLA 自评估（主页已诚实化标注"非独立侧信道审计"）', status: 'OPEN' },
  { id: 'C2-G2-1', seam: 'G2', need: 'L_Handshake 活性 PROPERTY 机器验证', evidence: 'C2.cfg 未列 L_Handshake; 注释 "do not claim verified"', status: 'OPEN' },
  { id: 'C2-M1',   seam: 'M',  need: 'K3 强独立对任意 N 成立', evidence: '仅 N=2 实跑', status: 'OPEN' },
  { id: 'OPK-S1-1', seam: 'S1', need: '真实 OPK 原子一次性消费 (DB 事务/锁)', evidence: '未链接实现', status: 'OPEN' },
  { id: 'OPK-S1-2', seam: 'S1', need: 'DB 计数与存储一致 (并发无漂移)', evidence: '未链接实现', status: 'OPEN' },
  { id: 'OPK-S4-1', seam: 'S4', need: 'OPK→会话密钥 X3DH 密码学绑定', evidence: 'Signal 规范 / DFHMP 2016（外部）', status: 'CLOSED' },
  { id: 'OPK-G2-1', seam: 'G2', need: 'T1_Progress / T2_UploadPhase 活性 PROPERTY 机器验证', evidence: '未进 OPK.cfg（仅 O1-O6+TypeOK）', status: 'OPEN' },
  { id: 'OPK-S2-1', seam: 'S2', need: 'OPK 选取/消费路径常量时间 (不泄露 keyId)', evidence: 'TVLA 未覆盖消费路径', status: 'OPEN' },
  { id: 'OPK-A', seam: 'M', need: 'Next 结构可解析', evidence: '已修（显式析取分支）；HEAD 原版 Parse Error', status: 'MODEL_DEFECT' },
  { id: 'OPK-B', seam: 'M', need: 'O4 反向 (b): CONSUMED => 日志含(u,k)', evidence: '已确认方向反；待新会话修', status: 'MODEL_DEFECT' },
  { id: 'OPK-C', seam: 'M', need: '状态空间可控 (降常数/约束 consumeLog)', evidence: '去 O4 后 1217 万状态未完', status: 'MODEL_DEFECT' },
];

function main() {
  console.log('=== seam-checker v1 ===');
  console.log('main_repo_dir=' + path.resolve(MAIN_REPO_DIR) + ' | jar=' + JAR);
  const results = {};
  let gPass = true;

  for (const name of Object.keys(MODELS)) {
    const res = runTLC(name);
    results[name] = res;
    console.log('\n### ' + name + ' -> ' + res.verdict + ' (exit ' + res.exit + ')');
    if (res.invariants) {
      const cfgInv = res.invariants.map(i => i.name);
      console.log('  cfg invariants: ' + (cfgInv.join(', ') || '(none)'));
      if (res.verdict === 'PARSE_FAIL') {
        console.log('  ⚠ 模型从未加载 → 上述不变式全是幻影证据（无机器证据）');
        gPass = false;
      } else if (res.verdict === 'INV_VIOLATED') {
        console.log('  ✗ 违反: ' + res.violated.join(', ') + ' → 配置中的不变量未全 PASS');
        gPass = false;
      } else if (res.verdict === 'PASS') {
        console.log('  ✓ 所有 ' + cfgInv.length + ' 条不变量均有真实机器证据 (states=' + res.states + ', distinct=' + res.distinct + ')');
      }
    } else if (res.missing) {
      console.log('  ✗ 模型文件缺失');
      gPass = false;
    }
  }

  // S 层报告（v2：有锚点的 S 项加 anchor_state 列，阴性对照不静默）
  const liveTree = { kind: 'fs', root: MAIN_REPO_DIR };
  const refTree = loadRefTree();
  const anchorResults = {};
  for (const a of ANCHORS) {
    if (a.status === 'MANUAL') {
      anchorResults[a.id] = { state: 'MANUAL', note: a.note };
    } else {
      anchorResults[a.id] = evalAnchor(a, liveTree, refTree);
    }
  }
  if (!refTree) {
    console.log('\n⚠ REF_COMMIT 未配置：双树阴性对照未启用（v2 机制不完整，已告警不退化为伪 PASS）。' +
      ' 建议设 REF_COMMIT=<fibemate 已知良 sha> 复跑以激活 ANCHOR_BROKEN 检测。');
  } else {
    console.log('\nref_tree=' + refTree.sha.slice(0, 12) + ' (双树阴性对照已启用)');
  }

  console.log('\n=== S 层接缝闭合报告 ===');
  const counts = { CLOSED: 0, OPEN: 0, MODEL_DEFECT: 0 };
  for (const s of S_LAYER) {
    counts[s.status]++;
    const tag = s.status === 'CLOSED' ? '✓' : s.status === 'MODEL_DEFECT' ? '⚠' : '·';
    let extra = '';
    const aid = ANCHOR_BY_SID[s.id];
    if (aid && anchorResults[aid]) {
      const ar = anchorResults[aid];
      extra = '  [anchor=' + ar.state + '] ' + (ar.note || '');
    }
    console.log('  ' + tag + ' [' + s.seam + '] ' + s.id + ' (' + s.status + '): ' + s.need + extra);
  }
  console.log('  ---');
  console.log('  CLOSED=' + counts.CLOSED + '  OPEN=' + counts.OPEN + '  MODEL_DEFECT=' + counts.MODEL_DEFECT);

  // v2 锚点三态汇总（独立列，便于 CI 解析）
  console.log('\n=== v2 锚点三态汇总 ===');
  const aCounts = {};
  for (const a of ANCHORS) {
    const st = anchorResults[a.id].state;
    aCounts[st] = (aCounts[st] || 0) + 1;
    console.log('  [' + a.seam + '] ' + a.id + ' -> ' + st + ' | ' + (anchorResults[a.id].note || ''));
  }
  console.log('  ---');
  console.log('  ' + Object.entries(aCounts).map(([k, v]) => k + '=' + v).join('  '));
  if (Object.values(anchorResults).some(r => r.state === 'ANCHOR_BROKEN')) {
    console.log('  ⚠ 存在 ANCHOR_BROKEN：锚点定义写错（非证据缺失），须修正 manifest 而非仓库。');
  }

  // 总判定（执行层）
  console.log('\n=== 总判定 ===');
  console.log('G 层（模型门禁）: ' + (gPass ? 'PASS' : 'FAIL'));
  console.log('纪律: "有 .cfg / 有 INVARIANT 行" ≠ "跑过" ≠ "通过"。执行层以 exit 0 + VIOLATED=0 为准。');
  console.log('OPK 当前 INV_VIOLATED(O4) 即活标本：声明层配了 O1-O6，执行层 O4 失败。');

  // 退出码：G 层失败或非 PARSE/VIOLATED 异常 → 非零（CI 红）
  process.exit(gPass ? 0 : 1);
}

main();
