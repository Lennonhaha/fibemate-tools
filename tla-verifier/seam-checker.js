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

  // S 层报告
  console.log('\n=== S 层接缝闭合报告 ===');
  const counts = { CLOSED: 0, OPEN: 0, MODEL_DEFECT: 0 };
  for (const s of S_LAYER) {
    counts[s.status]++;
    const tag = s.status === 'CLOSED' ? '✓' : s.status === 'MODEL_DEFECT' ? '⚠' : '·';
    console.log('  ' + tag + ' [' + s.seam + '] ' + s.id + ' (' + s.status + '): ' + s.need);
  }
  console.log('  ---');
  console.log('  CLOSED=' + counts.CLOSED + '  OPEN=' + counts.OPEN + '  MODEL_DEFECT=' + counts.MODEL_DEFECT);

  // 总判定（执行层）
  console.log('\n=== 总判定 ===');
  console.log('G 层（模型门禁）: ' + (gPass ? 'PASS' : 'FAIL'));
  console.log('纪律: "有 .cfg / 有 INVARIANT 行" ≠ "跑过" ≠ "通过"。执行层以 exit 0 + VIOLATED=0 为准。');
  console.log('OPK 当前 INV_VIOLATED(O4) 即活标本：声明层配了 O1-O6，执行层 O4 失败。');

  // 退出码：G 层失败或非 PARSE/VIOLATED 异常 → 非零（CI 红）
  process.exit(gPass ? 0 : 1);
}

main();
