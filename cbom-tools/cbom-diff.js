#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
/**
 * CBOM Diff — 加密材料清单变更检测器
 *
 * 用法:
 *   node tools/cbom-diff.js                          # diff HEAD~1 vs HEAD
 *   node tools/cbom-diff.js <old-hash> <new-hash>    # diff 两个 commit
 *   node tools/cbom-diff.js --json                   # 输出 JSON（CI 友好）
 *   node tools/cbom-diff.js --markdown               # 输出 Markdown（人类可读，默认）
 *
 * CI 集成:
 *   每次 push 后运行，检测算法新增/删减/属性变更
 *
 * 退出码:
 *   0 — 无变更
 *   1 — 有信息性变更（算法属性升级等）
 *   2 — 有警告性变更（算法删除、新经典算法引用等）
 *   3 — 有严重变更（量子脆弱算法被引入）
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ════════════════════════════
// 命令行解析
// ════════════════════════════
const args = process.argv.slice(2);
let oldHash = null, newHash = null;
let format = 'markdown'; // 'markdown' | 'json'
let gitMode = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--json') { format = 'json'; }
  else if (a === '--markdown') { format = 'markdown'; }
  else if (a === '--git') { gitMode = true; }
  else if (!oldHash) { oldHash = a; }
  else { newHash = a; }
}

if (!oldHash) oldHash = 'HEAD~1';
if (!newHash) newHash = 'HEAD';

// ════════════════════════════
// CBOM 加载
// ════════════════════════════
function loadCBOM(hash) {
  // 1. File path mode: .json extension → read file directly
  if (hash && hash.toLowerCase().endsWith('.json')) {
    const filePath = path.resolve(hash);
    if (!fs.existsSync(filePath)) {
      console.error(`✕ cbom-diff: file not found: ${filePath}`);
      process.exit(2);
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }
  // 2. Git mode
  if (gitMode) {
    try {
      const raw = execSync(`git show ${hash}:tools/cbom-cyclonedx.json`, {
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return JSON.parse(raw);
    } catch (e) {
      console.error(`✕ Cannot load CBOM from git ${hash}: ${e.message}`);
      process.exit(4);
    }
  }
  // 3. Default: load from local file
  try {
    const local = path.join(__dirname, 'cbom-cyclonedx.json');
    return JSON.parse(fs.readFileSync(local, 'utf-8'));
  } catch (e) {
    console.error(`✕ Cannot load CBOM from local file: ${e.message}`);
    process.exit(4);
  }
}

const oldCBOM = loadCBOM(oldHash);
const newCBOM = loadCBOM(newHash);

// ════════════════════════════
// 比较逻辑
// ════════════════════════════
const OLD = oldCBOM ? oldCBOM.version || 0 : 0;
const NEW = newCBOM ? newCBOM.version || 0 : 0;

const diff = {
  meta: {
    oldHash: oldHash,
    newHash: newHash,
    oldVersion: OLD,
    newVersion: NEW,
    date: new Date().toISOString(),
  },
  version: NEW > OLD ? 'bumped' : (NEW < OLD ? 'downgraded' : 'same'),
  components: { added: [], removed: [], changed: [], unchanged: 0 },
  dependencies: { added: [], removed: [] },
  severity: 'none', // 'none' | 'info' | 'warning' | 'critical'
  exitCode: 0,
};

// --- 组件比较 ---
if (oldCBOM && newCBOM) {
  const oldMap = new Map();
  oldCBOM.components.forEach(c => oldMap.set(c['bom-ref'] || c.name, c));
  const newMap = new Map();
  newCBOM.components.forEach(c => newMap.set(c['bom-ref'] || c.name, c));

  // Added
  newMap.forEach((c, ref) => {
    if (!oldMap.has(ref)) {
      const crypto = c.cryptoProperties || {};
      const assetType = crypto.assetType || c.type;
      diff.components.added.push({
        ref,
        name: c.name,
        type: assetType,
        risk: classifyRisk(assetType),
      });
    }
  });

  // Removed
  oldMap.forEach((c, ref) => {
    if (!newMap.has(ref)) {
      diff.components.removed.push({
        ref,
        name: c.name,
        type: (c.cryptoProperties || {}).assetType || c.type,
      });
    }
  });

  // Changed
  newMap.forEach((nc, ref) => {
    const oc = oldMap.get(ref);
    if (!oc) return;
    const changes = compareProperties(oc, nc);
    if (changes.length > 0) {
      diff.components.changed.push({ ref, name: nc.name, changes });
    } else {
      diff.components.unchanged++;
    }
  });
} else if (!oldCBOM && newCBOM) {
  diff.components.added = newCBOM.components.map(c => ({
    ref: c['bom-ref'],
    name: c.name,
    type: (c.cryptoProperties || {}).assetType || c.type,
    risk: 'info',
  }));
}

// --- 依赖关系比较 ---
if (oldCBOM && newCBOM) {
  const oldDepMap = new Map();
  oldCBOM.dependencies.forEach(d => oldDepMap.set(d.ref, (d.dependsOn || []).sort().join(',')));

  const newDepMap = new Map();
  newCBOM.dependencies.forEach(d => newDepMap.set(d.ref, (d.dependsOn || []).sort().join(',')));

  // Added deps
  newDepMap.forEach((deps, ref) => {
    if (!oldDepMap.has(ref)) {
      diff.dependencies.added.push({ ref, dependsOn: deps });
    } else if (oldDepMap.get(ref) !== deps) {
      diff.dependencies.added.push({ ref, dependsOn: deps, previous: oldDepMap.get(ref) });
    }
  });

  // Removed deps
  oldDepMap.forEach((deps, ref) => {
    if (!newDepMap.has(ref)) {
      diff.dependencies.removed.push({ ref, dependsOn: deps });
    }
  });
}

// --- 严重性判定 ---
const hasCriticalAdd = diff.components.added.some(c => c.risk === 'critical');
const hasWarningAdd = diff.components.added.some(c => c.risk === 'warning');
const hasRemoval = diff.components.removed.length > 0;
const hasChanges = diff.components.changed.length > 0;
const hasAdded = diff.components.added.length > 0;

if (hasCriticalAdd) {
  diff.severity = 'critical';
  diff.exitCode = 3;
} else if (hasRemoval || hasWarningAdd) {
  diff.severity = 'warning';
  diff.exitCode = 2;
} else if (hasAdded || hasChanges) {
  diff.severity = 'info';
  diff.exitCode = 1;
} else {
  diff.severity = 'none';
  diff.exitCode = 0;
}

// ════════════════════════════
// 算法风险分类
// ════════════════════════════
function classifyRisk(assetType) {
  const type = (assetType || '').toLowerCase();
  // PQC algorithms: safe additions
  if (/kem|sign|signature|post.quantum|pqc|mlkem|mldsa|slh/i.test(type)) return 'info';
  // Primitive/verification: neutral
  if (/ntt|sha|hash|primitive|verification|protocol/i.test(type)) return 'info';
  // Classic ECC: warning
  if (/ecc|ecdh|p-256|sm2|curve/i.test(type)) return 'warning';
  // Classic symmetric: info (still safe with large keys)
  if (/sym|sm4|aes|gcm/i.test(type)) return 'info';
  // Unknown: treat as warning
  return 'warning';
}

// ════════════════════════════
// 组件属性对比
// ════════════════════════════
function compareProperties(oldC, newC) {
  const changes = [];
  const oldCp = oldC.cryptoProperties || {};
  const newCp = newC.cryptoProperties || {};

  // Check assetType change
  if (oldCp.assetType !== newCp.assetType) {
    changes.push({ field: 'assetType', old: oldCp.assetType, new: newCp.assetType });
  }

  // Check algorithm level
  const oldAlg = (oldCp.algorithmProperties || {});
  const newAlg = (newCp.algorithmProperties || {});
  if (oldAlg.classicalSecurityLevel !== newAlg.classicalSecurityLevel) {
    changes.push({ field: 'classicalSecurityLevel', old: oldAlg.classicalSecurityLevel, new: newAlg.classicalSecurityLevel });
  }
  if (oldAlg.nistQuantumSecurityLevel !== newAlg.nistQuantumSecurityLevel) {
    changes.push({ field: 'nistQuantumSecurityLevel', old: oldAlg.nistQuantumSecurityLevel, new: newAlg.nistQuantumSecurityLevel });
  }

  // Check evidence
  const oldEvidence = oldC.evidence || {};
  const newEvidence = newC.evidence || {};
  if (oldEvidence.count !== newEvidence.count) {
    changes.push({ field: 'evidence.count', old: oldEvidence.count, new: newEvidence.count });
  }

  // version bump
  if (oldC.version !== newC.version && oldC.version != null && newC.version != null) {
    changes.push({ field: 'version', old: oldC.version, new: newC.version });
  }

  return changes;
}

// ════════════════════════════
// 输出
// ════════════════════════════
if (format === 'json') {
  console.log(JSON.stringify(diff, null, 2));
} else {
  // Markdown
  const lines = [];
  lines.push(`## CBOM Diff \`${oldHash.substring(0,8)} → ${newHash.substring(0,8)}\``);
  lines.push('');
  lines.push(`| 属性 | 值 |`);
  lines.push(`|------|-----|`);
  lines.push(`| 旧版本 | ${OLD} |`);
  lines.push(`| 新版本 | ${NEW} |`);
  lines.push(`| 版本 | ${diff.version} |`);
  lines.push(`| 严重性 | **${diff.severity}** (exit=${diff.exitCode}) |`);
  lines.push('');

  // Added components
  if (diff.components.added.length > 0) {
    lines.push('### ➕ 新增算法');
    lines.push('');
    lines.push('| 名称 | 类型 | 风险 |');
    lines.push('|------|------|------|');
    diff.components.added.forEach(c => {
      const riskEmoji = c.risk === 'critical' ? '🔴' : c.risk === 'warning' ? '🟡' : '🟢';
      lines.push(`| ${c.name} | ${c.type} | ${riskEmoji} ${c.risk} |`);
    });
    lines.push('');
  }

  // Removed
  if (diff.components.removed.length > 0) {
    lines.push('### ➖ 删除算法');
    lines.push('');
    lines.push('| 名称 | 类型 |');
    lines.push('|------|------|');
    diff.components.removed.forEach(c => {
      lines.push(`| ${c.name} | ${c.type} |`);
    });
    lines.push('');
  }

  // Changed
  if (diff.components.changed.length > 0) {
    lines.push(`### 🔄 属性变更 (${diff.components.changed.length} 项)`);
    lines.push('');
    diff.components.changed.forEach(c => {
      lines.push(`**${c.name}**`);
      c.changes.forEach(ch => {
        lines.push(`- \`${ch.field}\`: \`${ch.old}\` → \`${ch.new}\``);
      });
      lines.push('');
    });
  }

  // Dependencies
  if (diff.dependencies.added.length > 0 || diff.dependencies.removed.length > 0) {
    lines.push('### 🔗 依赖关系变更');
    lines.push('');
    if (diff.dependencies.added.length > 0) {
      diff.dependencies.added.forEach(d => {
        lines.push(`- ➕ \`${d.ref}\` → ${d.dependsOn || '(none)'}`);
        if (d.previous) lines.push(`  (先前: ${d.previous})`);
      });
    }
    if (diff.dependencies.removed.length > 0) {
      diff.dependencies.removed.forEach(d => {
        lines.push(`- ➖ \`${d.ref}\` ← ${d.dependsOn || '(none)'}`);
      });
    }
    lines.push('');
  }

  // Summary
  if (diff.severity === 'none') {
    lines.push('### ✅ 无变更');
    lines.push(`> 前后 CBOM 完全一致，${diff.components.unchanged} 算法无变化。`);
  } else if (diff.severity === 'info') {
    lines.push(`### ℹ️ 信息性变更`);
    lines.push(`> ${diff.components.unchanged} 算法保持原样。（${diff.meta.date}）`);
  } else if (diff.severity === 'warning') {
    lines.push('### ⚠️ 警告');
    lines.push('> 检测到值得关注的变更，请确认是否符合预期。');
  } else {
    lines.push('### 🔴 严重');
    lines.push('> 检测到量子脆弱算法被引入，**请立即审查**。');
  }

  console.log(lines.join('\n'));
}

process.exit(diff.exitCode);
