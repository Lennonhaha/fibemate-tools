#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫

'use strict';

/**
 * cbom-compliance — turn a CBOM into a 密评-oriented self-check report.
 *
 * Why this exists: a CycloneDX CBOM answers "what cryptography is in this tree".
 * A 密评 reviewer asks a different question: "is what is here the kind of
 * algorithm the regulation requires, and where is the rest". Those are two
 * vocabularies over one inventory.
 *
 * What this module will not do:
 *   - It does not score, grade, or conclude compliance. GB/T 39786-2021 sets
 *     requirements per level (chapters 6-9) across four technical domains; a
 *     static inventory is one input to an assessment, never the assessment.
 *   - It does not determine key length. The scanner is file-level; `RSA` in the
 *     CBOM is RSA, not RSA-1024 and not RSA-4096.
 *   - It does not reuse the CBOM's `quantumSecurity.level` as a compliance
 *     verdict. That field is a different axis: SM3 and SM4 carry
 *     `quantumSecurity: weak` because Grover halves the margin, while both are
 *     approved 商用密码算法. Reading the two axes as one produces a report that
 *     says "SM4 is weak", which is both true and useless.
 */

const fs = require('fs');
const path = require('path');

const PKG = require('./package.json');
// Metadata lookup only. Reusing the scanner's resolution keeps family/alias
// behaviour identical to the CBOM that produced the components: if a name
// resolved there, it resolves here with the same rules.
const { lookupMeta } = require('./cbom-scan.cjs');

// ── Policy tables ────────────────────────────────────────────────────
// These are name → policy mappings, not measurements. They answer "how does a
// 密评 reviewer classify this algorithm name", and nothing else.

// Algorithms published as 商用密码算法 (GM/T series), i.e. the ones the
// regulation points at when it says 国家密码管理部门核准的算法.
const APPROVED = new Set(['SM2', 'SM3', 'SM4', 'SM9', 'ZUC']);

// Names that are not algorithm bodies: an implementation technique (NTT) or a
// protocol construction (Double Ratchet). Classifying them as "non-approved
// algorithm" would be a category error, so they get their own bucket.
const CONSTRUCTS = new Set(['NTT', 'Double-Ratchet']);

// Broken, not merely foreign. Kept as a fallback for CBOMs produced elsewhere;
// in this repository's own metadata the same set is already marked
// `certificationLevel: deprecated`.
const KNOWN_BROKEN = new Set(['MD5', 'MD4', 'RC2', 'RC4', 'SHA-1', 'DES', '3DES', 'Blowfish', 'DSA']);

// Post-quantum families. Not approved either — the migration story and the
// compliance story are different roads that happen to share a map.
const PQC_FAMILIES = new Set([
  'ML-KEM', 'ML-DSA', 'SLH-DSA', 'Kyber', 'Dilithium', 'Falcon', 'HQC', 'BIKE',
  'Classic-McEliece', 'FrodoKEM', 'NTRU', 'NTRU-Prime', 'MAYO', 'CROSS', 'UOV',
  'SNOVA', 'SQIsign', 'SDitH', 'MQOM', 'QR-UOV',
]);

const BUCKET_LABEL = {
  approved: '合规（商用密码算法）',
  not_approved: '非商用密码算法',
  deprecated: '已废止/不安全',
  construct: '构造/技术（非算法本体）',
  unknown: '未知（需人工确认）',
};

const BUCKET_MEANING = {
  approved: '已列入国家密码管理部门发布的商用密码算法，密评语境下是目标算法。',
  not_approved: '未被核准的算法（国际标准算法或 PQC）。密评中通常需替换为国密算法，或按方案说明理由并申请例外。',
  deprecated: '已废止或已被证明不安全，任何等级下都不应继续使用。',
  construct: '不是算法本体（实现技术或协议构造），合规性取决于其内部使用的算法。',
  unknown: 'CBOM 中缺少该名称的元数据，无法自动分类。',
};

/**
 * Reduce a parameterised name to its family: `ML-DSA-65` → `ML-DSA`,
 * `AES-GCM` → `AES`, `P-256/ECDH` → `P-256`, `Keccak-256` → `Keccak`.
 */
function familyOf(name) {
  let s = String(name || '').trim();
  if (!s) return '';
  s = s.split('/')[0];
  // Curve names are not parameterised algorithm names: `P-256` must not become
  // `P`, and `secp256k1` must not become `secp`. This is the one place where a
  // trailing number is part of the identity rather than a parameter.
  if (/^(?:[Pp]-\d+|secp\d+k1|sect\d+k1|brainpoolP\d+[rt]1|Curve25519|Curve448)$/.test(s)) return s;
  // Strip one parameter suffix: -256, -GCM, -Poly1305, -1024.
  const stripped = s.replace(/-(?:[A-Za-z]*\d+|\d+[A-Za-z]*|GCM|Poly1305)$/, '');
  return stripped.length >= 2 ? stripped : s;
}

/**
 * Classify one CBOM component.
 * @param {string} name component name
 * @param {object|null} meta entry from algo-metadata.json, if any
 * @returns {{bucket: string, family: string, pqc: boolean, basis: string}}
 */
function classify(name, meta) {
  const family = familyOf(name);
  const pqc = PQC_FAMILIES.has(family) || PQC_FAMILIES.has(String(name));

  if (APPROVED.has(family) || APPROVED.has(String(name))) {
    return { bucket: 'approved', family, pqc: false, basis: 'name in approved list' };
  }
  if (CONSTRUCTS.has(String(name)) || CONSTRUCTS.has(family)) {
    return { bucket: 'construct', family, pqc: false, basis: 'name is a technique or construction' };
  }
  if (KNOWN_BROKEN.has(family) || KNOWN_BROKEN.has(String(name))) {
    return { bucket: 'deprecated', family, pqc: false, basis: 'name in known-broken list' };
  }
  if (pqc) {
    return { bucket: 'not_approved', family, pqc: true, basis: 'name in post-quantum families' };
  }
  if (meta && meta.certificationLevel === 'deprecated') {
    return { bucket: 'deprecated', family, pqc: false, basis: 'metadata certificationLevel=deprecated' };
  }
  if (meta && meta.algorithmProperties && meta.algorithmProperties.primitive) {
    return { bucket: 'not_approved', family, pqc: false, basis: 'metadata present, not approved' };
  }
  return { bucket: 'unknown', family, pqc: false, basis: 'no metadata and no policy entry' };
}

/**
 * Collect the algorithms in a CBOM with their evidence, grouped by name.
 * @param {object} bom parsed CycloneDX document
 */
function collect(bom) {
  const components = Array.isArray(bom && bom.components) ? bom.components : [];
  const rows = [];
  for (const c of components) {
    const props = c.cryptoProperties || {};
    const cls = classify(c.name, lookupMeta(c.name));
    // The BOM itself carries certificationLevel only via properties; read what is there.
    const cert = (c.properties || []).find((p) => p && p.name === 'fibemate:testingStatus');
    if (cert && cert.value === 'deprecated') {
      cls.bucket = 'deprecated';
      cls.basis = 'component property fibemate:testingStatus=deprecated';
    }
    const occ = (c.evidence && Array.isArray(c.evidence.occurrences)) ? c.evidence.occurrences : [];
    const methods = ((c.evidence && c.evidence.identity) || [])
      .flatMap((i) => (Array.isArray(i.methods) ? i.methods : []))
      .map((m) => m.technique + '@' + m.confidence);
    rows.push({
      name: c.name,
      bucket: cls.bucket,
      family: cls.family,
      pqc: cls.pqc,
      basis: cls.basis,
      primitive: (props.algorithmProperties && props.algorithmProperties.primitive) || '',
      occurrences: occ.map((o) => ({ location: o.location, line: o.line || 0, symbol: o.symbol || '' })),
      count: occ.length,
      truncatedAt: (c.properties || []).filter((p) => p && p.name === 'fibemate:occurrenceCountAtLeast')
        .map((p) => Number(p.value))[0] || null,
      methods,
    });
  }
  rows.sort((a, b) => (a.bucket === b.bucket ? a.name.localeCompare(b.name) : a.bucket.localeCompare(b.bucket)));
  return rows;
}

// ── Hardcoded private keys ───────────────────────────────────────────
// Scope is deliberately narrow: PEM private-key headers only. That is a fact
// about the file, not a judgement about whether the key is live. A hex blob
// assigned to a variable is not matched, and the report says so rather than
// implying full coverage of "hardcoded keys".

const PEM_RE = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY)-----/g;
const PEM_SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.cache']);
const PEM_MAX_BYTES = 1024 * 1024;

function looksBinary(buf) {
  const n = Math.min(buf.length, 1024);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/**
 * Scan a tree for PEM private-key headers.
 * @returns {{found: Array<{location: string, line: number, label: string}>, scannedFiles: number, skipped: string[]}}
 */
function scanPrivateKeyBlocks(root) {
  const found = [];
  const skipped = [];
  let scannedFiles = 0;

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (err) { skipped.push(path.relative(root, dir) + ': ' + (err.code || err.message)); return; }
    for (const e of entries) {
      if (e.name.startsWith('.') || PEM_SKIP_DIRS.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      let st;
      try { st = fs.statSync(full); } catch (err) { continue; }
      if (!st.isFile() || st.size > PEM_MAX_BYTES) continue;
      let buf;
      try { buf = fs.readFileSync(full); } catch (err) { continue; }
      if (looksBinary(buf)) continue;
      scannedFiles++;
      const text = buf.toString('utf-8');
      PEM_RE.lastIndex = 0;
      let m;
      while ((m = PEM_RE.exec(text)) !== null) {
        found.push({
          location: path.relative(root, full).replace(/\\/g, '/'),
          line: text.slice(0, m.index).split('\n').length,
          label: m[1],
        });
      }
    }
  }

  walk(root);
  return { found, scannedFiles, skipped };
}

// ── Rendering ────────────────────────────────────────────────────────

/**
 * Markdown table cell escaping. Escape the escape character first: escaping
 * only the delimiter leaves a trailing backslash that re-opens the cell.
 */
function cell(value) {
  return String(value == null ? '' : value)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim();
}

function summarise(bom, opts) {
  const options = opts || {};
  const rows = collect(bom);
  const counts = { approved: 0, not_approved: 0, deprecated: 0, construct: 0, unknown: 0 };
  const occurrences = { approved: 0, not_approved: 0, deprecated: 0, construct: 0, unknown: 0 };
  for (const r of rows) {
    counts[r.bucket] = (counts[r.bucket] || 0) + 1;
    occurrences[r.bucket] = (occurrences[r.bucket] || 0) + r.count;
  }
  return {
    tool: { name: 'cbom-tools', version: PKG.version },
    specVersion: bom && bom.specVersion ? bom.specVersion : '',
    timestamp: bom && bom.metadata && bom.metadata.timestamp ? bom.metadata.timestamp : '',
    scanRoot: options.dir || '',
    componentCount: rows.length,
    rows,
    counts,
    occurrences,
    pem: options.pem || null,
  };
}

/**
 * The three judgements, each with the scope it covers.
 *
 * There are four verdicts, and `unable` is one of them. A static inventory of
 * algorithm names cannot answer "is the data that should be encrypted actually
 * encrypted" -- that needs a data-flow and storage model this tool never sees.
 * Saying so is the professional answer; inventing a verdict there is how a
 * report loses the reader at the first question.
 */
function verdicts(s) {
  const d = s.counts.deprecated || 0;
  const n = s.counts.not_approved || 0;
  const u = s.counts.unknown || 0;
  const a = s.counts.approved || 0;

  let strength;
  if (!s.rows.length) {
    strength = { verdict: '无法判定', why: '本次 CBOM 中没有密码资产：这表示没扫到，不表示没用到，也不表示算法合规。' };
  } else if (d) {
    strength = { verdict: '高风险', why: '存在已废止算法 ' + d + ' 个（MD5/SHA-1/DES 一类）。这一类没有讨论空间：替换前不应进入测评准备。' };
  } else if (n) {
    strength = { verdict: '建议整改', why: '未发现已废止算法，但有非商用密码算法 ' + n + ' 个。按场景评估替换为国密的可行性；PQC 属迁移路线，不能替代国密的合规地位。' };
  } else if (u) {
    strength = { verdict: '无法判定', why: '有 ' + u + ' 个算法缺少元数据，无法分类。补齐元数据后再判定，不要默认通过。' };
  } else {
    strength = { verdict: '合规', why: '清单内 ' + a + ' 个算法均为商用密码算法，且未见已废止与非国密项。这是算法维度的结论，不含参数与实现。' };
  }

  let hardcoded;
  if (!s.pem) {
    hardcoded = { verdict: '无法判定', why: '本次未提供 `--dir`，没有执行 PEM 私钥块扫描。' };
  } else if (s.pem.found.length) {
    hardcoded = { verdict: '高风险', why: '在 ' + s.pem.scannedFiles + ' 个文本文件中命中 ' + s.pem.found.length + ' 处 PEM 私钥块。私钥进版本库即视为已泄露，须轮换。' };
  } else {
    hardcoded = { verdict: '合规', why: '扫描 ' + s.pem.scannedFiles + ' 个文本文件，未见 PEM 私钥块。覆盖范围仅此一类：代码里的 hex/base64 密钥材料、`.env` 口令、外部配置中心不在此列。' };
  }

  const storage = {
    verdict: '无法判定',
    why: 'CBOM 记录的是「用了什么算法」，不记录「哪份数据落在哪里、是否加密、密钥与密文是否分离」。判定存储与传输边界需要数据分类分级、存储介质与链路清单，本工具不采集这些。'
  };

  return { strength: strength, hardcoded: hardcoded, storage: storage };
}

function renderMarkdown(summary) {
  const s = summary;
  const L = [];
  const when = s.timestamp || new Date().toISOString();

  L.push('# 密码应用合规自查报告（预览）');
  L.push('');
  L.push('> 本报告由 `cbom-tools` 根据一份 CycloneDX CBOM 自动生成。它是一份**基于算法名与调用点的静态清单**，不是密评结论，不产生分数，也不能作为通过测评的证据。');
  L.push('');
  L.push('## 一、基本信息');
  L.push('');
  L.push('| 项 | 值 |');
  L.push('| --- | --- |');
  L.push('| BOM 生成时间 | ' + cell(when) + ' |');
  L.push('| 生成工具 | cbom-tools ' + cell(s.tool.version) + ' |');
  L.push('| CBOM 规格 | CycloneDX ' + cell(s.specVersion || '(未标注)') + ' |');
  if (s.scanRoot) L.push('| 扫描根目录 | `' + cell(s.scanRoot) + '` |');
  L.push('| 组件数（算法数） | ' + s.componentCount + ' |');
  L.push('');
  L.push('## 二、口径与边界（先读这一节）');
  L.push('');
  L.push('- **分类依据是算法名到策略表的映射，不是测量结论。** 依据是 GB/T 39786-2021 的要求集：密码应用应采用国家密码管理部门核准的商用密码算法。该标准按第一至第四级分章（第 6–9 章），并在物理和环境、网络和通信、设备和计算、应用和数据四个技术层面分别提出要求；本报告**不区分等级**，只做算法维度的清单。');
  L.push('- **量子安全维度与合规维度是两个正交的轴。** CBOM 里的 `quantumSecurity` 描述抗量子能力：`SM3`、`SM4` 在该维度标为 `weak`（Grover 折半），但它们在密评维度是**合规算法**。把两个轴读成一个，会得出「SM4 是弱算法」这种既不假也没用的结论。');
  L.push('- **本报告不识别密钥长度。** 扫描是文件级的：`RSA` 就是 RSA，既不是 RSA-1024，也不是 RSA-2048。若实际使用 RSA-1024，风险结论需由人工依据实际参数给出。');
  L.push('- **`unknown` 不是「安全」。** 它表示 CBOM 中没有该名称的元数据，需要人工确认。');
  L.push('');
  const v = verdicts(s);
  L.push('## 三、三项判定');
  L.push('');
  L.push('先说结论，再说依据。每一项都写明它覆盖了什么范围——密评专家最先问的不是分数，而是「你到底看了什么」。');
  L.push('');
  L.push('| 判定项 | 结论 | 依据 |');
  L.push('| --- | --- | --- |');
  L.push('| 算法强度 | **' + v.strength.verdict + '** | 3.1 |');
  L.push('| 硬编码风险 | **' + v.hardcoded.verdict + '** | 3.2 |');
  L.push('| 加密存储边界 | **' + v.storage.verdict + '** | 3.3 |');
  L.push('');
  L.push('> 结论只有四种取值：`合规`、`建议整改`、`高风险`、`无法判定`。`无法判定` 不是委婉的「通过」，而是「这个问题超出静态清单能回答的范围，必须由人接手」。');
  L.push('');
  L.push('### 3.1 算法强度');
  L.push('');
  L.push('**结论：' + v.strength.verdict + '**');
  L.push('');
  L.push(v.strength.why);
  L.push('');
  L.push('判据：出现已废止算法即高风险；仅出现非国密算法为建议整改；元数据缺失导致无法分类时，答案是不可判定，不是通过。');
  L.push('');
  L.push('### 3.2 硬编码风险');
  L.push('');
  L.push('**结论：' + v.hardcoded.verdict + '**');
  L.push('');
  L.push(v.hardcoded.why);
  L.push('');
  L.push('### 3.3 加密存储边界');
  L.push('');
  L.push('**结论：' + v.storage.verdict + '**');
  L.push('');
  L.push(v.storage.why);
  L.push('');
  L.push('这一项要的是数据流：哪些字段属于敏感数据、落在磁盘还是内存、传输走哪条链路、密钥与密文是否同处一地。算法清单回答不了它，硬答就是编。');
  L.push('');
  L.push('## 四、汇总');
  L.push('');
  L.push('| 分类 | 算法数 | 出现次数 | 含义 |');
  L.push('| --- | ---: | ---: | --- |');
  for (const b of ['deprecated', 'not_approved', 'unknown', 'construct', 'approved']) {
    L.push('| ' + BUCKET_LABEL[b] + ' | ' + (s.counts[b] || 0) + ' | ' + (s.occurrences[b] || 0) + ' | ' + BUCKET_MEANING[b] + ' |');
  }
  L.push('');

  L.push('## 五、算法明细');
  L.push('');
  L.push('「出现次数」是 CBOM 中的证据条数，不是调用点个数：同一行可能因多条匹配规则（字面量、调用参数、拼接字符串）产生多条证据。判断改哪个文件，看位置，不看数字。');
  L.push('');
  if (!s.rows.length) {
    L.push('本次 CBOM 中没有密码资产。**这不是「合规」，是「没扫到」**——请先确认扫描根目录与文件类型是否覆盖了待评估系统。');
  } else {
    L.push('| 算法 | 分类 | 载荷类型 | 出现次数 | 证据 | 首批位置 |');
    L.push('| --- | --- | --- | ---: | --- | --- |');
    for (const r of s.rows) {
      const label = r.bucket === 'deprecated'
        ? '**' + BUCKET_LABEL[r.bucket] + '**'
        : BUCKET_LABEL[r.bucket] + (r.pqc ? '（PQC）' : '');
      const locs = r.occurrences.slice(0, 3).map((o) => o.location + (o.line ? ':' + o.line : '')).join('<br>');
      const more = r.occurrences.length > 3 ? '<br>… 共 ' + r.occurrences.length + ' 处' : '';
      const count = r.truncatedAt ? '≥' + r.truncatedAt : String(r.count);
      L.push('| ' + cell(r.name) + ' | ' + label + ' | ' + cell(r.primitive || '-') + ' | ' + count + ' | ' + cell(r.methods.join(', ') || '-') + ' | ' + cell(locs || '-') + more + ' |');
    }
  }
  L.push('');

  L.push('## 六、疑似硬编码私钥');
  L.push('');
  if (!s.pem) {
    L.push('未执行。生成本报告时未提供 `--dir`，因此没有做 PEM 私钥块扫描。');
  } else {
    L.push('规则：只匹配 PEM 私钥块头（`-----BEGIN … PRIVATE KEY-----`）。命中是**文件里确实写着私钥块**这一事实，不代表该密钥仍有效或已被使用。');
    L.push('');
    L.push('| 项 | 值 |');
    L.push('| --- | --- |');
    L.push('| 扫描根目录 | `' + cell(s.pem.root) + '` |');
    L.push('| 已扫描文本文件 | ' + s.pem.scannedFiles + ' |');
    L.push('| 命中 PEM 私钥块 | ' + s.pem.found.length + ' |');
    L.push('');
    if (s.pem.found.length) {
      L.push('| 位置 | 类型 |');
      L.push('| --- | --- |');
      for (const f of s.pem.found.slice(0, 20)) {
        L.push('| `' + cell(f.location) + ':' + f.line + '` | ' + cell(f.label) + ' |');
      }
      if (s.pem.found.length > 20) L.push('| … 其余 ' + (s.pem.found.length - 20) + ' 处见 CBOM 扫描输出 |  |');
      L.push('');
    }
    L.push('不在检测范围：散落在代码里的 hex/base64 密钥材料、`.env` 中的口令、证书（公开信息）、密钥派生逻辑。这些都需要人工审阅。');
  }
  L.push('');

  L.push('## 七、未评估项（需人工确认）');
  L.push('');
  L.push('| 项目 | 为什么不在本报告内 | 建议核对方式 |');
  L.push('| --- | --- | --- |');
  L.push('| 密钥长度与参数 | 文件级扫描拿不到参数 | 逐调用点核对（如 RSA 位数、SM2 曲线） |');
  L.push('| 密钥生存周期 | 属 GB/T 39786-2021 附录 B 的管理要求，静态扫描看不到 | 查密钥生成、分发、更新、销毁流程与记录 |');
  L.push('| 随机数质量 | 取决于运行时实现 | 核对是否使用经批准的随机数发生器 |');
  L.push('| 密码产品认证 | 属产品资质，不是代码属性 | 核对密码模块/产品的认证证书 |');
  L.push('| 协议实现正确性 | 需要协议级测试 | 按接口逐项做功能与异常测试 |');
  L.push('| 侧信道与故障注入 | 需要实验环境（TVLA 等） | 见 `docs/research/` 下的威胁模型与测量记录 |');
  L.push('| 非 PEM 形式的硬编码密钥 | 检测规则只覆盖 PEM 块 | 代码审计 + 密钥管理系统盘点 |');
  L.push('');

  L.push('## 八、建议');
  L.push('');
  const d = s.counts.deprecated || 0;
  const n = s.counts.not_approved || 0;
  const u = s.counts.unknown || 0;
  if (d) {
    L.push('1. **先处理已废止算法（' + d + ' 个）**：这是唯一无需讨论的整改项，替换前不应进入测评准备阶段。');
  }
  if (n) {
    L.push((d ? 2 : 1) + '. **非商用密码算法（' + n + ' 个）**：按业务场景评估替换为国密算法（SM2/SM3/SM4）的可行性；确实无法替换的，在密码应用方案中写明理由与替代措施。PQC 算法属迁移路线，不能替代国密算法的合规地位。');
  }
  if (u) {
    L.push((d && n ? 3 : (d || n ? 2 : 1)) + '. **未知分类（' + u + ' 个）**：补齐元数据后再判断，不要默认通过。');
  }
  if (!d && !n && !u) {
    L.push('算法维度未见需要整改的项。**这不等于合规**：见第七节未评估项。');
  }
  L.push('');
  L.push('## 九、复现');
  L.push('');
  L.push('```bash');
  L.push('# 1) 生成 CBOM');
  L.push('npx cbom-tools scan --dir <path> --out cbom.json');
  L.push('# 2) 生成本报告');
  L.push('npx cbom-tools compliance --bom cbom.json --dir <path> --out 密评自查报告.md');
  L.push('```');
  L.push('');
  L.push('本文件由机器生成，内容会随代码变化。不要把它当作固定结论引用。');
  L.push('');
  return L.join('\n');
}

// ── CLI ──────────────────────────────────────────────────────────────

const USAGE = 'usage: cbom-compliance --bom <file> [--dir <path>] [--out <file>] [--format md|json]';

function readFlag(args, name) {
  const eq = name + '=';
  let value = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name) {
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) return { error: name + ' needs a value' };
      value = next;
    } else if (args[i].startsWith(eq)) {
      value = args[i].slice(eq.length);
    }
  }
  if (value === '') return { error: name + ' needs a value' };
  return { value };
}

function fail(message) {
  console.error(USAGE);
  console.error('  ' + message);
  process.exit(2);
}

function main() {
  const args = process.argv.slice(2);
  const bomFlag = readFlag(args, '--bom');
  if (bomFlag.error) fail(bomFlag.error);
  if (bomFlag.value === null) fail('--bom is required');

  const dirFlag = readFlag(args, '--dir');
  if (dirFlag.error) fail(dirFlag.error);
  const outFlag = readFlag(args, '--out');
  if (outFlag.error) fail(outFlag.error);
  const fmtFlag = readFlag(args, '--format');
  if (fmtFlag.error) fail(fmtFlag.error);
  const format = fmtFlag.value === null ? 'md' : fmtFlag.value;
  if (format !== 'md' && format !== 'json') fail('--format must be md or json');

  let bom;
  try {
    bom = JSON.parse(fs.readFileSync(bomFlag.value, 'utf-8'));
  } catch (err) {
    fail('cannot read ' + bomFlag.value + ' (' + (err.code || err.message) + ')');
  }
  if (!bom || bom.bomFormat !== 'CycloneDX') {
    fail(bomFlag.value + ' is not a CycloneDX document (bomFormat=' + (bom && bom.bomFormat) + ')');
  }

  let pem = null;
  if (dirFlag.value) {
    const root = path.resolve(dirFlag.value);
    let st;
    try { st = fs.statSync(root); } catch (err) { fail('--dir not found: ' + root); }
    if (!st.isDirectory()) fail('--dir is not a directory: ' + root);
    const r = scanPrivateKeyBlocks(root);
    pem = { root, scannedFiles: r.scannedFiles, found: r.found, skipped: r.skipped };
  }

  const summary = summarise(bom, { dir: dirFlag.value || '', pem });
  const out = format === 'json' ? JSON.stringify(summary, null, 2) : renderMarkdown(summary);

  if (outFlag.value) {
    fs.writeFileSync(outFlag.value, out, 'utf-8');
    console.error('cbom-compliance: wrote ' + outFlag.value + ' (' + summary.componentCount + ' algorithms, deprecated=' + summary.counts.deprecated + ', not_approved=' + summary.counts.not_approved + ')');
  } else {
    process.stdout.write(out);
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = {
  verdicts,
  classify,
  familyOf,
  collect,
  summarise,
  renderMarkdown,
  scanPrivateKeyBlocks,
  cell,
  BUCKET_LABEL,
  APPROVED,
  PQC_FAMILIES,
};
