'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const { partitionRoots, buildModules } = require('./config');
const { iterate, compilePatterns } = require('./core/walk');
const { collectArtifacts, buildIndex } = require('./core/artifacts');
const { resolveClaim, explain } = require('./core/resolve');
const { readArtifactCache, writeArtifactCache } = require('./core/cache');
const { compareValues, valueFromString, normKey } = require('./core/normalize');
const { scanFiles } = require('./pooled-scan');
const { appendRun, readRuns, HISTORY_SCHEMA } = require('./history');

/**
 * 服务层：编排「扫文档 → 收产出物 → 绑定 → 判定 → 统计 → 门禁」。
 * 不依赖 http / cli 任何类型。
 */

function labelFor(rootAbs, rel, isFileRoot) {
  if (isFileRoot) return rel;
  const base = path.basename(rootAbs);
  return base ? base + '/' + rel : rel;
}

function listDocFiles(cfg) {
  const { dirs, files, missing } = partitionRoots(cfg.docs.roots, cfg.__baseDir || cfg.__cwd);
  const includeRe = compilePatterns(cfg.docs.include);
  const out = [];
  const seen = new Set();

  for (const f of files) {
    const key = path.resolve(f.abs);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ full: f.abs, rel: f.rel, size: fs.statSync(f.abs).size });
  }
  for (const d of dirs) {
    for (const f of iterate(d.abs, {
      exclude: cfg.docs.exclude,
      matchInclude: (rel) => includeRe.some((re) => re.test(rel)),
      maxFileBytes: cfg.docs.maxFileBytes,
      maxFiles: cfg.docs.maxFiles,
      maxDepth: cfg.docs.maxDepth
    })) {
      const key = path.resolve(f.full);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ full: f.full, rel: labelFor(d.abs, f.rel, false), size: f.size });
    }
  }
  return { files: out, missing };
}

function matchesFile(value, pattern) {
  if (!pattern) return true;
  const re = compilePatterns([pattern]);
  return re.some((r) => r.test(value));
}

function applyBinding(claim, cfg) {
  for (const b of cfg.bindings || []) {
    if (b.key && normKey(b.key) !== normKey(claim.key)) continue;
    if (b.module && claim.module !== b.module) continue;
    if (b.kind && b.kind !== claim.kind) continue;
    if (b.file && !matchesFile(claim.file, b.file)) continue;
    return b;
  }
  return null;
}

function matchRule(list, claim) {
  for (const r of list || []) {
    if (r.key && normKey(r.key) !== normKey(claim.key)) continue;
    if (r.kind && r.kind !== claim.kind) continue;
    if (r.file && !matchesFile(claim.file, r.file)) continue;
    // module: null 是有效写法 =「没识别出模块的行」；不写 module 则不限制
    if (r.module !== undefined && (claim.module || null) !== r.module) continue;
    return r;
  }
  return null;
}

function denyRule(claim, cfg) {
  return matchRule(cfg.deny, claim);
}

function isDenied(claim, cfg) {
  return !!denyRule(claim, cfg);
}

function isIgnored(claim, cfg) {
  return !!matchRule(cfg.ignore, claim);
}

/**
 * 哈希存证目录（sealed）：返回命中的那条 glob，未命中返回 null。
 *
 * 存在理由：`www/docs/tsa/**` 里的文件本身就是 TSA 时间戳的对象，
 * 插一行 `<!-- verifact: ... -->` 就改变哈希、破坏存证。disposition 要改文件，
 * 所以这条路走不通；ignore/deny 又只能按 key/kind 逐条写、治不了「整个目录」。
 * sealed 是目录级的「连碰都不碰」声明。
 */
function sealedPattern(claim, cfg) {
  for (const p of cfg.sealed || []) {
    if (matchesFile(claim.file, p)) return p;
  }
  return null;
}

function evaluateGate(stats, policy) {
  const failOn = policy || 'drift';
  if (failOn === 'none') return { failed: false, policy: failOn };
  if (failOn === 'review') {
    return { failed: stats.drift + stats.ambiguous + stats.unbound + stats.refMissing > 0, policy: failOn };
  }
  if (failOn === 'lint-high') {
    return { failed: stats.lintHigh > 0, policy: failOn };
  }
  return { failed: stats.drift > 0, policy: 'drift' };
}

async function run(cfg, opts) {
  const options = opts || {};
  const startedAt = Date.now();
  const log = options.logger || require('./logger').create({ quiet: true });
  const modules = buildModules(cfg.modules);

  // 1) 文档清单 + 并行抽取
  const listed = listDocFiles(cfg);
  const scan = await scanFiles(listed.files, {
    modules,
    deep: !!options.deep,
    maxBytes: cfg.docs.maxFileBytes,
    doLint: cfg.lint.enabled,
    lintOpts: cfg.lint,
    concurrency: options.concurrency
  });

  // 处置声明解析失败必须让整次运行失败。若只记成 docScanErrors，这份文档的声明会
  // 静默消失，报告少了一整片数字却仍然绿色 —— 那正是本工具反对的假绿。
  const fatal = scan.errors.filter((e) => e && e.fatal);
  if (fatal.length) {
    const lines = fatal.map((e) => (e.detail ? e.detail : e.rel + ': ' + e.reason));
    const err = new Error('处置声明解析失败（' + fatal.length + ' 处）：\n  ' + lines.join('\n  '));
    err.name = 'DispositionError';
    err.fatal = fatal;
    throw err;
  }

  const claims = [];
  const lintFindings = [];
  for (const r of scan.results) {
    for (const c of r.claims) claims.push(c);
    for (const l of r.lint) lintFindings.push(l);
  }

  // 2) 产出物（带指纹增量缓存）
  const artifactRoots = partitionRoots(cfg.artifacts.roots, cfg.__baseDir || cfg.__cwd);
  const absRoots = artifactRoots.dirs.map((d) => d.abs).concat(artifactRoots.files.map((f) => f.abs));
  const cached = (cfg.cache.enabled && !options.noCache)
    ? readArtifactCache(cfg, cfg.__cwd, absRoots)
    : { hit: false, reason: 'disabled' };

  let artifacts;
  let cacheState = cached.hit ? 'hit' : 'miss';
  if (cached.hit) {
    artifacts = { entries: cached.entries, presence: cached.presence, scanned: cached.scanned, skipped: cached.skipped, fileLines: cached.fileLines || [] };
  } else {
    const t0 = Date.now();
    artifacts = collectArtifacts(cfg, modules);
    writeArtifactCache(cfg, cfg.__cwd, absRoots, artifacts);
    log.info('artifact_index_rebuilt', { ms: Date.now() - t0, entries: artifacts.entries.length });
  }

  // 自证清洗：既是文档又是产出物的文件必须踢出去，否则会出现「README 自己给自己作证」
  let selfRemoved = 0;
  const docAbs = new Set(listed.files.map((f) => path.resolve(f.full)));
  if (!options.allowSelfEvidence) {
    const before = artifacts.entries.length;
    artifacts.entries = artifacts.entries.filter((e) => !e.abs || !docAbs.has(e.abs));
    selfRemoved = before - artifacts.entries.length;
    if (selfRemoved) log.info('self_evidence_filtered', { removed: selfRemoved });
  }

  const index = buildIndex(artifacts);

  // 3) 逐条判定
  const results = [];
  const stats = {
    docs: listed.files.length,
    artifacts: artifacts.entries.length,
    // claims 仍是「进入判定」的条数（code-artifact 且未被 ignore/deny）——语义不变。
    claims: 0, verified: 0, drift: 0, ambiguous: 0, unbound: 0,
    refFound: 0, refMissing: 0, ignored: 0, denied: 0,
    // 新增维度：处置分类。claimsTotal = 抽到的全部声明（含 ignored/denied），
    // dispositioned = 因处置分类而未进入判定的条数。
    claimsTotal: claims.length, dispositioned: 0, dispositionCounts: {},
    standardRefs: 0, sealed: 0
  };

  // sealed 规则命中率：一条规则零命中就是「配了但没生效」，
  // 滴漏地让人以为存证目录已受保护——必须报出来。
  const sealedHits = new Map((cfg.sealed || []).map((p) => [p, 0]));

  for (const claim of claims) {
    // 标准编号引用（`FIPS 203/205`、`GB/T 32918/32905`）：形状是比值，语义不是。
    // 提取层已标记，这里单列计数：不进判定、不进覆盖率分母，但必须能在报告里被看见。
    // 放在 deny 之前——它是抽取层的真相，不该被配置层的规则再摆一道。
    if (claim.notMeasurement) {
      stats.standardRefs++;
      results.push(Object.assign({}, claim, {
        status: 'reference',
        note: '标准编号引用（' + claim.notMeasurement + '）：不按比值解析'
      }));
      continue;
    }

    // 哈希存证目录：连碰都不碰。放在 deny 之前——目录级保护比逐条规则更强。
    const sealedBy = sealedPattern(claim, cfg);
    if (sealedBy) {
      stats.sealed++;
      sealedHits.set(sealedBy, (sealedHits.get(sealedBy) || 0) + 1);
      results.push(Object.assign({}, claim, {
        status: 'sealed',
        note: '哈希存证目录（sealed: ' + sealedBy + '）：不能插注释，不参与判定'
      }));
      continue;
    }

    // 优先级：deny > disposition > ignore > 正常判定（RFC §3.5）。
    // deny 是结构性的（对照组不能比），优先于任何作者声明。
    if (isDenied(claim, cfg)) {
      stats.denied++;
      const rule = denyRule(claim, cfg);
      results.push(Object.assign({}, claim, {
        status: 'denied',
        note: '拒绝自动绑定' + (rule && rule.note ? '：' + rule.note : '')
      }));
      continue;
    }

    const disposition = claim.disposition || 'code-artifact';
    const judgedDisposition = claim.disposition && claim.disposition !== 'code-artifact';
    if (judgedDisposition) {
      // 声明者已表态：这条数字不是产物属性。它不进判定，也不进覆盖率分母，
      // 但仍然逐条留在报告里（status=disposition），不允许静默丢弃。
      stats.dispositioned++;
      results.push(Object.assign({}, claim, {
        status: 'disposition',
        note: '处置分类：' + disposition + (claim.dispositionArgs ? '（' + Object.keys(claim.dispositionArgs).map((k) => k + '=' + claim.dispositionArgs[k]).join(' ') + '）' : '')
      }));
      continue;
    }

    if (isIgnored(claim, cfg)) {
      stats.ignored++;
      const rule = matchRule(cfg.ignore, claim);
      // why 不只用于校验：它要跟着声明一起进报告，否则「为什么忽略」就只活在配置里。
      results.push(Object.assign({}, claim, {
        status: 'ignored',
        note: '命中 ignore 规则' + (rule && rule.why ? '：' + rule.why : '')
      }));
      continue;
    }
    stats.claims++;

    const binding = applyBinding(claim, cfg);
    if (binding && binding.expect != null) {
      const expect = valueFromString(String(binding.expect));
      const cmp = compareValues(claim.value, expect, cfg.resolve);
      if (cmp.equal) stats.verified++; else stats.drift++;
      results.push(Object.assign({}, claim, {
        status: cmp.equal ? 'verified' : 'drift',
        score: 1, cmp, note: '人工显式绑定',
        best: { source: '<binding>', path: binding.key || claim.key, value: expect }
      }));
      continue;
    }

    const res = resolveClaim(claim, index, cfg.resolve);
    if (res.status === 'verified') stats.verified++;
    else if (res.status === 'drift') stats.drift++;
    else if (res.status === 'ambiguous') stats.ambiguous++;
    else if (res.status === 'ref-found') stats.refFound++;
    else if (res.status === 'ref-missing') stats.refMissing++;
    else stats.unbound++;

    results.push(Object.assign({}, claim, res, { note: explain(res) }));
  }

  // 处置分布：只统计「作者表过态」的声明。ignored 与 denied 都不是作者的分类判断，
  // 各自单独计数、不重复计入这里。denied 若混进来，会以默认值 code-artifact 落进桶里，
  // 报告就出现「处置分类 code-artifact 247」而「分母 246」（1 条拒绑的差，#102）。
  stats.dispositionCounts = { 'code-artifact': 0, 'measured-once': 0, progress: 0, narrative: 0 };
  for (const c of results) {
    if (c.status === 'ignored' || c.status === 'denied' || c.status === 'reference' || c.status === 'sealed') continue;
    const key = c.disposition || 'code-artifact';
    if (stats.dispositionCounts[key] == null) stats.dispositionCounts[key] = 0;
    stats.dispositionCounts[key]++;
  }
  // code-artifact 桶与覆盖率分母必须同源：进入判定的条数只从一个地方来，
  // 不允许两处各算一次（那正是 #102 的成因）。
  const codeArtifactClaims = stats.claims;

  // 反洗白警示：整份文件一条 code-artifact 都没有 → 单列出来的文件级声明；
  // 全报告非 code-artifact 占比 > 50% → 顶部警示。没有这两条，整文件标注就成了
  // 「把分母搬走」的合法外衣。
  const perFile = new Map();
  for (const c of results) {
    if (c.status === 'ignored' || c.status === 'reference' || c.status === 'sealed') continue;
    if (!perFile.has(c.file)) perFile.set(c.file, []);
    perFile.get(c.file).push(c);
  }
  const fullyDispositionedFiles = [];
  for (const [file, list] of perFile) {
    if (!list.length) continue;
    if (list.every((c) => (c.disposition || 'code-artifact') !== 'code-artifact')) {
      fullyDispositionedFiles.push({ file, claims: list.length });
    }
  }
  const judgedTotal = codeArtifactClaims + stats.dispositioned;
  // 同一文件里完全相同的两条声明（同一行写了两次同一个数，或复制粘贴的残骸）：
  // 它们有两个身份，但作者大概不知道。报告要指出来，否则「重复」永远没人收拾。
  const dupGroups = new Map();
  for (const c of results) {
    if (!(c.stableKeyGroupSize > 1)) continue;
    const base = String(c.stableKey).replace(/#\d+$/, '');
    if (!dupGroups.has(base)) dupGroups.set(base, []);
    dupGroups.get(base).push(c);
  }
  const duplicateClaims = [];
  for (const [stableKey, list] of dupGroups) {
    duplicateClaims.push({
      stableKey,
      file: list[0].file,
      key: list[0].key,
      kind: list[0].kind,
      value: list[0].value ? list[0].value.raw : null,
      lines: list.map((c) => c.line),
      ids: list.map((c) => c.id)
    });
  }
  stats.duplicateClaimGroups = duplicateClaims.length;

  stats.dispositionWarnings = {
    fullyDispositionedFiles,
    share: judgedTotal ? stats.dispositioned / judgedTotal : 0,
    shareExceedsHalf: judgedTotal > 0 && stats.dispositioned / judgedTotal > 0.5
  };

  // sealed 规则零命中 = 规则写了但没生效（路径写错、或目录被改名）。
  // 不说的话，存证目录就处在「以为被保护、实际在裸奔」的状态。
  stats.sealedWarnings = { emptyPatterns: [...sealedHits.entries()].filter(([, n]) => n === 0).map(([p]) => p) };

  // 跨文档互证：同一个键在不同文档里给了不同的值（没有产出物可锚时的第二层信号）
  let crossDoc = [];
  if (!cfg.crossDoc || cfg.crossDoc.enabled !== false) {
    crossDoc = require('./core/crossdoc').crossDocCheck(results, cfg.crossDoc || {});
  }

  const lintCounts = { high: 0, medium: 0, low: 0 };
  for (const f of lintFindings) if (lintCounts[f.severity] != null) lintCounts[f.severity]++;

  const withGate = Object.assign({ lintHigh: lintCounts.high }, stats);
  const gate = evaluateGate(withGate, cfg.gate.failOn);

  const report = {
    schema: 'verifact-report/2',
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    config: {
      configFile: cfg.__configFile,
      cwd: cfg.__cwd,
      baseDir: cfg.__baseDir,
      docsRoots: cfg.docs.roots,
      artifactRoots: cfg.artifacts.roots,
      minScore: cfg.resolve.minScore,
      relTolerance: cfg.resolve.relTolerance,
      modules: modules.length,
      failOn: cfg.gate.failOn
    },
    meta: {
      cache: cacheState,
      cacheReason: cached.reason || null,
      workers: scan.workers || 0,
      pooled: !!scan.pooled,
      docsMissing: listed.missing,
      docScanErrors: scan.errors.length,
      artifactsScanned: artifacts.scanned,
      artifactsSkipped: artifacts.skipped,
      selfEvidenceRemoved: selfRemoved
    },
    counts: Object.assign({
      lint: lintFindings.length,
      crossDoc: crossDoc.length,
      crossDocWarn: crossDoc.filter((x) => x.severity === 'warn').length,
      // 双分母：覆盖率必须能同时说出「以 code-artifact 为分母」和「以全部受判声明为分母」。
      // 受判 = 进入判定的 + 作者声明非产物属性的 + 被拒绑的（拒绑也是判定结论，只是不绑定）。
      codeArtifactClaims,
      allJudgedClaims: codeArtifactClaims + stats.dispositioned + stats.denied
    }, stats),
    lintCounts,
    gate,
    claims: results,
    duplicateClaims,
    crossDoc,
    lint: lintFindings
  };

  if (cfg.cache.enabled && !options.noCache) {
    // state map 只收录非 unbound 的声明：unbound 占比高且没有迁移信息量。
    // 键是 stableKey（内容寻址），不是含行号的 id —— 否则在声明上方插一行注释，
    // 整份文件的身份全部改名，drift 历史会把排版改动读成大规模迁移（#96）。
    const states = {};
    for (const c of results) if (c.status !== 'unbound') states[c.stableKey] = c.status;
    // 先读后写：读出来的 legacyDropped 说明有多少条 schema 1 记录被丢弃，
    // 用户需要知道「这次比较的基准为什么变短了」，否则会以为工具丢了数据。
    const prevRuns = readRuns(cfg, cfg.__cwd, 1);
    const legacyDropped = (prevRuns && prevRuns.legacyDropped) || 0;
    const appended = appendRun(cfg, cfg.__cwd, {
      schema: HISTORY_SCHEMA,
      generatedAt: report.generatedAt,
      durationMs: report.durationMs,
      counts: report.counts,
      lintCounts: report.lintCounts,
      gate: report.gate,
      cache: cacheState,
      states
    });
    if (appended) report.meta.history = { schema: HISTORY_SCHEMA, legacyDropped };
  }

  return report;
}

module.exports = { run, evaluateGate, listDocFiles, applyBinding, isIgnored, isDenied, denyRule, sealedPattern, labelFor };
