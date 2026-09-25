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
const { appendRun } = require('./history');

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
  const { dirs, files, missing } = partitionRoots(cfg.docs.roots, cfg.__cwd);
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

function isIgnored(claim, cfg) {
  return (cfg.ignore || []).some((ig) => {
    if (ig.key && normKey(ig.key) !== normKey(claim.key)) return false;
    if (ig.kind && ig.kind !== claim.kind) return false;
    if (ig.file && !matchesFile(claim.file, ig.file)) return false;
    return true;
  });
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

  const claims = [];
  const lintFindings = [];
  for (const r of scan.results) {
    for (const c of r.claims) claims.push(c);
    for (const l of r.lint) lintFindings.push(l);
  }

  // 2) 产出物（带指纹增量缓存）
  const artifactRoots = partitionRoots(cfg.artifacts.roots, cfg.__cwd);
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
    claims: 0, verified: 0, drift: 0, ambiguous: 0, unbound: 0,
    refFound: 0, refMissing: 0, ignored: 0
  };

  for (const claim of claims) {
    if (isIgnored(claim, cfg)) {
      stats.ignored++;
      results.push(Object.assign({}, claim, { status: 'ignored', note: '命中 ignore 规则' }));
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
    schema: 'verifact-report/1',
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    config: {
      configFile: cfg.__configFile,
      cwd: cfg.__cwd,
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
    counts: Object.assign({ lint: lintFindings.length, crossDoc: crossDoc.length, crossDocWarn: crossDoc.filter((x) => x.severity === 'warn').length }, stats),
    lintCounts,
    gate,
    claims: results,
    crossDoc,
    lint: lintFindings
  };

  if (cfg.cache.enabled && !options.noCache) {
    // state map 只收录非 unbound 的声明：unbound 占比高且没有迁移信息量。
    // id 形如 <file>:L<line>:<kind>:<key>，同一行同键的两条声明会合并，够看趋势即可。
    const states = {};
    for (const c of results) if (c.status !== 'unbound') states[c.id] = c.status;
    appendRun(cfg, cfg.__cwd, {
      generatedAt: report.generatedAt,
      durationMs: report.durationMs,
      counts: report.counts,
      lintCounts: report.lintCounts,
      gate: report.gate,
      cache: cacheState,
      states
    });
  }

  return report;
}

module.exports = { run, evaluateGate, listDocFiles, applyBinding, isIgnored, labelFor };
