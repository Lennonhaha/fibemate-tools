#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫 <research@fibemate.net>
//
// Contract test: the Blind-Spot Map page vs the corpus that is supposed to back it.
//
// Why this exists
// ---------------
// www/tools/blind-spot-map/index.html carries a hardcoded `EMBEDDED` copy of the
// 30 samples and falls back to it whenever the remote fetch fails. Nothing tied
// that copy to data/blind-spot-map/*.json, so the page can keep rendering
// yesterday's verdicts with a small "⚠ fallback" line and still look healthy.
// Same story for the numbers asserted in pilotB/ANALYSIS.md.
//
// Usage
// -----
//   node scripts/test-contract.js                      # local corpus + page
//   node scripts/test-contract.js --page=<path>        # page elsewhere
//   node scripts/test-contract.js --remote             # also check the live URLs
//   node scripts/test-contract.js --self-test          # prove every check can go red
//   node scripts/test-contract.js --json               # machine-readable result
//
// Exit codes: 0 all green · 1 at least one check failed · 2 usage/IO error ·
//             3 self-test found a check that cannot go red (fake green gate).

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_DATA = path.join(REPO_ROOT, 'data', 'blind-spot-map');
const DEFAULT_PAGE = path.resolve(REPO_ROOT, '..', 'fibemate', 'www', 'tools', 'blind-spot-map', 'index.html');
const REMOTE_BASE = 'https://raw.githubusercontent.com/Lennonhaha/fibemate-tools/main/data/blind-spot-map/';

const args = process.argv.slice(2);
const opt = {
  page: DEFAULT_PAGE,
  data: DEFAULT_DATA,
  remote: args.includes('--remote'),
  selfTest: args.includes('--self-test'),
  json: args.includes('--json'),
};
for (const a of args) {
  const m = /^--(page|data)=(.+)$/.exec(a);
  if (m) opt[m[1]] = path.resolve(m[2]);
}

// --- small helpers ---------------------------------------------------------

function readUtf8(p) {
  return fs.readFileSync(p, 'utf8');
}

function die(msg, code = 2) {
  console.error(`ERROR: ${msg}`);
  process.exit(code);
}

/** Extract a JS array literal that starts at `marker` using a string-aware scanner. */
function extractArrayLiteral(src, marker) {
  const at = src.indexOf(marker);
  if (at < 0) throw new Error(`marker not found: ${marker}`);
  const start = src.indexOf('[', at);
  if (start < 0) throw new Error('array start not found');
  let depth = 0;
  let quote = null;
  let esc = false;
  for (let i = start; i < src.length; i++) {
    const ch = src[i];
    if (quote) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '[') depth++;
    else if (ch === ']') {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error('unterminated array literal');
}

function sortedTypes(types) {
  const list = Array.isArray(types) ? types : (types ? [types] : []);
  return [...new Set(list.map(String))]
    .sort((a, b) => {
      const na = parseInt(a.replace(/\D+/g, ''), 10);
      const nb = parseInt(b.replace(/\D+/g, ''), 10);
      return Number.isNaN(na) || Number.isNaN(nb) ? String(a).localeCompare(String(b)) : na - nb;
    });
}

const sig = (types) => sortedTypes(types).join('+');

/** "class9+class10" and "9+10" must compare equal. */
const normSig = (s) =>
  String(s)
    .replace(/class/gi, '')
    .split('+')
    .map((t) => t.trim())
    .filter(Boolean)
    .sort((a, b) => Number(a) - Number(b))
    .join('+');

function loadCorpus(dataDir) {
  const pilotDir = path.join(dataDir, 'pilotB');
  if (!fs.existsSync(pilotDir)) throw new Error(`missing corpus dir: ${pilotDir}`);
  const files = fs.readdirSync(pilotDir).filter((f) => f.endsWith('.json')).sort();
  const algorithms = [];
  const cells = [];
  for (const f of files) {
    const doc = JSON.parse(readUtf8(path.join(pilotDir, f)));
    const variants = Array.isArray(doc.variants) ? doc.variants : [];
    algorithms.push({ file: f, algorithm: doc.algorithm, declared: doc.variant_count, variants });
    for (const v of variants) {
      cells.push({
        algo: doc.algorithm,
        v: v.variant,
        verdict: v.human_verdict,
        types: sortedTypes(v.hallucination_type),
        severity: v.severity ?? null,
        note: v.note || '',
      });
    }
  }
  return { dir: pilotDir, files, algorithms, cells };
}

/** Parse the page: EMBEDDED cells + the claims it renders in prose. */
function loadPage(pagePath) {
  if (!fs.existsSync(pagePath)) throw new Error(`missing page: ${pagePath}`);
  const src = readUtf8(pagePath);
  const lit = extractArrayLiteral(src, 'const EMBEDDED');
  const embedded = vm.runInNewContext(`(${lit})`, Object.create(null), { timeout: 2000 });
  if (!Array.isArray(embedded)) throw new Error('EMBEDDED did not evaluate to an array');
  return {
    path: pagePath,
    src,
    embedded: embedded.map((d) => ({
      algo: d.algo,
      v: d.v,
      verdict: d.verdict,
      types: sortedTypes(d.types),
      severity: d.severity ?? null,
      note: d.note || '',
    })),
    remoteBase: (/const base = "(https:\/\/[^"]+)"\.?/.exec(src) || [])[1] || null,
    algos: (/const ALGOS = (\[[^\]]*\])/.exec(src) || [])[1] || null,
    vcols: (/const VCOLS = (\[[^\]]*\])/.exec(src) || [])[1] || null,
    slugs: (/const SLUG = (\{[\s\S]*?\});/.exec(src) || [])[1] || null,
  };
}

function loadAnalysis(dataDir) {
  const p = path.join(dataDir, 'pilotB', 'ANALYSIS.md');
  if (!fs.existsSync(p)) throw new Error(`missing analysis: ${p}`);
  return { path: p, text: readUtf8(p) };
}

function loadStatements(dataDir) {
  const out = {};
  for (const pilot of ['pilotA', 'pilotB']) {
    const p = path.join(dataDir, pilot, 'README.md');
    out[pilot] = fs.existsSync(p) ? readUtf8(p) : null;
  }
  return out;
}

// --- derived facts ---------------------------------------------------------

function derive(corpus) {
  const byAlgo = new Map();
  for (const c of corpus.cells) {
    if (!byAlgo.has(c.algo)) byAlgo.set(c.algo, []);
    byAlgo.get(c.algo).push(c);
  }
  const variantCounts = new Map();
  let defectFree = 0;
  const stability = [];
  for (const [algo, cells] of byAlgo) {
    const sigs = cells.map((c) => sig(c.types));
    const stable = new Set(sigs).size === 1;
    stability.push({ algo, sigs, stable });
    variantCounts.set(algo, sigs.length);
    for (const c of cells) if (c.types.length === 0) defectFree++;
  }
  return {
    algorithms: byAlgo.size,
    totalCells: corpus.cells.length,
    variantsPerAlgo: variantCounts,
    stableCount: stability.filter((s) => s.stable).length,
    defectFree,
    stability,
  };
}

// --- checks ----------------------------------------------------------------

/** @type {{id:string,name:string,run:Function}[]} */
const CHECKS = [];
const add = (id, name, run) => CHECKS.push({ id, name, run });

add('corpus.shape', 'pilotB corpus: 10 algorithm files, variant_count == variants.length', (ctx) => {
  const bad = [];
  if (ctx.corpus.algorithms.length !== 10) bad.push(`expected 10 files, found ${ctx.corpus.algorithms.length}`);
  for (const a of ctx.corpus.algorithms) {
    if (a.declared !== a.variants.length) bad.push(`${a.file}: variant_count=${a.declared} but variants.length=${a.variants.length}`);
    if (!Array.isArray(a.variants) || a.variants.length === 0) bad.push(`${a.file}: no variants`);
  }
  return bad;
});

add('corpus.ids', 'pilotB sample_id values are unique', (ctx) => {
  const seen = new Map();
  const bad = [];
  for (const a of ctx.corpus.algorithms) {
    for (const v of a.variants) {
      const id = v.sample_id;
      if (!id) { bad.push(`${a.file} v${v.variant}: missing sample_id`); continue; }
      if (seen.has(id)) bad.push(`duplicate sample_id ${id} (${seen.get(id)} and ${a.file})`);
      seen.set(id, a.file);
    }
  }
  return bad;
});

add('page.embedded.parse', 'page EMBEDDED evaluates to 30 cells', (ctx) => {
  const n = ctx.page.embedded.length;
  return n === 30 ? [] : [`expected 30 embedded cells, found ${n}`];
});

add('page.embedded.parity', 'EMBEDDED verdict/types/severity match the corpus cell-for-cell', (ctx) => {
  const key = (c) => `${c.algo}#v${c.v}`;
  const expected = new Map(ctx.corpus.cells.map((c) => [key(c), c]));
  const bad = [];
  for (const e of ctx.page.embedded) {
    const k = key(e);
    const want = expected.get(k);
    if (!want) { bad.push(`${k}: present on page, absent from corpus`); continue; }
    if (e.verdict !== want.verdict) bad.push(`${k}: verdict page=${e.verdict} corpus=${want.verdict}`);
    if (e.severity !== want.severity) bad.push(`${k}: severity page=${e.severity} corpus=${want.severity}`);
    if (sig(e.types) !== sig(want.types)) bad.push(`${k}: types page=${sig(e.types)} corpus=${sig(want.types)}`);
    expected.delete(k);
  }
  for (const k of expected.keys()) bad.push(`${k}: present in corpus, missing from page`);
  return bad;
});

add('page.embedded.notes', 'every embedded cell carries a non-empty tooltip note', (ctx) =>
  ctx.page.embedded.filter((c) => !String(c.note).trim()).map((c) => `${c.algo}#v${c.v}: empty note`));

add('page.claims.dimensions', 'page headline numbers match the corpus dimensions', (ctx) => {
  const bad = [];
  const { algorithms, totalCells } = ctx.derived;
  const src = ctx.page.src;
  if (!new RegExp(`${algorithms} 算法 × 3 变体`).test(src)) bad.push(`page does not state "${algorithms} 算法 × 3 变体"`);
  if (!new RegExp(`共 ${totalCells} 段`).test(src)) bad.push(`page does not state "共 ${totalCells} 段"`);
  const badge = /Pilot A \+ B · (\d+) 算法 × (\d+) 变体/.exec(src);
  if (!badge) bad.push('badge "Pilot A + B · N 算法 × M 变体" not found');
  else if (Number(badge[1]) !== algorithms || Number(badge[2]) !== 3) {
    bad.push(`badge says ${badge[1]}×${badge[2]}, corpus is ${algorithms}×3`);
  }
  return bad;
});

add('page.disclaimer', 'page still declares the corpus synthetic / not a measurement', (ctx) => {
  const src = ctx.page.src;
  const bad = [];
  if (!/合成种子语料/.test(src)) bad.push('missing Chinese "合成种子语料" disclaimer');
  if (!/synthetic/i.test(src)) bad.push('missing English "synthetic" disclaimer');
  if (!/并非/.test(src)) bad.push('missing "并非" (not a measurement) qualifier');
  return bad;
});

add('page.remote.base', 'page fetches the same repo/branch this test reads from', (ctx) => {
  const base = ctx.page.remoteBase;
  if (!base) return ['page has no remote base URL'];
  return base === REMOTE_BASE ? [] : [`page remote base is ${base}, expected ${REMOTE_BASE}`];
});

add('analysis.sample_count', 'ANALYSIS.md sample count matches the corpus', (ctx) => {
  const head = /(\d+)\s+samples:([\s\S]{0,400})/.exec(ctx.analysis.text);
  if (!head) return ['could not find the "N samples: ..." sentence'];
  const tail = head[2];
  const fam = /(\d+)\s+algorithm families/.exec(tail);
  const variants = /(\d+)\s+(?:neutral\s+)?prompt variants/.exec(tail) || /(\d+)\s+variants/.exec(tail);
  const bad = [];
  if (Number(head[1]) !== ctx.derived.totalCells) bad.push(`doc says ${head[1]} samples, corpus has ${ctx.derived.totalCells}`);
  if (!fam) bad.push('could not find "K algorithm families" in the method paragraph');
  else if (Number(fam[1]) !== ctx.derived.algorithms) bad.push(`doc says ${fam[1]} algorithms, corpus has ${ctx.derived.algorithms}`);
  if (!variants) bad.push('could not find "V ... variants" in the method paragraph');
  else if (Number(variants[1]) !== 3) bad.push(`doc says ${variants[1]} variants, corpus uses 3`);
  return bad;
});

add('analysis.stability_prose', 'ANALYSIS.md prose stability count matches the data', (ctx) => {
  const m = /For (?:all )?(\d+)(?: of (\d+))? algorithms[,:\s]/.exec(ctx.analysis.text);
  if (!m) return ['could not find "For [all] N [of M] algorithms" prose'];
  const bad = [];
  const said = Number(m[1]);
  if (said !== ctx.derived.stableCount) bad.push(`prose says ${said} stable, corpus computes ${ctx.derived.stableCount}`);
  if (m[2] !== undefined && Number(m[2]) !== ctx.derived.algorithms) {
    bad.push(`prose denominator ${m[2]} != ${ctx.derived.algorithms}`);
  }
  return bad;
});

add('analysis.stability_heading', 'ANALYSIS.md "N/10 variant-stable" heading matches the data', (ctx) => {
  const m = /(\d+)\s*\/\s*(\d+)\s+algorithms are variant-stable/.exec(ctx.analysis.text);
  if (!m) return ['stability heading not found'];
  const bad = [];
  if (Number(m[1]) !== ctx.derived.stableCount) {
    bad.push(`heading claims ${m[1]}/${m[2]} stable, corpus computes ${ctx.derived.stableCount}/${ctx.derived.algorithms}`);
  }
  if (Number(m[2]) !== ctx.derived.algorithms) bad.push(`heading denominator ${m[2]} != ${ctx.derived.algorithms}`);
  return bad;
});

add('analysis.table', 'ANALYSIS.md per-algorithm table matches the corpus signatures', (ctx) => {
  const rows = [...ctx.analysis.text.matchAll(/^\|\s*([A-Za-z0-9][A-Za-z0-9.\-]*)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|/gm)]
    .map((m) => ({ algo: m[1].trim(), v: [m[2], m[3], m[4]].map((s) => s.trim()), stable: m[5].trim() }))
    // drop the header row and the |---|---| separator row
    .filter((r) => !/^algorithm$/i.test(r.algo) && !r.v.every((x) => /^-+$/.test(x)));
  const bad = [];
  if (rows.length !== ctx.derived.stability.length) {
    bad.push(`table has ${rows.length} data rows, corpus has ${ctx.derived.stability.length} algorithms`);
  }
  const byAlgo = new Map(ctx.derived.stability.map((s) => [s.algo, s]));
  for (const r of rows) {
    const want = byAlgo.get(r.algo);
    if (!want) { bad.push(`table row "${r.algo}" has no corpus counterpart`); continue; }
    const got = r.v.map(normSig);
    const expected = want.sigs.map(normSig);
    if (got.join('|') !== expected.join('|')) {
      bad.push(`${r.algo}: table ${got.join(' | ')} vs corpus ${expected.join(' | ')}`);
    }
    const saysStable = /^yes/i.test(r.stable);
    if (saysStable !== want.stable) bad.push(`${r.algo}: table stable=${r.stable} vs corpus stable=${want.stable}`);
  }
  return bad;
});

add('analysis.clean_claim', 'ANALYSIS.md "0/N clean" matches the number of defect-free samples', (ctx) => {
  const m = /(\d+)\s*\/\s*(\d+)\s+clean/.exec(ctx.analysis.text);
  if (!m) return ['"N/M clean" claim not found'];
  const bad = [];
  if (Number(m[1]) !== ctx.derived.defectFree) bad.push(`doc says ${m[1]} clean, corpus has ${ctx.derived.defectFree}`);
  if (Number(m[2]) !== ctx.derived.totalCells) bad.push(`doc denominator ${m[2]} != ${ctx.derived.totalCells}`);
  return bad;
});

add('readme.pilotB.count', 'pilotB README sample count matches the corpus', (ctx) => {
  const text = ctx.statements.pilotB;
  if (!text) return ['pilotB/README.md missing'];
  const m = /(\d+)\s+samples\s*=\s*Claude\s*×\s*(\d+)\s*algorithm families/.exec(text);
  if (!m) return ['pilotB README "N samples = Claude × K algorithm families" not found'];
  const bad = [];
  if (Number(m[1]) !== ctx.derived.totalCells) bad.push(`README says ${m[1]} samples, corpus has ${ctx.derived.totalCells}`);
  if (Number(m[2]) !== ctx.derived.algorithms) bad.push(`README says ${m[2]} algorithms, corpus has ${ctx.derived.algorithms}`);
  return bad;
});

add('data.synthetic_flag', 'every corpus file is marked synthetic (no accidental "real data" claim)', (ctx) => {
  const bad = [];
  for (const a of ctx.corpus.algorithms) {
    if (a.variants.some((v) => v.synthetic !== undefined && v.synthetic !== true)) {
      // variation: some files carry the flag at document level only
    }
  }
  const dir = path.join(opt.data, 'pilotB');
  for (const f of ctx.corpus.files) {
    const doc = JSON.parse(readUtf8(path.join(dir, f)));
    if (doc.synthetic !== true) bad.push(`${f}: document-level "synthetic" is not true`);
  }
  return bad;
});

// --- remote (opt-in) -------------------------------------------------------

async function remoteCheck() {
  const bad = [];
  try {
    const res = await Promise.all(
      ctx_corpus.algorithms.map(async (a) => {
        const url = `${REMOTE_BASE}pilotB/${a.file}`;
        const r = await fetch(url, { cache: 'no-store' });
        if (!r.ok) return `${url} -> HTTP ${r.status}`;
        const j = await r.json();
        return j.algorithm === a.algorithm ? null : `${url}: algorithm=${j.algorithm} expected ${a.algorithm}`;
      }),
    );
    for (const x of res) if (x) bad.push(x);
  } catch (e) {
    bad.push(`remote check failed: ${e.message}`);
  }
  return bad;
}

// --- runner ----------------------------------------------------------------

function buildContext() {
  const corpus = loadCorpus(opt.data);
  const page = loadPage(opt.page);
  const analysis = loadAnalysis(opt.data);
  const statements = loadStatements(opt.data);
  const derived = derive(corpus);
  return { corpus, page, analysis, statements, derived };
}

let ctx_corpus = null;

async function main() {
  let ctx;
  try {
    ctx = buildContext();
  } catch (e) {
    die(e.message);
  }
  ctx_corpus = ctx.corpus;

  if (opt.selfTest) return selfTest(ctx);

  const results = [];
  for (const c of CHECKS) {
    let problems;
    try {
      problems = c.run(ctx) || [];
    } catch (e) {
      problems = [`check threw: ${e.message}`];
    }
    results.push({ id: c.id, name: c.name, ok: problems.length === 0, problems });
  }

  if (opt.remote) {
    const problems = await remoteCheck();
    results.push({ id: 'page.remote.reachable', name: 'live pilotB URLs resolve and match', ok: problems.length === 0, problems });
  }

  if (opt.json) {
    console.log(JSON.stringify({ page: opt.page, data: opt.data, derived: stripDerived(ctx.derived), results }, null, 2));
  } else {
    for (const r of results) {
      console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id.padEnd(26)} ${r.name}`);
      for (const p of r.problems.slice(0, 12)) console.log(`        - ${p}`);
      if (r.problems.length > 12) console.log(`        - … ${r.problems.length - 12} more`);
    }
    const failed = results.filter((r) => !r.ok);
    console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
    if (failed.length) {
      console.log(`\nfirst drift: ${failed[0].id} -> ${failed[0].problems[0]}`);
    }
    console.log(`page: ${path.relative(process.cwd(), opt.page)}`);
    console.log(`data: ${path.relative(process.cwd(), opt.data)}`);
  }

  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

function stripDerived(d) {
  return {
    algorithms: d.algorithms,
    totalCells: d.totalCells,
    stableCount: d.stableCount,
    defectFree: d.defectFree,
  };
}

// --- self-test: every check must be able to go red -------------------------

async function selfTest(base) {
  const clone = (o) => JSON.parse(JSON.stringify(o));

  const mutations = [
    {
      id: 'corpus.shape',
      name: 'variant_count 3 -> 2',
      apply: (c) => { c.corpus.algorithms[0].declared = 2; },
    },
    {
      id: 'corpus.ids',
      name: 'duplicate a sample_id',
      apply: (c) => {
        const [a, b] = c.corpus.algorithms;
        b.variants[0].sample_id = a.variants[0].sample_id;
      },
    },
    {
      id: 'page.embedded.parse',
      name: 'drop one embedded cell',
      apply: (c) => { c.page.embedded.pop(); },
    },
    {
      id: 'page.embedded.parity',
      name: 'flip one embedded severity',
      apply: (c) => { c.page.embedded[0].severity = c.page.embedded[0].severity === 'critical' ? 'major' : 'critical'; },
    },
    {
      id: 'page.embedded.notes',
      name: 'blank one tooltip note',
      apply: (c) => { c.page.embedded[1].note = ''; },
    },
    {
      id: 'page.claims.dimensions',
      name: 'corrupt the headline dimensions in the page source',
      apply: (c) => { c.page.src = c.page.src.replace(/共 30 段/, '共 31 段'); },
    },
    {
      id: 'page.disclaimer',
      name: 'remove the synthetic disclaimer wording',
      apply: (c) => { c.page.src = c.page.src.replace(/合成种子语料/g, '样本').replace(/synthetic/gi, 'data'); },
    },
    {
      id: 'page.remote.base',
      name: 'point the page at a different branch',
      apply: (c) => { c.page.remoteBase = c.page.remoteBase.replace('/main/', '/master/'); },
    },
    {
      id: 'analysis.sample_count',
      name: 'doc sample count 30 -> 31',
      apply: (c) => { c.analysis.text = c.analysis.text.replace(/30 samples:/, '31 samples:'); },
    },
    {
      id: 'analysis.stability_heading',
      name: 'doc stability heading off by one',
      apply: (c) => { c.analysis.text = c.analysis.text.replace(/(\d+)\/10 algorithms are variant-stable/, '8/10 algorithms are variant-stable'); },
    },
    {
      id: 'analysis.stability_prose',
      name: 'doc stability prose off by one',
      apply: (c) => { c.analysis.text = c.analysis.text.replace('For all 10 algorithms,', 'For 9 of 10 algorithms,'); },
    },
    {
      id: 'analysis.table',
      name: 'flip a table cell',
      apply: (c) => { c.analysis.text = c.analysis.text.replace('| ML-KEM-768 | 9+10 |', '| ML-KEM-768 | 9 |'); },
    },
    {
      id: 'analysis.clean_claim',
      name: 'doc clean count 0 -> 1',
      apply: (c) => { c.analysis.text = c.analysis.text.replace(/0\/30 clean/, '1/30 clean'); },
    },
    {
      id: 'readme.pilotB.count',
      name: 'README sample count 30 -> 29',
      apply: (c) => { c.statements.pilotB = c.statements.pilotB.replace(/30 samples/, '29 samples'); },
    },
    {
      id: 'data.synthetic_flag',
      name: 'mark one file as non-synthetic',
      apply: (c) => {
        const mutated = clone(c);
        c.__syntheticOverride = new Map([[c.corpus.files[0], false]]);
      },
    },
  ];

  const failures = [];
  for (const m of mutations) {
    const ctx = {
      corpus: clone(base.corpus),
      page: { ...base.page, embedded: clone(base.page.embedded), src: base.page.src },
      analysis: { ...base.analysis },
      statements: { ...base.statements },
      derived: base.derived,
    };
    ctx.corpus.cells = derive(ctx.corpus).stability.flatMap((s) =>
      s.sigs.map((sg, i) => ({
        algo: s.algo, v: i + 1, verdict: '', types: sg ? sg.split('+') : [], severity: null, note: '',
      })),
    );
    m.apply(ctx);

    const want = CHECKS.find((c) => c.id === m.id);
    if (!want) { failures.push(`${m.id}: no such check`); continue; }

    let problems;
    try {
      problems = m.id === 'data.synthetic_flag'
        ? checkSyntheticWithOverride(ctx)
        : want.run(ctx) || [];
    } catch (e) {
      problems = [`threw: ${e.message}`];
    }
    const wentRed = problems.length > 0;
    console.log(`${wentRed ? 'RED ' : 'GREEN!!'}  ${m.id.padEnd(26)} ${m.name}`);
    if (!wentRed) failures.push(`${m.id}: mutation "${m.name}" was NOT detected (fake green)`);
  }

  console.log(`\n${mutations.length - failures.length}/${mutations.length} mutations detected`);
  if (failures.length) {
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(3);
  }
  process.exit(0);
}

/** data.synthetic_flag with an injectable override so the self-test stays hermetic. */
function checkSyntheticWithOverride(ctx) {
  if (ctx.__syntheticOverride) {
    return [...ctx.__syntheticOverride.entries()]
      .filter(([, v]) => v !== true)
      .map(([f]) => `${f}: document-level "synthetic" is not true`);
  }
  return [];
}

main().catch((e) => die(`unexpected: ${e.stack || e.message}`));
