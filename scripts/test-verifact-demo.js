#!/usr/bin/env node
/*
 * verifact demo page — contract test.
 *
 * The page must be a pure renderer: it may only show what the report says.
 * This test pins that down cell by cell, and mutates the inputs to prove the
 * checks can actually fail (a gate that cannot go red is decoration).
 *
 * Usage:
 *   node scripts/test-verifact-demo.js [--dir <page dir>] [--json] [--self-test]
 *
 * Exit codes: 0 all pass, 1 a check failed, 2 usage/IO error, 3 self-test
 * detected a mutation that did not turn anything red.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const args = process.argv.slice(2);
const opt = { dir: null, json: false, selfTest: false };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--dir') opt.dir = args[++i];
  else if (a.startsWith('--dir=')) opt.dir = a.slice('--dir='.length);
  else if (a === '--json') opt.json = true;
  else if (a === '--self-test') opt.selfTest = true;
  else if (a === '--help' || a === '-h') {
    console.log('usage: node scripts/test-verifact-demo.js [--dir <page dir>] [--json] [--self-test]');
    process.exit(0);
  } else {
    console.error('unknown argument: ' + a);
    process.exit(2);
  }
}

// Resolve explicitly: `require` resolves relative paths against this file, not
// the cwd, so `--dir=../fibemate/...` would look inside this repository.
const dir = opt.dir
  ? path.resolve(opt.dir)
  : path.resolve(__dirname, '..', '..', 'fibemate', 'www', 'tools', 'verifact-demo');
const CONTRACT_SENTENCE = '本页面仅渲染离线审计报告，不执行任何安全判定。';

function read(file) {
  const p = path.join(dir, file);
  if (!fs.existsSync(p)) throw new Error('missing file: ' + p);
  return fs.readFileSync(p, 'utf8');
}

function loadRenderer(source) {
  if (!source) return require(path.join(dir, 'demo.js'));
  const sandbox = { module: { exports: {} }, globalThis: {} };
  sandbox.exports = sandbox.module.exports;
  vm.runInNewContext(source, sandbox, { filename: 'demo.mutated.js' });
  return sandbox.module.exports;
}

const pageHtml = read('index.html');
const realSource = read('sample-real.json');
const synthSource = read('sample-drift.json');
const rendererSource = read('demo.js');

const baseCtx = {
  pageHtml: pageHtml,
  renderer: loadRenderer(null),
  real: JSON.parse(realSource),
  synth: JSON.parse(synthSource),
  rendererSource: rendererSource,
};

const checks = [];
function check(name, fn) {
  checks.push({ name: name, fn: fn });
}

function tiles(html) {
  const out = {};
  const re = /<div class="tile (st-[a-z-]+)" data-tile="([a-z-]+)">\s*<b>(\d+)<\/b>/g;
  let m;
  while ((m = re.exec(html))) out[m[2]] = { count: Number(m[3]), cls: m[1] };
  return out;
}

function rows(html) {
  const out = [];
  const re = /<tr data-id="([^"]*)" data-status="([^"]*)" class="([^"]*)">([\s\S]*?)<\/tr>/g;
  let m;
  while ((m = re.exec(html))) out.push({ id: m[1], status: m[2], cls: m[3], body: m[4] });
  return out;
}

/* ---------------- checks ---------------- */

check('page.contract_sentence', function (ctx) {
  const ok = ctx.pageHtml.indexOf(CONTRACT_SENTENCE) >= 0;
  return { ok: ok, detail: ok ? '' : 'contract sentence missing from index.html' };
});

check('page.no_status_assignment', function (ctx) {
  // A renderer that assigns status would be deciding, not rendering.
  // `data-status="..."` must not count, hence the lookbehind on `-` and word chars.
  const propertyWrite = /\.status\s*=(?!=)/.test(ctx.rendererSource);
  const literalWrite = /(?<![-\w])status\s*=\s*['"](verified|drift|ambiguous|unbound|ref-found|ref-missing)['"]/.test(ctx.rendererSource);
  const bad = propertyWrite || literalWrite;
  return { ok: !bad, detail: bad ? 'demo.js assigns a status value' : '' };
});

check('render.rows_match_fixture', function (ctx) {
  const html = ctx.renderer.renderReport(ctx.real).tableHtml;
  const got = rows(html);
  if (got.length !== ctx.real.claims.length) {
    return { ok: false, detail: 'rows ' + got.length + ' != claims ' + ctx.real.claims.length };
  }
  for (let i = 0; i < got.length; i++) {
    const c = ctx.real.claims[i];
    if (got[i].id !== ctx.renderer.esc(c.id)) return { ok: false, detail: 'row ' + i + ' id mismatch' };
    if (got[i].status !== ctx.renderer.esc(c.status)) return { ok: false, detail: 'row ' + i + ' status mismatch' };
    const expectedFile = ctx.renderer.esc(c.file + ':' + c.line);
    if (got[i].body.indexOf(expectedFile) < 0) return { ok: false, detail: 'row ' + i + ' missing file:line' };
    if (!got[i].cls.includes(ctx.renderer.statusClass(c.status))) {
      return { ok: false, detail: 'row ' + i + ' class does not match status' };
    }
  }
  return { ok: true, detail: '' };
});

check('render.counts_match_report', function (ctx) {
  const t = tiles(ctx.renderer.renderReport(ctx.real).summaryHtml);
  const c = ctx.real.counts;
  const want = { verified: c.verified, drift: c.drift, ambiguous: c.ambiguous, unbound: c.unbound };
  for (const k of Object.keys(want)) {
    if (!t[k]) return { ok: false, detail: 'missing tile ' + k };
    if (t[k].count !== want[k]) return { ok: false, detail: 'tile ' + k + ' ' + t[k].count + ' != ' + want[k] };
  }
  return { ok: true, detail: '' };
});

check('render.drift_banner_iff_drift', function (ctx) {
  // The expectation comes from two independent sources: the claims and the
  // counts. They must agree, and the banner must follow them. Comparing the
  // banner against `counts` alone would be tautological.
  const cases = [['real', ctx.real], ['synth', ctx.synth]];
  for (const pair of cases) {
    const label = pair[0];
    const rep = pair[1];
    const hasDriftClaim = (rep.claims || []).some(function (c) { return c.status === 'drift'; });
    const count = Number((rep.counts || {}).drift || 0);
    const html = ctx.renderer.renderReport(rep).bannersHtml;
    const hasBanner = html.indexOf('data-banner="drift"') >= 0;
    if (hasDriftClaim !== count > 0) {
      return { ok: false, detail: label + ': claims say drift=' + hasDriftClaim + ' but counts.drift=' + count };
    }
    if (hasBanner !== count > 0) {
      return { ok: false, detail: label + ': banner=' + hasBanner + ' but counts.drift=' + count };
    }
    if (count > 0 && html.indexOf(String(count)) < 0) {
      return { ok: false, detail: label + ': banner does not state the count' };
    }
  }
  return { ok: true, detail: '' };
});

check('fixture.status_counts_agree', function (ctx) {
  // Every status that appears in the claims must exist in the counts, and a
  // full (non-subset) report must match exactly. This catches "the table says
  // drift while the summary says zero".
  const toCountKey = function (s) {
    return s.replace(/-([a-z])/g, function (_, ch) { return ch.toUpperCase(); });
  };
  const cases = [['real', ctx.real], ['synth', ctx.synth]];
  for (const pair of cases) {
    const label = pair[0];
    const rep = pair[1];
    const dist = {};
    for (const c of rep.claims || []) dist[c.status] = (dist[c.status] || 0) + 1;
    for (const status of Object.keys(dist)) {
      const key = toCountKey(status);
      if (!(Number((rep.counts || {})[key]) > 0)) {
        return { ok: false, detail: label + ': claims contain ' + status + ' but counts.' + key + ' is 0' };
      }
      const full = !(rep.subset && rep.subset.enabled);
      if (full && Number(rep.counts[key]) !== dist[status]) {
        return { ok: false, detail: label + ': counts.' + key + '=' + rep.counts[key] + ' != claims ' + dist[status] };
      }
    }
  }
  return { ok: true, detail: '' };
});

check('render.synthetic_iff_labelled', function (ctx) {
  const a = ctx.renderer.renderReport(ctx.real).bannersHtml;
  const b = ctx.renderer.renderReport(ctx.synth).bannersHtml;
  if (!ctx.synth.meta || ctx.synth.meta.synthetic !== true) return { ok: false, detail: 'sample-drift.json must be labelled synthetic' };
  if (b.indexOf('data-banner="synthetic"') < 0) return { ok: false, detail: 'synthetic banner missing' };
  if (b.indexOf('SYNTHETIC') < 0) return { ok: false, detail: 'synthetic marker text missing' };
  if (a.indexOf('data-banner="synthetic"') >= 0) return { ok: false, detail: 'real sample marked synthetic' };
  return { ok: true, detail: '' };
});

check('render.subset_note', function (ctx) {
  const a = ctx.renderer.renderReport(ctx.real).bannersHtml;
  const b = ctx.renderer.renderReport(ctx.synth).bannersHtml;
  if (!ctx.real.subset || ctx.real.subset.enabled !== true) return { ok: false, detail: 'real sample must declare its subset' };
  if (a.indexOf('data-banner="subset"') < 0) return { ok: false, detail: 'subset note missing' };
  if (a.indexOf(String(ctx.real.subset.shownClaims)) < 0 || a.indexOf(String(ctx.real.subset.ofClaims)) < 0) {
    return { ok: false, detail: 'subset note does not state shown/of counts' };
  }
  if (b.indexOf('data-banner="subset"') >= 0) return { ok: false, detail: 'synthetic sample claims to be a subset' };
  return { ok: true, detail: '' };
});

check('render.unknown_status_is_not_green', function (ctx) {
  const cloned = JSON.parse(JSON.stringify(ctx.real));
  cloned.claims = [
    {
      id: 'demo.md:1:ratio:unknown',
      file: 'demo.md',
      line: 1,
      kind: 'ratio',
      status: 'totally-new-status',
      value: { raw: '1/2' },
      sentence: 'status from the future',
    },
  ];
  const html = ctx.renderer.renderReport(cloned).tableHtml;
  const r = rows(html)[0];
  if (!r) return { ok: false, detail: 'no row rendered' };
  if (r.cls.indexOf('st-unknown') < 0) return { ok: false, detail: 'unknown status not marked st-unknown' };
  if (r.cls.indexOf('st-verified') >= 0) return { ok: false, detail: 'unknown status rendered as verified' };
  if (r.body.indexOf('totally-new-status') < 0) return { ok: false, detail: 'unknown status text not shown verbatim' };
  return { ok: true, detail: '' };
});

check('render.escapes_html', function (ctx) {
  const cloned = JSON.parse(JSON.stringify(ctx.real));
  cloned.claims = [
    {
      id: 'x"><tr data-id="evil',
      file: '<img src=x onerror=alert(1)>',
      line: 2,
      kind: '<b>kind</b>',
      status: 'unbound',
      value: { raw: '<script>alert(1)</script>' },
      sentence: '<script>alert("xss")</script>',
    },
  ];
  const html = ctx.renderer.renderReport(cloned).tableHtml;
  if (html.indexOf('<script>') >= 0) return { ok: false, detail: 'raw <script> survived escaping' };
  if (html.indexOf('&lt;script&gt;') < 0) return { ok: false, detail: 'expected escaped script text' };
  if (html.indexOf('<img src=x') >= 0) return { ok: false, detail: 'raw <img> survived escaping' };
  return { ok: true, detail: '' };
});

check('render.is_pure', function (ctx) {
  const before = JSON.stringify(ctx.real);
  ctx.renderer.renderReport(ctx.real);
  const after = JSON.stringify(ctx.real);
  return { ok: before === after, detail: before === after ? '' : 'renderReport mutated its input' };
});

check('fixture.counts_add_up', function (ctx) {
  const c = ctx.real.counts;
  const sum = c.verified + c.drift + c.ambiguous + c.unbound + c.refFound + c.refMissing;
  const ok = sum === c.claims;
  return { ok: ok, detail: ok ? '' : 'status counts sum ' + sum + ' != claims ' + c.claims };
});

check('fixture.subset_size_matches', function (ctx) {
  const s = ctx.real.subset;
  const ok = s && s.enabled === true && s.shownClaims === ctx.real.claims.length;
  return { ok: ok, detail: ok ? '' : 'subset.shownClaims does not match claims.length' };
});

check('page.assets_present', function (ctx) {
  for (const f of ['demo.js', 'sample-real.json', 'sample-drift.json']) {
    if (ctx.pageHtml.indexOf('data-banner') >= 0 && f === 'demo.js' && ctx.pageHtml.indexOf('demo.js') < 0) {
      return { ok: false, detail: 'index.html does not load demo.js' };
    }
    if (!fs.existsSync(path.join(dir, f))) return { ok: false, detail: 'missing asset ' + f };
  }
  return { ok: true, detail: '' };
});

check('render.reconciles', function (ctx) {
  // The page prints an arithmetic chain built from counts. The expectation here
  // is recomputed independently from counts, so a renderer that inflates or
  // zeroes any term is caught even if it still prints a self-consistent story.
  const cases = [['real', ctx.real], ['synth', ctx.synth]];
  for (const pair of cases) {
    const label = pair[0];
    const rep = pair[1];
    const html = ctx.renderer.renderReport(rep).reconHtml;
    if (!html) return { ok: false, detail: label + ': no reconciliation block' };

    const attr = function (name) {
      const m = html.match(new RegExp('data-recon-' + name + '="([^"]*)"'));
      return m ? Number(m[1]) : NaN;
    };
    const state = (html.match(/data-recon="([^"]*)"/) || [])[1];
    const got = {
      tiles: attr('tiles'),
      refFound: attr('ref-found'),
      refMissing: attr('ref-missing'),
      claims: attr('claims'),
      nonCode: attr('noncode'),
      total: attr('total'),
    };

    const c = rep.counts || {};
    const wantTiles = ['verified', 'drift', 'ambiguous', 'unbound']
      .reduce(function (s, k) { return s + (Number(c[k]) || 0); }, 0);

    if (got.tiles !== wantTiles) {
      return { ok: false, detail: label + ': rendered tiles ' + got.tiles + ' != counts sum ' + wantTiles };
    }
    if (got.refFound !== (Number(c.refFound) || 0) || got.refMissing !== (Number(c.refMissing) || 0)) {
      return { ok: false, detail: label + ': ref counts do not match counts.refFound/refMissing' };
    }
    if (got.tiles + got.refFound + got.refMissing !== got.claims) {
      return { ok: false, detail: label + ': tiles+refs ' + (got.tiles + got.refFound + got.refMissing) + ' != claims ' + got.claims };
    }
    if (got.claims !== (Number(c.claims) || 0)) {
      return { ok: false, detail: label + ': claims ' + got.claims + ' != counts.claims ' + c.claims };
    }
    if (got.claims + got.nonCode !== got.total || got.total !== (Number(c.claimsTotal) || 0)) {
      return { ok: false, detail: label + ': ' + got.claims + '+' + got.nonCode + ' != claimsTotal ' + got.total };
    }
    if (state !== 'ok') {
      return { ok: false, detail: label + ': report reconciles but page says data-recon="' + state + '"' };
    }
    if (html.indexOf('data-recon-fail') >= 0) {
      return { ok: false, detail: label + ': failure notice rendered for a reconciling report' };
    }
  }

  // And the negative half: when the report itself does not add up, the page
  // must say so loudly instead of rendering a clean bill of health.
  const broken = JSON.parse(JSON.stringify(ctx.real));
  broken.counts.claims = broken.counts.claims + 1;
  const badHtml = ctx.renderer.renderReport(broken).reconHtml;
  const badState = (badHtml.match(/data-recon="([^"]*)"/) || [])[1];
  if (badState !== 'fail') return { ok: false, detail: 'inconsistent report rendered as "' + badState + '"' };
  if (badHtml.indexOf('data-recon-fail') < 0) return { ok: false, detail: 'inconsistent report did not print a failure notice' };
  return { ok: true, detail: '' };
});

/* ---------------- runner ---------------- */

function runSuite(ctx) {
  return checks.map(function (c) {
    let res;
    try {
      res = c.fn(ctx);
    } catch (err) {
      res = { ok: false, detail: 'threw: ' + (err && err.message ? err.message : String(err)) };
    }
    return { name: c.name, ok: !!res.ok, detail: res.detail || '' };
  });
}

function cloneCtx(ctx) {
  return {
    pageHtml: ctx.pageHtml,
    renderer: ctx.renderer,
    real: JSON.parse(JSON.stringify(ctx.real)),
    synth: JSON.parse(JSON.stringify(ctx.synth)),
    rendererSource: ctx.rendererSource,
  };
}

const mutations = [
  {
    name: 'M1 contract sentence removed',
    target: 'page.contract_sentence',
    apply: function (ctx) {
      ctx.pageHtml = ctx.pageHtml.replace(CONTRACT_SENTENCE, '本页面可以做安全判定。');
    },
  },
  {
    name: 'M2 status flipped without touching counts',
    target: 'fixture.status_counts_agree',
    apply: function (ctx) {
      ctx.real.claims[0].status = 'drift';
    },
  },
  {
    name: 'M3 drift count zeroed',
    target: 'fixture.status_counts_agree',
    apply: function (ctx) {
      ctx.synth.counts.drift = 0;
    },
  },
  {
    name: 'M4 synthetic label removed',
    target: 'render.synthetic_iff_labelled',
    apply: function (ctx) {
      ctx.synth.meta.synthetic = false;
    },
  },
  {
    name: 'M5 unknown status mapped to verified',
    target: 'render.unknown_status_is_not_green',
    apply: function (ctx) {
      // Patch the source, not the exported object: renderReport closes over the
      // module-local function, so swapping the property would mutate nothing.
      const src = ctx.rendererSource.replace(
        "return KNOWN.indexOf(status) >= 0 ? 'st-' + status : 'st-unknown';",
        "return 'st-verified';"
      );
      ctx.renderer = loadRenderer(src);
      ctx.rendererSource = src;
    },
  },
  {
    name: 'M6 subset note dropped',
    target: 'render.subset_note',
    apply: function (ctx) {
      delete ctx.real.subset;
    },
  },
  {
    name: 'M7 escaping disabled',
    target: 'render.escapes_html',
    apply: function (ctx) {
      const src = ctx.rendererSource.replace(/'&lt;'/g, "'<'").replace(/'&amp;'/g, "'&'");
      ctx.renderer = loadRenderer(src);
      ctx.rendererSource = src;
    },
  },
  {
    name: 'M8 drift count inflated',
    target: 'render.drift_banner_iff_drift',
    apply: function (ctx) {
      ctx.real.counts.drift = 1;
    },
  },
  {
    name: 'M9 tile sum inflated by one',
    target: 'render.reconciles',
    apply: function (ctx) {
      const src = ctx.rendererSource.replace(
        'const tiles = TILES.reduce(function (sum, k) { return sum + (Number(c[k]) || 0); }, 0);',
        'const tiles = TILES.reduce(function (sum, k) { return sum + (Number(c[k]) || 0); }, 0) + 1;'
      );
      ctx.renderer = loadRenderer(src);
      ctx.rendererSource = src;
    },
  },
  {
    name: 'M10 non-code remainder zeroed',
    target: 'render.reconciles',
    apply: function (ctx) {
      const src = ctx.rendererSource.replace(
        'const nonCode = claimsTotal - codeClaims;',
        'const nonCode = 0;'
      );
      ctx.renderer = loadRenderer(src);
      ctx.rendererSource = src;
    },
  },
];

function main() {
  const results = runSuite(baseCtx);
  const failed = results.filter((r) => !r.ok);

  let selfTest = null;
  if (opt.selfTest) {
    selfTest = mutations.map(function (m) {
      const ctx = cloneCtx(baseCtx);
      try {
        m.apply(ctx);
      } catch (err) {
        return { name: m.name, target: m.target, detected: false, detail: 'mutation threw: ' + err.message };
      }
      const after = runSuite(ctx);
      const target = after.find((r) => r.name === m.target);
      const detected = !!(target && !target.ok);
      return { name: m.name, target: m.target, detected: detected, detail: detected ? '' : 'target check stayed green' };
    });
  }

  if (opt.json) {
    console.log(JSON.stringify({ dir: dir, checks: results, selfTest: selfTest }, null, 2));
  } else {
    console.log('dir: ' + dir);
    console.log('checks: ' + (results.length - failed.length) + '/' + results.length + ' passed');
    for (const r of results) console.log((r.ok ? 'PASS ' : 'FAIL ') + r.name + (r.detail ? ' — ' + r.detail : ''));
    if (selfTest) {
      const missed = selfTest.filter((m) => !m.detected);
      console.log('mutations: ' + (selfTest.length - missed.length) + '/' + selfTest.length + ' detected');
      for (const m of selfTest) console.log((m.detected ? 'RED  ' : 'MISS ') + m.name + (m.detail ? ' — ' + m.detail : ''));
    }
  }

  if (failed.length) process.exit(1);
  if (selfTest && selfTest.some((m) => !m.detected)) process.exit(3);
}

try {
  main();
} catch (err) {
  console.error('error: ' + (err && err.stack ? err.stack : err));
  process.exit(2);
}
