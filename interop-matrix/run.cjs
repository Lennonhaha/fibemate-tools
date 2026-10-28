#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// ML-KEM-768 interoperability matrix, two ends: P = fibemate-pqc-kem (pure JS),
// N = @noble/post-quantum (independent oracle).
//
// Design and rationale: fibemate/docs/design/interop-matrix-spec.md, sections 3-5 and 11.
// Shipped shape: 4 cells (2 judged, 2 baselines), Mode D only, no skipped rows, no warn().
//
// Usage:
//   node interop-matrix/run.cjs --pqc-kem <dir> --noble <dir> [--fibemate-repo <dir>]
//                              [--out <dir>]
//
// Exit codes: 0 = PASS, 1 = FAIL, 2 = setup error, 3 = INVALID (a baseline cell failed,
// which means the harness cannot judge anything else), 4 = stale seed table.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const PARAMS = 'ML-KEM-768';
const MODE = 'D';

// Section 3 of the spec: recomputable seeds plus the table they must match. A stale table
// is a silent lie, so the run aborts instead of measuring with different entropy.
const EXPECTED_SEEDS = {
  1: '1aedfca8cad29c3a5da0b70576db3fe04422830abba03aee6790fbf3d1f80858fb0bcd96afa45d36d6e86d2ff4d246a73e186a80caf3274c79d0ebbc333d47d8',
  2: '9b45f5cdddf5e96709bf2206177329f8d19b81e9e3a28e50ddfee4b7fc1258e3d9df027791aa0b727d6b6e4c04b5675723e8941426cdf6c05ece88a5b29d283e',
  3: '65afd75f02707887e33a73eed9f21c8ddd88560ce56bf0f77c46e295b49d3a444f6de5a8ac9f45cb10f6ba0a56c5d88b228581ca48caa698570bb6cc45f44328',
};

const hex = (u8) => Buffer.from(u8).toString('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const fileSha256 = (p) => sha256(fs.readFileSync(p));
const relTo = (p, root) => {
  const r = path.relative(root, p).split(path.sep).join('/');
  return r.startsWith('..') ? p.split(path.sep).slice(-3).join('/') : r;
};
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const shake = (label, n) => crypto.createHash('shake256', { outputLength: n }).update(label).digest();

function parseArgs(argv) {
  const out = { out: null, mutate: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error(`unexpected argument: ${a}`);
    out[a.slice(2)] = argv[i + 1];
    i += 1;
  }
  return out;
}

// Mutation hooks exist so the harness can be shown to fail. Without them "62/62 PASS" is
// only a claim about this code path, not about its ability to detect a wrong end.
const MUTATIONS = {
  // Simulates an end that is internally consistent but not ML-KEM: Kyber round 3, where the
  // shared secret carries an extra KDF. Ciphertexts match, baselines pass, cross cells fail.
  'n-kyber-kdf': (e) => {
    const kdf = (ss, ct) => new Uint8Array(crypto.createHash('sha3-256')
      .update(Buffer.concat([Buffer.from(ss), crypto.createHash('sha3-256').update(Buffer.from(ct)).digest()]))
      .digest());
    const origEncap = e.N.encap;
    e.N.encap = (pk, m) => {
      const r = origEncap(pk, m);
      return { ct: r.ct, ss: kdf(r.ss, r.ct) };
    };
    const origDecap = e.N.decap;
    e.N.decap = (sk, ct) => kdf(origDecap(sk, ct), ct);
  },
  'n-encap-ss': (e) => {
    const orig = e.N.encap;
    e.N.encap = (pk, m) => {
      const r = orig(pk, m);
      const ss = Uint8Array.from(r.ss);
      ss[0] ^= 0x01;
      return { ct: r.ct, ss };
    };
  },
  'p-decap-ss': (e) => {
    const orig = e.P.decap;
    e.P.decap = (sk, ct) => {
      const ss = Uint8Array.from(orig(sk, ct));
      ss[0] ^= 0x01;
      return ss;
    };
  },
};

function gitHead(dir) {
  try {
    return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// ---------------------------------------------------------------------------
// Adapters. Both ends expose keygen(d,z) -> {pk,sk}, encap(pk,m) -> {ct,ss}, decap(sk,ct) -> ss.
// Application-level API differences (argument order, return key names) are normalised here
// and nowhere else, so a cell cannot silently call a different algorithm than it reports.
// ---------------------------------------------------------------------------

function makeEndP(kemDir) {
  const kem = require(path.join(kemDir, 'index.js'));
  const src = path.join(kemDir, 'src', 'ml-kem-768.js');
  const pkg = readJson(path.join(kemDir, 'package.json'));
  // `currentParamSet` is a string export, not a getter; `getParams().name` is the same fact
  // through the accessor that exists on every version of this package.
  const active = typeof kem.currentParamSet === 'string'
    ? kem.currentParamSet
    : (typeof kem.getParams === 'function' ? kem.getParams().name : undefined);
  if (active !== PARAMS) {
    throw new Error(`P: unexpected parameter set ${String(active)}`);
  }
  return {
    id: 'P',
    name: pkg.name,
    version: pkg.version,
    source: src,
    sourceSha256: fileSha256(src),
    mode: MODE,
    keygen: (d, z) => {
      const kp = kem.generateKeypairDerand(d, z);
      return { pk: kp.publicKey, sk: kp.secretKey };
    },
    encap: (pk, m) => {
      const r = kem.encapsulateDerand(pk, m);
      return { ct: r.ciphertext, ss: r.sharedSecret };
    },
    decap: (sk, ct) => kem.decapsulate(sk, ct),
  };
}

function makeEndN(nobleDir) {
  const mod = require(path.join(nobleDir, 'ml-kem.js'));
  const kem = mod.ml_kem768;
  const src = path.join(nobleDir, 'ml-kem.js');
  const pkg = readJson(path.join(nobleDir, 'package.json'));
  return {
    id: 'N',
    name: pkg.name,
    version: pkg.version,
    source: src,
    sourceSha256: fileSha256(src),
    mode: MODE,
    keygen: (d, z) => {
      const seed = new Uint8Array(64);
      seed.set(d, 0);
      seed.set(z, 32);
      const kp = kem.keygen(seed);
      return { pk: kp.publicKey, sk: kp.secretKey };
    },
    encap: (pk, m) => {
      const r = kem.encapsulate(pk, m);
      return { ct: r.cipherText, ss: r.sharedSecret };
    },
    decap: (sk, ct) => kem.decapsulate(ct, sk),
  };
}

// ---------------------------------------------------------------------------

const ends = {};
const checks = [];
let cells = [];
const logs = {};

function record(scope, name, ok, detail) {
  checks.push({ scope, name, status: ok ? 'PASS' : 'FAIL', detail: detail || '' });
  return ok;
}

function attempt(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (err) {
    return { ok: false, error: `${err && err.message ? err.message : String(err)}` };
  }
}

function buildSeeds() {
  return [1, 2, 3].map((i) => {
    const seed = shake(`fibemate-interop-matrix/2026-10/seed-${i}`, 64);
    const m = shake(`fibemate-interop-matrix/2026-10/msg-${i}`, 32);
    const expected = EXPECTED_SEEDS[i];
    if (hex(seed) !== expected) {
      throw Object.assign(new Error(`seed table mismatch for S${i}: computed ${hex(seed)}`), { code: 4 });
    }
    return {
      label: `S${i}`,
      seedHex: hex(seed),
      d: new Uint8Array(seed.subarray(0, 32)),
      z: new Uint8Array(seed.subarray(32, 64)),
      m: new Uint8Array(m),
      mHex: hex(m),
    };
  });
}

function run() {
  const seeds = buildSeeds();
  const derived = [];
  const reference = {};

  // Derivation: same (d, z) must give byte-identical pk and sk in both ends. This is the
  // strongest claim Mode D supports and the one a self-consistent round trip cannot make.
  for (const s of seeds) {
    const kpP = attempt(() => ends.P.keygen(s.d, s.z));
    const kpN = attempt(() => ends.N.keygen(s.d, s.z));
    if (!kpP.ok || !kpN.ok) {
      record(`${s.label}/derive`, 'keygen ran on both ends', false, `${kpP.error || ''} ${kpN.error || ''}`.trim());
      derived.push({ label: s.label, error: true });
      continue;
    }
    const pkEqual = eq(kpP.value.pk, kpN.value.pk);
    const skEqual = eq(kpP.value.sk, kpN.value.sk);
    record(`${s.label}/derive`, 'pk byte-identical P vs N', pkEqual, `P=${hex(kpP.value.pk).slice(0, 32)} N=${hex(kpN.value.pk).slice(0, 32)}`);
    record(`${s.label}/derive`, 'sk byte-identical P vs N', skEqual, `${kpP.value.sk.length}B vs ${kpN.value.sk.length}B`);
    derived.push({
      label: s.label,
      pkEqual,
      skEqual,
      pkSha256: sha256(kpP.value.pk),
      skSha256: sha256(kpP.value.sk),
      keys: { P: kpP.value, N: kpN.value },
    });
  }

  const usable = derived.filter((d) => d.keys);

  // Baseline reference: P keygen -> P encap -> P decap. If this fails the matrix is INVALID.
  for (const d of usable) {
    const s = seeds.find((x) => x.label === d.label);
    const enc = attempt(() => ends.P.encap(d.keys.P.pk, s.m));
    if (!enc.ok) {
      record(`${d.label}/baseline`, 'P encap ran', false, enc.error);
      continue;
    }
    const dec = attempt(() => ends.P.decap(d.keys.P.sk, enc.value.ct));
    if (!dec.ok) {
      record(`${d.label}/baseline`, 'P decap ran', false, dec.error);
      continue;
    }
    record(`${d.label}/baseline`, 'P round trip returns its own shared secret', eq(dec.value, enc.value.ss));
    reference[d.label] = { ct: enc.value.ct, ss: enc.value.ss };
  }

  // Cells: keygen by A, encap by B, decap by A (primary), plus decap by B (auxiliary).
  for (const d of usable) {
    if (!reference[d.label]) continue;
    const s = seeds.find((x) => x.label === d.label);
    const ref = reference[d.label];
    for (const A of ['P', 'N']) {
      for (const B of ['P', 'N']) {
        const cellId = `${A}${B}`;
        const baseline = A === B;
        const enc = attempt(() => ends[B].encap(d.keys[A].pk, s.m));
        const cell = {
          cell: cellId,
          id: `${cellId}/${d.label}`,
          keygen: A,
          encap: B,
          decap: A,
          baseline,
          mode: MODE,
          seed: d.label,
          checks: [],
          ctSha256: null,
          ssSha256: null,
          error: null,
        };
        if (!enc.ok) {
          cell.error = enc.error;
          cell.checks.push({ name: 'encap ran', status: 'FAIL', detail: enc.error });
          cells.push(cell);
          record(`${cellId}/${d.label}`, 'encap ran', false, enc.error);
          continue;
        }
        const dec = attempt(() => ends[A].decap(d.keys[A].sk, enc.value.ct));
        const decB = attempt(() => ends[B].decap(d.keys[A].sk, enc.value.ct));

        // Three distinct claims. They are kept apart on purpose:
        //  - roundTrip: decap returns the secret the sender computed (interop; also the sanity
        //    check for a baseline cell, and the only thing that decides INVALID);
        //  - agreesWithRef: the secret equals end P's (cross-end agreement, a Mode D claim);
        //  - ctBytesEqual: ciphertexts are byte-identical, which a Kyber-style end can pass
        //    while still returning a different secret. Reporting them as one number is how a
        //    matrix ends up hiding a KDF difference behind a green cell.
        const roundTrip = dec.ok && eq(dec.value, enc.value.ss);
        const agreesWithRef = dec.ok && eq(dec.value, ref.ss);
        const ctBytesEqual = eq(enc.value.ct, ref.ct);
        const auxOk = decB.ok && eq(decB.value, enc.value.ss);

        cell.ctSha256 = sha256(enc.value.ct);
        cell.ssSha256 = dec.ok ? sha256(dec.value) : null;
        cell.roundTrip = roundTrip;
        cell.agreesWithRef = agreesWithRef;
        cell.checks.push({ name: `decap by ${A} returns sender ss`, status: roundTrip ? 'PASS' : 'FAIL', detail: dec.ok ? '' : dec.error });
        cell.checks.push({ name: `decap by ${B} returns sender ss (aux)`, status: auxOk ? 'PASS' : 'FAIL', detail: decB.ok ? '' : decB.error });
        cell.checks.push({ name: 'ss equals end P reference', status: agreesWithRef ? 'PASS' : 'FAIL', detail: '' });
        cell.checks.push({ name: 'ct byte-identical to baseline', status: ctBytesEqual ? 'PASS' : 'FAIL', detail: `P ref=${hex(ref.ct).slice(0, 24)} cell=${hex(enc.value.ct).slice(0, 24)}` });
        cells.push(cell);

        record(`${cellId}/${d.label}`, 'round trip returns sender ss', roundTrip, dec.ok ? '' : dec.error);
        record(`${cellId}/${d.label}`, 'ss equals end P reference', agreesWithRef);
        record(`${cellId}/${d.label}`, 'ct bytes match baseline', ctBytesEqual);

        logs[cell.id] = [
          `cell ${cell.id} mode=${MODE} baseline=${baseline}`,
          `pk(${A}) sha256 ${sha256(d.keys[A].pk)}`,
          `ct(${B}) sha256 ${cell.ctSha256}`,
          `ct hex ${hex(enc.value.ct)}`,
          `ss(${B}) hex ${hex(enc.value.ss)}`,
          `ss(${A} decap) hex ${dec.ok ? hex(dec.value) : '<error> ' + dec.error}`,
          `ss(${B} decap) hex ${decB.ok ? hex(decB.value) : '<error> ' + decB.error}`,
        ].join('\n');
      }
    }
  }

  // Controls. A control that throws is a FAIL, not a skip: FIPS 203 section 7.3 requires a
  // deterministic pseudo-random secret, and an exception is not that.
  const controls = [];
  for (const d of usable) {
    const ref = reference[d.label];
    if (!ref) continue;
    const s = seeds.find((x) => x.label === d.label);

    const flipped = Uint8Array.from(ref.ct);
    flipped[0] ^= 0x01;

    const flP = attempt(() => ends.P.decap(d.keys.P.sk, flipped));
    const flN = attempt(() => ends.N.decap(d.keys.N.sk, flipped));
    const flPag = flP.ok ? attempt(() => ends.P.decap(d.keys.P.sk, flipped)) : { ok: false };
    const noThrow = flP.ok && flN.ok;
    const differs = noThrow && !eq(flP.value, ref.ss) && !eq(flN.value, ref.ss);
    const stable = noThrow && flPag.ok && eq(flP.value, flPag.value);
    const agrees = noThrow && eq(flP.value, flN.value);
    const row = {
      seed: d.label,
      flippedCtSha256: sha256(flipped),
      implicitRejection: {
        noThrow,
        differsFromOriginal: differs,
        deterministic: stable,
        matchesAcrossEnds: agrees,
        ssSha256: noThrow ? sha256(flP.value) : null,
        error: noThrow ? null : `${flP.error || ''} ${flN.error || ''}`.trim(),
      },
    };
    controls.push(row);

    record(`${d.label}/control`, 'flipped ct: implicit rejection, no throw', noThrow, noThrow ? '' : row.implicitRejection.error);
    record(`${d.label}/control`, 'flipped ct: ss differs from original', differs);
    record(`${d.label}/control`, 'flipped ct: ss deterministic', stable);
    record(`${d.label}/control`, 'flipped ct: ss identical across ends', agrees);

    const other = usable.find((x) => x.label !== d.label);
    if (other) {
      const wrP = attempt(() => ends.P.decap(other.keys.P.sk, ref.ct));
      const wrN = attempt(() => ends.N.decap(other.keys.N.sk, ref.ct));
      const wrongOk = wrP.ok && wrN.ok && !eq(wrP.value, ref.ss) && !eq(wrN.value, ref.ss);
      row.wrongKey = { rejected: wrongOk, ssSha256: wrP.ok ? sha256(wrP.value) : null };
      record(`${d.label}/control`, 'wrong key does not return the sender ss', wrongOk);
    }
    void s;
  }

  const pks = usable.map((d) => d.pkSha256);
  const sss = usable.map((d) => (reference[d.label] ? sha256(reference[d.label].ss) : null));
  const uniquePk = new Set(pks).size === pks.length;
  const uniqueSs = new Set(sss.filter(Boolean)).size === sss.filter(Boolean).length;
  record('global', 'three seeds produce three distinct pk', uniquePk, pks.map((h) => h.slice(0, 12)).join(' '));
  record('global', 'three seeds produce three distinct ss', uniqueSs);

  const baselineChecks = cells.filter((c) => c.baseline);
  const baselineOk = baselineChecks.length > 0 && baselineChecks.every((c) => c.roundTrip === true)
    && controls.every((c) => c.implicitRejection.noThrow);
  const failed = checks.filter((c) => c.status === 'FAIL');
  const verdict = !usable.length || !baselineOk ? 'INVALID' : failed.length ? 'FAIL' : 'PASS';

  return { verdict, checks, cells, controls, seeds, derived, reference, failed };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args['pqc-kem'] || !args.noble) {
    console.error('usage: run.cjs --pqc-kem <dir> --noble <dir> [--fibemate-repo <dir>] [--out <dir>]');
    process.exit(2);
  }
  const outDir = args.out ? path.resolve(args.out) : path.join(__dirname, 'out');
  fs.mkdirSync(path.join(outDir, 'logs'), { recursive: true });

  ends.P = makeEndP(path.resolve(args['pqc-kem']));
  ends.N = makeEndN(path.resolve(args.noble));

  const mutation = args.mutate || null;
  if (mutation) {
    if (!MUTATIONS[mutation]) throw new Error(`unknown mutation: ${mutation}`);
    MUTATIONS[mutation](ends);
    console.error(`MUTATION ACTIVE: ${mutation} (this run must not pass)`);
  }

  const fibemateRepo = args['fibemate-repo'] ? path.resolve(args['fibemate-repo']) : path.resolve(args['pqc-kem'], '..', '..');
  const toolsRepo = path.resolve(__dirname, '..');

  const result = run();

  const meta = {
    generatedAt: new Date().toISOString(),
    params: PARAMS,
    mode: MODE,
    node: process.version,
    ends: {
      P: { name: ends.P.name, version: ends.P.version, source: relTo(ends.P.source, fibemateRepo), sha256: ends.P.sourceSha256, mode: ends.P.mode },
      N: { name: ends.N.name, version: ends.N.version, source: relTo(ends.N.source, fibemateRepo), sha256: ends.N.sourceSha256, mode: ends.N.mode },
    },
    commits: { fibemate: gitHead(fibemateRepo), fibemateTools: gitHead(toolsRepo) },
    mutation,
    seeds: result.seeds.map((s) => ({ label: s.label, seed: s.seedHex, m: s.mHex })),
    note: 'Mode D: both ends take caller-supplied d, z and m, so pk/sk/ct byte equality is claimable, not just interop.',
  };

  const json = {
    ...meta,
    verdict: result.verdict,
    checks: result.checks,
    cells: result.cells,
    controls: result.controls,
    summary: {
      checks: result.checks.length,
      failed: result.checks.filter((c) => c.status === 'FAIL').length,
      cells: result.cells.length,
      baselines: result.cells.filter((c) => c.baseline).length,
    },
  };
  fs.writeFileSync(path.join(outDir, 'matrix.json'), JSON.stringify(json, null, 2) + '\n', 'utf8');

  for (const [id, text] of Object.entries(logs)) {
    fs.writeFileSync(path.join(outDir, 'logs', `${id.replace(/\//g, '-')}.log`), text + '\n', 'utf8');
  }

  const md = [];
  md.push(`# ML-KEM-768 interop matrix (${result.verdict})`, '');
  md.push(`Generated ${meta.generatedAt} | mode **${MODE}** | node ${meta.node}`, '');
  if (meta.mutation) md.push(`**MUTATION ACTIVE: ${meta.mutation} — self-test run, not evidence.**`, '');
  md.push('| end | implementation | version | source sha256 (first 16) |', '|---|---|---|---|');
  for (const id of ['P', 'N']) {
    const e = meta.ends[id];
    md.push(`| ${id} | ${e.name} | ${e.version} | \`${e.sha256.slice(0, 16)}\` |`);
  }
  md.push('', `fibemate \`${meta.commits.fibemate}\` | fibemate-tools \`${meta.commits.fibemateTools}\``, '');
  md.push('## Derivation (Mode D)', '');
  md.push('| seed | pk P vs N | sk P vs N |', '|---|---|---|');
  for (const d of result.derived) {
    md.push(`| ${d.label} | ${d.pkEqual ? '=P' : '!=P'} | ${d.skEqual ? '=P' : '!=P'} |`);
  }
  md.push('', '`=P` means the bytes equal end P\'s output; no digests are printed here, `matrix.json` carries them.', '');
  md.push('## Cells: keygen A -> encap B -> decap A', '');
  md.push('| cell | seed | mode | baseline | ct bytes | round trip | ss =P | result |', '|---|---|---|---|---|---|---|---|');
  for (const c of result.cells) {
    const ok = c.checks.every((x) => x.status === 'PASS');
    const ct = c.checks.find((x) => x.name.startsWith('ct byte'));
    md.push(`| ${c.cell} | ${c.seed} | ${c.mode} | ${c.baseline ? 'yes' : 'no'} | ${ct.status === 'PASS' ? '=P' : '!=P'} | ${c.roundTrip ? 'PASS' : 'FAIL'} | ${c.agreesWithRef ? '=P' : '!=P'} | **${ok ? 'PASS' : 'FAIL'}** |`);
  }
  md.push('', '`round trip` = decap returns the secret the sender computed (interop). `ss =P` = the secret is byte-equal to end P\'s. A cell can match on ciphertext bytes and still differ on the secret; that is what the `ss =P` column is for.', '');
  md.push('', '## Controls', '');
  md.push('| seed | flipped ct: no throw | differs | deterministic | same ss both ends | wrong key rejected |', '|---|---|---|---|---|---|');
  for (const c of result.controls) {
    const r = c.implicitRejection;
    md.push(`| ${c.seed} | ${r.noThrow ? 'PASS' : 'FAIL'} | ${r.differsFromOriginal ? 'PASS' : 'FAIL'} | ${r.deterministic ? 'PASS' : 'FAIL'} | ${r.matchesAcrossEnds ? 'PASS' : 'FAIL'} | ${c.wrongKey ? (c.wrongKey.rejected ? 'PASS' : 'FAIL') : 'n/a'} |`);
  }
  md.push('', '## Verdict', '');
  md.push(`**${result.verdict}** — ${result.checks.filter((c) => c.status === 'PASS').length}/${result.checks.length} checks passed.`);
  if (result.verdict === 'INVALID') {
    md.push('', 'A baseline cell failed. The harness cannot judge interoperability, so this run is reported as INVALID rather than as a partial pass.');
  }
  const failedList = result.checks.filter((c) => c.status === 'FAIL');
  if (failedList.length) {
    md.push('', '### Failures', '', '| scope | check | detail |', '|---|---|---|');
    for (const f of failedList) md.push(`| ${f.scope} | ${f.name} | ${f.detail.replace(/\|/g, '\\|')} |`);
  }
  fs.writeFileSync(path.join(outDir, 'matrix.md'), md.join('\n') + '\n', 'utf8');

  console.log(md.join('\n'));
  console.log(`\nartifacts: ${outDir} (matrix.json, matrix.md, logs/${Object.keys(logs).length})`);
  process.exit(result.verdict === 'PASS' ? 0 : result.verdict === 'INVALID' ? 3 : 1);
}

try {
  main();
} catch (err) {
  if (err && err.code === 4) {
    console.error(`stale seed table: ${err.message}`);
    process.exit(4);
  }
  console.error(`setup error: ${err && err.stack ? err.stack : err}`);
  process.exit(2);
}
