#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-scan.cjs — scan a directory tree for cryptographic assets,
// emit CycloneDX 1.6 CBOM with provenance-aware merge policy.

'use strict';

const fs = require('fs');
const path = require('path');

const { HIERARCHY, lookup: algoLookup } = require('./algorithm-hierarchy.cjs');

const ALGO_META = JSON.parse(fs.readFileSync(path.join(__dirname, 'algo-metadata.json'), 'utf-8'));
const PKG = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf-8'));

const NAME_ALIASES = {
  'ML-KEM-768': 'ML-KEM',
  'ML-KEM-512': 'ML-KEM',
  'ML-KEM-1024': 'ML-KEM',
  'ML-DSA': 'ML-DSA/fml-dsa',
  'ML-DSA-44': 'ML-DSA/fml-dsa',
  'ML-DSA-65': 'ML-DSA/fml-dsa',
  'ML-DSA-87': 'ML-DSA/fml-dsa',
  'Keccak-256': 'Keccak',
};

function lookupMeta(name) {
  if (ALGO_META[name]) return ALGO_META[name];
  const alias = NAME_ALIASES[name];
  if (alias && ALGO_META[alias]) return ALGO_META[alias];
  return null;
}

// Package-level rules declare algorithm availability without
// source-level call sites. A component may exist with zero
// occurrences — this is informational, not a scan miss.
// See Issue #55 for the granularity decision.
const DEFAULT_RULES = {
  packages: {
    // Multi-parameter packages → family-level inference per José Q2 ruling
    '@noble/post-quantum': ['ML-DSA', 'ML-KEM', 'SLH-DSA'],
    // @noble/hashes is multi-family — conservative: single-family inference
    '@noble/hashes': ['Keccak'],
    // Genuinely single-target packages → specific inference
    'keccak256': ['Keccak-256'],
    // Existing entries (unchanged)
    'sm-crypto': ['SM2', 'SM3', 'SM4'],
    'sm2-crypto': ['SM2'],
    jsbn: ['RSA'],
    '@fibemate/sm2-crypto': ['SM2'],
    '@fibemate/keccak': ['Keccak-256', 'SHA3-256'],
  },
  sourcePatterns: [
    // ── PQC specific (run first; dedup clears generic for same pos) ──
    { re: /\bml[-_]?dsa[-_]?44\b/gi, algs: ['ML-DSA-44'] },
    { re: /\bml[-_]?dsa[-_]?65\b/gi, algs: ['ML-DSA-65'] },
    { re: /\bml[-_]?dsa[-_]?87\b/gi, algs: ['ML-DSA-87'] },
    { re: /\bml[-_]?kem[-_]?512\b/gi, algs: ['ML-KEM-512'] },
    { re: /\bml[-_]?kem[-_]?768\b/gi, algs: ['ML-KEM-768'] },
    { re: /\bml[-_]?kem[-_]?1024\b/gi, algs: ['ML-KEM-1024'] },
    { re: /\bkeccak[-_]?224\b/gi, algs: ['Keccak-224'] },
    { re: /\bkeccak[-_]?256\b/gi, algs: ['Keccak-256'] },
    { re: /\bkeccak[-_]?384\b/gi, algs: ['Keccak-384'] },
    { re: /\bkeccak[-_]?512\b/gi, algs: ['Keccak-512'] },
    // ── PQC generic (dedup removes overlap with specific above) ──
    { re: /\bml[-_]?kem\b/gi, algs: ['ML-KEM'] },
    { re: /\bml[-_]?dsa\b/gi, algs: ['ML-DSA'] },
    { re: /\bslh[-_]?dsa\b/gi, algs: ['SLH-DSA'] },
    { re: /\bkeccak\b/gi, algs: ['Keccak'] },
    // ── SM / legacy ──
    { re: /require\(['"]sm-crypto['"]\)/g, algs: ['SM2', 'SM3', 'SM4'] },
    { re: /noble.*post-?quantum/gi, algs: ['ML-KEM', 'ML-DSA'] },
    { re: /crypto\.createHash\(['"]sha3-(\d+)['"]\)/g, algs: ['SHA3-$1'] },
    { re: /crypto\.createHash\(['"]sha-?256['"]\)/g, algs: ['SHA-256'] },
    { re: /crypto\.createHash\(['"]sha-?512['"]\)/g, algs: ['SHA-512'] },
    { re: /\bsm2\b/gi, algs: ['SM2'] },
    { re: /\bsm3\b/gi, algs: ['SM3'] },
    { re: /\bsm4\b/gi, algs: ['SM4'] },
    // ── C/C++ (monocypher) ──
    { re: /\bcrypto_lock\b/g, algs: ['ChaCha20-Poly1305'] },
    { re: /\bcrypto_unlock\b/g, algs: ['ChaCha20-Poly1305'] },
    { re: /\bcrypto_x25519/g, algs: ['X25519'] },
    { re: /\bcrypto_sign/g, algs: ['Ed25519'] },
    { re: /\bcrypto_check\b/g, algs: ['Ed25519'] },
    { re: /\bcrypto_blake2b/g, algs: ['Blake2b'] },
    { re: /\bcrypto_argon2i\b/g, algs: ['Argon2i'] },
    { re: /\bcrypto_key_exchange\b/g, algs: ['X25519'] },
    // ── C/C++ (mbedtls) ──
    { re: /\bmbedtls_sha256/g, algs: ['SHA-256'] },
    { re: /\bmbedtls_sha512/g, algs: ['SHA-512'] },
    { re: /\bmbedtls_aes/g, algs: ['AES'] },
    { re: /\bmbedtls_gcm/g, algs: ['AES-GCM'] },
    { re: /\bmbedtls_ecdh/g, algs: ['ECDH'] },
    { re: /\bmbedtls_rsa/g, algs: ['RSA'] },
    // ── Python hashlib ──
    { re: /import\s+hashlib/g, algs: ['SHA-256'] },
    { re: /hashlib\.sha256\(/g, algs: ['SHA-256'] },
    { re: /hashlib\.new\(\s*["']sha256["']/gi, algs: ['SHA-256'] },
  ],
};

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.cache']);
const SCAN_EXT = /\.(cjs|mjs|js|ts|tsx|jsx|cpp|c|h|hpp|py)$/;
const MAX_OCC_PER_ALGO = 50;

// ── Dependency inference ────────────────────────────────────────────

function loadPackageDeps(dir) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return {};
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    return { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  } catch {
    return {};
  }
}

/**
 * Match manifest dependencies against rules.
 * @returns {Map<string, {pkgName: string, confidence: number}>}
 */
function matchDeps(deps, rules) {
  /** @type {Map<string, {origins: Array<{pkgName:string, confidence:number}>}>} */
  const found = new Map();
  for (const [pkgName, _v] of Object.entries(deps || {})) {
    const algos = rules.packages[pkgName];
    if (!algos) continue;
    for (const algo of algos) {
      if (!found.has(algo)) found.set(algo, { origins: [] });
      found.get(algo).origins.push({ pkgName, confidence: 0.7 });
    }
  }
  return found;
}

// ── Source scanning ─────────────────────────────────────────────────

function scanSource(root, rules) {
  /** @type {Map<string, Array<{location:string, line:number, symbol:string}>>} */
  const result = new Map();

  function addOcc(algoName, file, line, symbol, span) {
    if (!result.has(algoName)) result.set(algoName, []);
    const arr = result.get(algoName);
    if (arr.length >= MAX_OCC_PER_ALGO) return;
    const loc = path.relative(root, file).replace(/\\/g, '/');
    if (arr.some(o => o.location === loc && o.line === line && o.span.start === span.start && o.span.end === span.end)) return;
    arr.push({ location: loc, line, symbol, span });
  }

  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
      if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!SCAN_EXT.test(entry.name)) continue;
      let content;
      try { content = fs.readFileSync(full, 'utf-8'); }
      catch { continue; }
      for (const { re, algs } of rules.sourcePatterns) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(content)) !== null) {
          const line = content.slice(0, m.index).split('\n').length;
          const span = { start: m.index, end: m.index + m[0].length };
          for (const a of algs) {
            const name = a.replace(/\$(\d+)/g, (_, i) => m[i]);
            addOcc(name, full, line, m[0], span);
          }
        }
      }
    }
  }
  walk(root);
  return result;
}

// ── Occurrence deduplication ────────────────────────────────────────

/**
 * For each (file,line) position, if a family has both a specific match
 * (with params) and a generic match (without params), drop the generic.
 * Prevents e.g. "ml-dsa-65" from producing both ML-DSA-65 and ML-DSA.
 */
function deduplicateOccurrences(source) {
  // 1. Flatten occurrences with span → [{algoName, family, params, location, line, start, end}]
  const flat = [];
  for (const [algoName, occs] of source) {
    const h = HIERARCHY[algoName];
    if (!h) continue;
    for (const o of occs) {
      flat.push({
        algoName, family: h.family, params: h.params,
        location: o.location, line: o.line,
        start: o.span.start, end: o.span.end,
      });
    }
  }

  // 2. Collect spans of all specific matches
  const specificSpans = flat
    .filter(e => e.params !== null)
    .map(e => ({ location: e.location, line: e.line, start: e.start, end: e.end }));

  function covers(outer, inner) {
    return outer.location === inner.location
      && outer.line === inner.line
      && outer.start <= inner.start
      && outer.end >= inner.end;
  }

  // 3. Drop generic occurrences whose span is covered by a specific match
  const drop = new Set(); // "algoName@location:line:start:end"
  for (const e of flat) {
    if (e.params !== null) continue; // keep all specifics
    const absorbed = specificSpans.some(s => covers(s, e));
    if (absorbed) drop.add(`${e.algoName}@${e.location}:${e.line}:${e.start}:${e.end}`);
  }

  // 4. Rebuild
  const out = new Map();
  for (const [algoName, occs] of source) {
    const kept = occs.filter(o => !drop.has(`${algoName}@${o.location}:${o.line}:${o.span.start}:${o.span.end}`));
    if (kept.length) out.set(algoName, kept);
  }
  return out;
}

// ── Provenance merge ────────────────────────────────────────────────

/**
 * Merge dependency and source results into components with provenance evidence.
 *
 * Merge rule: exact-name match on both sides → one identity with two methods.
 * Single source → one identity with one method.
 * Different names → separate components (by union iteration).
 *
 * @param {Map<string, {pkgName:string, confidence:number}>} fromDeps
 * @param {Map<string, Array<{location:string, line:number, symbol:string}>>} fromSource
 * @returns {Array<object>} components
 */
function mergeEvidence(fromDeps, fromSource) {
  const names = new Set([...fromDeps.keys(), ...fromSource.keys()]);
  const components = [];

  for (const name of names) {
    const depInfo = fromDeps.get(name);
    const srcOccs = fromSource.get(name) || [];
    const methods = [];

    // Bug 3 fix: one method per dependency origin
    if (depInfo) {
      for (const o of depInfo.origins) {
        methods.push({
          technique: 'manifest-analysis',
          confidence: o.confidence,
          value: o.pkgName,
        });
      }
    }
    if (srcOccs.length) {
      const h = HIERARCHY[name];
      const conf = (h && h.params !== null) ? 0.9 : 0.7;
      methods.push({
        technique: 'source-code-analysis',
        confidence: conf,
        value: srcOccs[0].symbol,
      });
    }

    // Bug 1 fix: omit line for manifest occurrences (unknown real line)
    const occurrences = [];
    if (depInfo) {
      for (const o of depInfo.origins) {
        occurrences.push({ location: 'package.json', symbol: o.pkgName });
      }
    }
    // Strip internal span fields from source occurrences before output
    for (const src of srcOccs) {
      const { span, ...clean } = src;
      occurrences.push(clean);
    }

    const identityConf = methods.length
      ? Math.max(...methods.map(m => m.confidence))
      : 0.5;

    const comp = {
      type: 'cryptographic-asset',
      name,
      'bom-ref': `crypto:${name}`,
      evidence: {
        identity: [{
          field: 'name',
          confidence: identityConf,
          concludedValue: name,
          methods,
        }],
        occurrences,
      },
    };

    const meta = lookupMeta(name);
    if (meta) {
      comp.cryptoProperties = {
        assetType: meta.assetType,
        algorithmProperties: meta.algorithmProperties,
      };
      const props = [];
      if (meta.implementationPlatform) {
        props.push({ name: 'fibemate:implementationLanguages', value: meta.implementationPlatform });
      }
      if (meta.certificationLevel) {
        props.push({ name: 'fibemate:testingStatus', value: meta.certificationLevel });
      }
      if (meta.quantumSecurity && meta.quantumSecurity.level) {
        props.push({ name: 'fibemate:quantumSecurity:level', value: meta.quantumSecurity.level });
      }
      if (props.length) comp.properties = props;
    }

    components.push(comp);
  }

  return components.sort((a, b) => a.name.localeCompare(b.name));
}

// ── Output ──────────────────────────────────────────────────────────

function toCycloneDX(components) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'cbom-scan', version: PKG.version, vendor: 'FIBEMATE' }],
    },
    components,
  };
}

// ── Entry point ─────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  const dirFlag = args.indexOf('--dir');
  let dir = process.cwd();
  if (dirFlag !== -1) {
    const v = args[dirFlag + 1];
    if (!v || v.startsWith('--')) {
      console.error('usage: cbom-scan [--dir <path>] [--out <file>]');
      process.exit(2);
    }
    dir = v;
  }
  const outPath = args.includes('--out') ? args[args.indexOf('--out') + 1] : null;

  const deps = loadPackageDeps(dir);
  const fromDeps = matchDeps(deps, DEFAULT_RULES);
  const rawSource = scanSource(dir, DEFAULT_RULES);
  const fromSource = deduplicateOccurrences(rawSource);
  const components = mergeEvidence(fromDeps, fromSource);
  const bom = toCycloneDX(components);

  const output = JSON.stringify(bom, null, 2);
  if (outPath) {
    fs.writeFileSync(outPath, output, 'utf-8');
    console.error(`cbom-scan: wrote ${components.length} algorithms to ${outPath}`);
  } else {
    console.log(output);
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}