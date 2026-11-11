#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-scan.cjs — scan a directory tree for cryptographic assets,
// emit a CycloneDX 1.6 or 1.7 CBOM with provenance-aware merge policy.

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
    // ── Receiver-agnostic call sites ──────────────────────────────
    // `crypto.createHash('sha-256')` above only sees the literal receiver.
    // A destructured import (`const { createHash: h } = require('crypto')`)
    // or a wrapper object (`c.createHash(...)`) hides the receiver, so the
    // same argument is matched without naming the object.
    { re: /\.createHash\(\s*['"]sha-?256['"]/g, algs: ['SHA-256'] },
    { re: /\.createHash\(\s*['"]sha-?512['"]/g, algs: ['SHA-512'] },
    { re: /\.createCipheriv\(\s*['"][^'"]{0,64}aes[^'"]{0,64}gcm[^'"]{0,64}['"]/gi, algs: ['AES-GCM'] },
    // ── Bare algorithm identifiers ────────────────────────────────
    // Names that appear as data (config, CLI flag, registry key) rather
    // than as part of a known function name.
    { re: /\baes[-_]?(?:128|192|256)[-_]?gcm\b/gi, algs: ['AES-GCM'] },
    { re: /\bchacha20[-_]?poly1305\b/gi, algs: ['ChaCha20-Poly1305'] },
    { re: /\bed25519\b/gi, algs: ['Ed25519'] },
    { re: /\bx25519\b/gi, algs: ['X25519'] },
    { re: /\becdh\b/gi, algs: ['ECDH'] },
    { re: /\brsa\b/gi, algs: ['RSA'] },
    { re: /\bsha-?256\b/gi, algs: ['SHA-256'] },
    { re: /\bsha-?512\b/gi, algs: ['SHA-512'] },
  ],
};

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.cache']);
const SCAN_EXT = /\.(cjs|mjs|js|ts|tsx|jsx|cpp|c|h|hpp|py)$/;
const MAX_OCC_PER_ALGO = 50;
// A single generated bundle or vendored blob can be hundreds of megabytes.
// Reading it whole buys nothing — the scan is textual and the file is not
// hand-written crypto — so the scanner skips it and says so on stderr.
const MAX_FILE_BYTES = 8 * 1024 * 1024;

function warn(message) {
  console.error('cbom-scan: warning: ' + message);
}

// ── Literal resolution ──────────────────────────────────────────────
//
// A name that is assembled at compile time is still a name. This pass
// recovers the common assembly forms so the regexes above can see them:
//
//   'sha' + '256'                    adjacent literal concatenation
//   ['sh', 'a256'].join('')          array join
//   `ml-kem-${'768'}`                template with literal interpolation
//   Buffer.from('bWwt...', 'base64') base64 payload
//   '\x73\x68\x61\x32\x35\x36'       escaped bytes
//
// It is deliberately syntactic. A name computed from a variable, an
// environment variable, or a network response is NOT recovered — see
// README "What a static scan cannot see". Claiming otherwise would be the
// exact false assurance this tool exists to prevent.

function decodeEscapes(text) {
  return text.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, (m, seq) => {
    if (seq[0] === 'x' && seq.length === 3) return String.fromCharCode(parseInt(seq.slice(1), 16));
    if (seq[0] === 'u' && seq.length === 5) return String.fromCharCode(parseInt(seq.slice(1), 16));
    switch (seq) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      case '\\': return '\\';
      case "'": return "'";
      case '"': return '"';
      case '`': return '`';
      default: return seq;
    }
  });
}

function lineAt(content, index) {
  return content.slice(0, index).split('\n').length;
}

/**
 * Recover algorithm names that are assembled out of literals.
 *
 * This walks the source once with an explicit escape state instead of running
 * regexes over raw file content: a quote-class with an optional escape branch
 * is polynomial on adversarial input (CodeQL says so, correctly), and a literal
 * scanner cannot backtrack at all.
 *
 * @returns {Array<{text: string, line: number}>}
 */
function readQuoted(content, start) {
  const quote = content[start];
  let i = start + 1;
  let raw = '';
  while (i < content.length) {
    const ch = content[i];
    if (ch === '\\') {
      if (i + 1 >= content.length) return null;
      raw += ch + content[i + 1];
      i += 2;
      continue;
    }
    if (ch === quote) return { value: raw, quote, start, end: i };
    if (quote !== '`' && ch === '\n') return null;
    raw += ch;
    i++;
  }
  return null;
}

function collectLiterals(content) {
  const lits = [];
  let i = 0;
  while (i < content.length) {
    const ch = content[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const lit = readQuoted(content, i);
      if (lit) {
        lits.push(lit);
        i = lit.end + 1;
        continue;
      }
    }
    i++;
  }
  return lits;
}

function lastNonSpace(content, before) {
  for (let i = before - 1; i >= 0; i--) {
    const ch = content[i];
    if (ch !== ' ' && ch !== '\t' && ch !== '\r' && ch !== '\n') return ch;
    if (before - i > 200) return null;
  }
  return null;
}

const BASE64_CHARS = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');

function looksLikeBase64(text) {
  if (text.length < 8 || text.length % 4 !== 0) return false;
  let padding = 0;
  for (const ch of text) {
    if (!BASE64_CHARS.has(ch)) return false;
    if (ch === '=') padding++;
    else if (padding > 0) return false;
  }
  return padding <= 2;
}

function deriveLiterals(content) {
  const out = [];
  const push = (text, index) => {
    const decoded = decodeEscapes(text);
    // Short names matter (`md5`, `aes`, `sha256`), so the floor is 3 — but a
    // literal with no letters at all cannot name an algorithm.
    if (decoded.trim().length >= 3 && /[a-z]/i.test(decoded)) out.push({ text: decoded, line: lineAt(content, index) });
  };

  const lits = collectLiterals(content);

  // 1. Adjacent literal concatenation, including across line breaks.
  //    'sha' + '256'  /  'ml-kem-' +\n  '768'
  for (let i = 0; i < lits.length; i++) {
    let text = lits[i].value;
    let j = i;
    while (j + 1 < lits.length && content.slice(lits[j].end + 1, lits[j + 1].start).trim() === '+') {
      text += lits[j + 1].value;
      j++;
    }
    if (j > i) push(text, lits[i].start);
  }

  // 2. Array of literals joined with an empty separator: ['ml','-kem'].join('')
  for (let i = 0; i + 1 < lits.length; i++) {
    let j = i;
    while (j + 1 < lits.length && content.slice(lits[j].end + 1, lits[j + 1].start).trim() === ',') j++;
    if (j === i) continue;
    if (lastNonSpace(content, lits[i].start) !== '[') continue;
    const tail = content.slice(lits[j].end + 1, lits[j].end + 64);
    if (!/^\s*\]\s*\.join\(\s*(['"`])\1\s*\)/.test(tail)) continue;
    push(lits.slice(i, j + 1).map((l) => l.value).join(''), lits[i].start);
  }

  // 3. Template literals whose only interpolation is a string literal:
  //    `ml-kem-${'768'}`
  for (const lit of lits) {
    if (lit.quote !== '`' || !lit.value.includes('${')) continue;
    let flat = '';
    let rest = lit.value;
    let unresolved = false;
    while (rest.length > 0) {
      const at = rest.indexOf('${');
      if (at === -1) { flat += rest; break; }
      flat += rest.slice(0, at);
      const close = rest.indexOf('}', at + 2);
      if (close === -1) { unresolved = true; break; }
      const inner = rest.slice(at + 2, close).trim();
      const sub = inner.startsWith('"') || inner.startsWith("'") ? readQuoted(inner, 0) : null;
      if (sub && sub.end === inner.length - 1) flat += sub.value;
      else { flat += '${'; unresolved = true; }
      rest = rest.slice(close + 1);
    }
    if (!unresolved) push(flat, lit.start);
  }

  // 4. base64 payloads: Buffer.from('<b64>', 'base64') / atob('<b64>')
  const markers = ['Buffer.from(', 'atob('];
  for (const marker of markers) {
    let from = 0;
    for (;;) {
      const at = content.indexOf(marker, from);
      if (at === -1) break;
      from = at + marker.length;
      let p = from;
      while (p < content.length && (content[p] === ' ' || content[p] === '\t')) p++;
      const lit = readQuoted(content, p);
      if (!lit || (lit.quote !== '"' && lit.quote !== "'")) continue;
      if (!looksLikeBase64(lit.value)) continue;
      if (marker === 'Buffer.from(') {
        const tail = content.slice(lit.end + 1, lit.end + 32);
        if (!/^\s*,\s*(['"`])base64\1\s*\)/.test(tail)) continue;
      }
      const decoded = Buffer.from(lit.value, 'base64').toString('utf-8');
      push(decoded, at);
    }
  }

  // 5. Plain literals written as escapes ('\x73\x68\x61\x32\x35\x36').
  // A literal with no backslash is already visible to the regexes; only the
  // escaped form needs decoding.
  for (const lit of lits) {
    if (lit.value.includes('\\')) push(lit.value, lit.start);
  }

  return out;
}

// ── Dependency inference ────────────────────────────────────────────

function loadPackageDeps(dir) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return {};
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    return { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  } catch (err) {
    // A manifest we cannot parse is a coverage hole, not a clean result:
    // dependency inference silently degrades to source-only. Say so.
    warn('cannot parse ' + pkgPath + ' (' + (err.code || err.message) + '); dependency inference skipped');
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
    catch (err) {
      warn('cannot read directory ' + d + ' (' + (err.code || err.message) + '); skipped');
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!SCAN_EXT.test(entry.name)) continue;
      let content;
      try {
        const st = fs.statSync(full);
        if (st.size > MAX_FILE_BYTES) {
          warn('skipped ' + path.relative(root, full) + ': ' + st.size + ' bytes exceeds ' + MAX_FILE_BYTES);
          continue;
        }
        content = fs.readFileSync(full, 'utf-8');
      } catch (err) {
        warn('skipped ' + path.relative(root, full) + ': ' + (err.code || err.message));
        continue;
      }
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
      // Second pass over names assembled from literals (concat / join /
      // template / base64 / escaped bytes). Occurrences are reported at
      // the line where the literal is written.
      for (const lit of deriveLiterals(content)) {
        for (const { re, algs } of rules.sourcePatterns) {
          const scan = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
          let lm;
          while ((lm = scan.exec(lit.text)) !== null) {
            const span = { start: lm.index, end: lm.index + lm[0].length };
            for (const a of algs) {
              const name = a.replace(/\$(\d+)/g, (_, i) => lm[i]);
              addOcc(name, full, lit.line, lm[0], span);
            }
            if (lm[0].length === 0) break;
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

function toCycloneDX(components, specVersion) {
  return {
    bomFormat: 'CycloneDX',
    specVersion,
    version: 1,
    // `nistQuantumSecurityLevel` is deliberately absent from every component:
    // this scan is file-level, so any integer in 0..6 would be an invented
    // assessment. Omission says "unknown", and the note below says so out
    // loud, because a consumer that folds absent into 0 would otherwise read
    // an inventory as a claim that nothing is quantum-safe.
    properties: [
      {
        name: 'fibemate:nistQuantumSecurityLevel:semantics',
        value: 'omitted means unknown/unassessed, never 0',
      },
    ],
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'cbom-scan', version: PKG.version, vendor: 'FIBEMATE' }],
    },
    components,
  };
}

// ── Entry point ─────────────────────────────────────────────────────

const SPEC_VERSIONS = ['1.6', '1.7'];
const DEFAULT_SPEC = '1.7';
const USAGE = 'usage: cbom-scan [--dir <path>] [--out <file>] [--spec 1.6|1.7]';

/**
 * Read `--flag value` or `--flag=value`.
 *
 * The equals form used to be invisible to the parser: `--dir=./x` left the
 * directory at process.cwd() and scanned the wrong tree without complaining.
 * A flag that is silently ignored is worse than a flag that errors.
 */
function readFlag(args, name) {
  const eqPrefix = name + '=';
  let value = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name) {
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) return { error: name + ' needs a value' };
      value = next;
    } else if (args[i].startsWith(eqPrefix)) {
      value = args[i].slice(eqPrefix.length);
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

  const dirFlag = readFlag(args, '--dir');
  if (dirFlag.error) fail(dirFlag.error);
  const dir = dirFlag.value === null ? process.cwd() : dirFlag.value;

  const outFlag = readFlag(args, '--out');
  if (outFlag.error) fail(outFlag.error);
  const outPath = outFlag.value;

  const specFlag = readFlag(args, '--spec');
  if (specFlag.error) fail(specFlag.error);
  const specVersion = specFlag.value === null ? DEFAULT_SPEC : specFlag.value;
  if (!SPEC_VERSIONS.includes(specVersion)) {
    fail('--spec must be one of ' + SPEC_VERSIONS.join(', ') + ' (got "' + specVersion + '")');
  }

  // A path that does not exist used to produce an empty CBOM and exit 0.
  // Downstream that reads as "no cryptography here" — a false clean result
  // on a typo. Refuse instead; see README "Exit codes".
  let dirStat;
  try { dirStat = fs.statSync(dir); }
  catch (err) {
    fail('--dir not found: ' + dir + ' (' + (err.code || err.message) + ')');
  }
  if (!dirStat.isDirectory()) fail('--dir is not a directory: ' + dir);

  const deps = loadPackageDeps(dir);
  const fromDeps = matchDeps(deps, DEFAULT_RULES);
  const rawSource = scanSource(dir, DEFAULT_RULES);
  const fromSource = deduplicateOccurrences(rawSource);
  const components = mergeEvidence(fromDeps, fromSource);
  const bom = toCycloneDX(components, specVersion);

  const output = JSON.stringify(bom, null, 2);
  if (outPath) {
    fs.writeFileSync(outPath, output, 'utf-8');
    console.error(`cbom-scan: wrote ${components.length} algorithms to ${outPath} (CycloneDX ${specVersion})`);
  } else {
    console.log(output);
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_RULES,
  deriveLiterals,
  decodeEscapes,
  scanSource,
  deduplicateOccurrences,
  mergeEvidence,
  toCycloneDX,
  lookupMeta,
};