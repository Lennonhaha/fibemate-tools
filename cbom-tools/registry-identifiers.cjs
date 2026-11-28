// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// registry-identifiers.cjs — read *registered* algorithm names into components.
//
// Why this exists
// ---------------
// 0.3.2 saw an algorithm only where its canonical name was written out
// ("AES-GCM", "ML-KEM-768"). Everything the standards bodies publish as an
// *identifier* was invisible: a TLS cipher suite, a supported group, a
// signature scheme, a JWA `alg` value. Those strings are most of what a real
// TLS/IKE/SSH policy file contains, so a CBOM built from such a file said "no
// cryptography here" while the file was nothing but cryptography. The ShorList
// measured run (2,099 forms) put the cost of that blind spot at 0 hits on the
// DH, EC, EdDSA, LMS and XMSS families.
//
// Sources, one per name space. All are public registries; nothing is fetched
// at scan time, and no benchmark row is read.
//   * TLS cipher suites, supported groups, signature schemes — IANA "TLS
//     Parameters" registry (RFC 8446, RFC 5246, RFC 8422, RFC 7919).
//   * FFDHE groups — RFC 7919.  MODP groups — RFC 3526.
//     SSH key-exchange groups — RFC 4253, RFC 8268.
//   * Curve names — SEC 2, FIPS 186-5 (NIST P-/K-/B-), RFC 5639 (brainpool),
//     X9.62 prime*, RFC 7748 (X25519/X448). The list below is the one in
//     CycloneDX `cryptography-defs.json` → `ellipticCurves`.
//   * Signature schemes and JWA `alg` values — RFC 8446 §4.2.3, RFC 7518 §3.1,
//     RFC 8709 (Ed25519/Ed448 in SSH), NIST SP 800-208 (LMS/XMSS).
//
// Naming: a component is named for its family plus the parameter the
// identifier pins, in the CycloneDX style `<family>-<parameter>`
// (`EC-P-256`, `DH-ffdhe2048`, `EdDSA-Ed25519`). A bare family name (`RSA`,
// `ECDH`) is used where the identifier pins nothing beyond the family. This
// keeps the name honest: `EC-P-256` says "this is the P-256 curve", not "this
// is ECDSA" — the curve alone does not choose a role, and the identifier
// around it (`PURPOSE_SIGN`, `set_ecdh_curve`, …) does.
//
// A cipher suite is decomposed into every algorithm it names, because that is
// what the suite is: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` is ECDH (key
// agreement) plus RSA (authentication) plus AES-256-GCM (record protection)
// plus SHA-384 (PRF/transcript). Reporting only one of them is how 0.3.2
// produced `wrong family` for four rows: it took the authentication segment
// and called it the algorithm.
'use strict';

// ── Curve vocabulary ────────────────────────────────────────────────
// Canonical spelling is the registry's; matching is case-insensitive.
const NIST_CURVES = [
  'P-192', 'P-224', 'P-256', 'P-384', 'P-521',
  'K-163', 'K-233', 'K-283', 'K-409', 'K-571',
  'B-163', 'B-233', 'B-283', 'B-409', 'B-571',
];
const SECG_CURVES = [
  'secp112r1', 'secp112r2', 'secp128r1', 'secp128r2',
  'secp160k1', 'secp160r1', 'secp160r2',
  'secp192k1', 'secp192r1', 'secp224k1', 'secp224r1',
  'secp256k1', 'secp256r1', 'secp384r1', 'secp521r1',
  'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2',
  'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2',
  'sect233k1', 'sect233r1', 'sect239k1',
  'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1',
  'sect571k1', 'sect571r1',
];
const BRAINPOOL_CURVES = [];
for (const bits of [160, 192, 224, 256, 320, 384, 512]) {
  for (const suffix of ['r1', 't1']) BRAINPOOL_CURVES.push(`brainpoolP${bits}${suffix}`);
}
const X962_CURVES = ['prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3', 'prime256v1'];
// RFC 7748 keeps its own spelling; a CBOM of a TLS stack meets "X25519" far
// more often than "Curve25519", and both name the same curve.
const MONTGOMERY_CURVES = [
  ['x25519', 'X25519'], ['curve25519', 'X25519'],
  ['x448', 'X448'], ['curve448', 'X448'],
];

const CURVE_CANON = new Map(); // lower(name) -> canonical name
for (const n of [...NIST_CURVES, ...SECG_CURVES, ...BRAINPOOL_CURVES, ...X962_CURVES]) {
  CURVE_CANON.set(n.toLowerCase(), n);
}
for (const [alias, canon] of MONTGOMERY_CURVES) CURVE_CANON.set(alias, canon);

// One alternation, longest first so `secp256k1` wins over shorter shares.
// Boundaries are letters-only, not `\b`: registered identifiers glue the curve
// to its neighbour with `_` (`SSL_GROUP_X25519_MLKEM768`,
// `MBEDTLS_ECP_DP_SECP384R1`), and `\b` treats `_` as a word character, which
// is why the first cut of this module missed both.
const CURVE_RE = new RegExp(
  '(?<![A-Za-z])(?:'
  + [...CURVE_CANON.values()]
    .sort((a, b) => b.length - a.length)
    .map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|')
  + ')(?![A-Za-z])',
  'gi',
);

// ── Finite-field groups (FFDH) ──────────────────────────────────────
// RFC 7919 (ffdhe) and RFC 3526 (modp) name groups by modulus size; SSH names
// them by group number (RFC 4253) or by the modulus size explicitly (RFC 8268).
const DH_GROUP_RES = [
  ['ffdhe', /(?<![A-Za-z])ffdhe(2048|3072|4096|6144|8192)(?![0-9])/gi],
  ['modp', /(?<![A-Za-z])modp(768|1024|1536|2048|3072|4096|6144|8192)(?![0-9])/gi],
  ['group', /(?<![A-Za-z])diffie-hellman-group(1|14|15|16|17|18)(?![0-9])/gi],
  ['ecp', /(?<![A-Za-z])ecp(256|384|521)(?![0-9])/gi],
];

// ── TLS cipher suites ───────────────────────────────────────────────
// Bulk ciphers that the family vocabulary in CycloneDX covers. Anything else
// (CAMELLIA, ARIA, SEED, NULL) is deliberately left out: a component named for
// a family nobody defines is noise in the BOM, not evidence.
//
// Token boundaries are `_`-aware for the same reason as the curve list:
// `AES_256_GCM`, `3DES_EDE_CBC`, `RC4_40`, `DES_CBC`. Order matters — 3DES
// before DES, or every triple-DES suite is read as single DES.
const BULK_TOKENS = [
  [/(?:^|_)3DES(?:_|$)|DES_EDE/, '3DES'],
  [/(?:^|_)DES(?:40|_CBC|_|$)/, 'DES'],
  [/(?:^|_)RC4(?:_|$)/, 'RC4'],
  [/(?:^|_)RC2(?:_|$)/, 'RC2'],
  [/(?:^|_)CHACHA20(?:_|$)/, 'ChaCha20'],
  [/(?:^|_)AES(?:128|192|256)?(?:_|$)/, 'AES'],
];

function familiesOfKex(kex) {
  const out = [];
  if (/^ECDHE/.test(kex) || /^ECDH/.test(kex)) out.push('ECDH');
  else if (/^EDH|^DHE|^DH/.test(kex)) out.push('DH');
  if (/(?:^|_)RSA(?:$|_)/.test(kex)) out.push('RSA');
  if (/(?:^|_)ECDSA(?:$|_)/.test(kex)) out.push('ECDSA');
  if (/(?:^|_)DSS(?:$|_)/.test(kex)) out.push('DSA');
  // PSK/SRP/KRB5/ANON carry no public-key algorithm of their own.
  return out;
}

// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` -> ['ECDH', 'RSA', 'AES']
// The trailing hash is returned only when it is a family the BOM vocabulary
// knows (SHA-1, MD5); SHA-256/384 are PRF inputs, not separate assets here.
function decomposeTlsSuite(suite) {
  const out = [];
  const upper = suite.toUpperCase();
  const withAt = upper.indexOf('_WITH_');
  const kex = withAt >= 0 ? upper.slice(4, withAt) : '';
  const body = withAt >= 0 ? upper.slice(withAt + 6) : upper.slice(4);
  if (kex) for (const f of familiesOfKex(kex)) out.push(f);
  // TLS 1.3 suites have no key-exchange token: every one of them uses
  // (EC)DHE, but the name does not say which, so nothing is claimed here.
  for (const [re, fam] of BULK_TOKENS) if (re.test(body)) { out.push(fam); break; }
  if (/_MD5$/.test(body)) out.push('MD5');
  else if (/_SHA$/.test(body)) out.push('SHA-1');
  return out;
}

// OpenSSL cipher-list element: `ECDHE-RSA-AES256-GCM-SHA384`, `DHE-RSA-AES256`,
// `ECDHE+AESGCM`, `AES128-GCM-SHA256`. A leading `!` is an exclusion, and an
// exclusion is not a use — the caller's regex never starts inside `!`.
function decomposeOpensslCipher(text) {
  const out = [];
  for (const part of text.split(/[+-]/)) {
    const up = part.toUpperCase();
    const kexFams = familiesOfKex(up);
    if (kexFams.length) { out.push(...kexFams); continue; }
    for (const [re, bulk] of BULK_TOKENS) {
      const probe = `_${up}_`;
      if (re.test(probe)) { out.push(bulk); break; }
    }
    if (up === 'SHA') out.push('SHA-1');
    else if (up === 'MD5') out.push('MD5');
  }
  return out;
}

// ── Signature schemes and JWA `alg` ─────────────────────────────────
// `(?<![A-Za-z])` again: `mbedtls_ecdsa_genkey`, `rsa_pss_rsae_sha256` and
// `MLKEM768` are glued with `_` and would be missed by `\b`.
const SIGNATURE_RES = [
  [/(?<![A-Za-z])rsa[-_]?(?:pss|pkcs1|oaep|ssa|es)[-_]?(?:rsae[-_]?|pss[-_]?)?(?:sha[-_]?\d+|pss|oaep)?/gi, 'RSA'],
  [/(?<![A-Za-z])rsa[-_]sha2[-_]?\d+/gi, 'RSA'],
  [/(?<![A-Za-z])RSA[_-](?:PSS|PKCS1|OAEP)[-_]?[\w-]*/g, 'RSA'],
  [/(?<![A-Za-z])ecdsa(?:[-_][\w-]+)?/gi, 'ECDSA'],
  [/(?<![A-Za-z])ES(256K?|384|512)(?![0-9])/g, 'ECDSA'],
  [/(?<![A-Za-z])(?:RS|PS)(256|384|512)(?![0-9])/g, 'RSA'],
  [/(?<![A-Za-z])ssh-rsa(?![A-Za-z])/gi, 'RSA'],
  [/(?<![A-Za-z])ssh-dss(?![A-Za-z])/gi, 'DSA'],
  [/(?<![A-Za-z])ssh-ed25519(?![A-Za-z])/gi, 'EdDSA'],
  [/(?<![A-Za-z])eddsa(?![A-Za-z])/gi, 'EdDSA'],
  [/(?<![A-Za-z])ecdhe(?![A-Za-z])/gi, 'ECDH'],
  [/(?<![A-Za-z])slh[-_]?dsa[\w-]*/gi, 'SLH-DSA'],
  [/(?<![A-Za-z])mldsa[-_]?(\d{2,3})(?![0-9])/gi, 'ML-DSA-$1'],
  [/(?<![A-Za-z])mlkem[-_]?(\d{3,4})(?![0-9])/gi, 'ML-KEM-$1'],
  [/xwing[-_]?mlkem[-_]?(\d{3,4})/gi, 'ML-KEM-$1'],
  [/(?<![A-Za-z])lms[-_](?:sha2?[-_]?\d+|sha256[-_]m\d+[-_]h\d+)[\w-]*/gi, 'LMS'],
  [/(?<![A-Za-z])xmss[-_][\w-]+/gi, 'XMSS'],
];

// ── Line context ────────────────────────────────────────────────────
// A curve name in a group list is used for key agreement; the same name in
// `CURVE = "P-256"` is just a curve. A curve under `PURPOSE_SIGN` is used for
// signatures. Neither name says so by itself, so the surrounding identifier
// decides which side of the family the component belongs to.
const KEX_CONTEXT = /(?:TLS_GROUP|GROUPS?|supported_groups|KexAlgorithms|kex|kx_group|ecdh_curves?|ECCurve|NamedGroup|Group|KE_METHODS|KEY_EXCHANGE|AGREE_KEY|SSL_GROUP|ecdhCurves)/i;
const SIGN_CONTEXT = /(?:\b(?:ECDSA|PURPOSE_SIGN|PURPOSE_VERIFY|sign|signing|signature|KeyAlgorithm|KeySpec)\b)/i;

function lineOf(content, index) {
  let from = index;
  while (from > 0 && content[from - 1] !== '\n') from--;
  let to = index;
  while (to < content.length && content[to] !== '\n') to++;
  return { text: content.slice(from, to), start: from };
}

/**
 * Every registered identifier in `content`, as
 * `{ index, end, algorithms: string[], symbol }`.
 * The caller decides whether the position is a use (see isNotAUse in
 * cbom-scan.cjs) and where the line is.
 */
function collectRegistrySites(content) {
  const sites = [];
  const push = (index, end, algorithms, symbol) => {
    // `!ECDSA` in a cipher list is an exclusion (see cipherListElement).
    if (index > 0 && content[index - 1] === '!') return;
    const algs = [...new Set(algorithms.filter(Boolean))];
    if (algs.length) sites.push({ index, end, algorithms: algs, symbol });
  };

  // TLS 1.2/1.0 suite names (and the `TLS_` prefix of 1.3 suites).
  const tlsRe = /(?<![A-Za-z])TLS_[A-Z0-9_]+/g;
  let m;
  while ((m = tlsRe.exec(content)) !== null) {
    const text = m[0];
    if (/_WITH_/.test(text)) {
      push(m.index, m.index + text.length, decomposeTlsSuite(text), text);
      continue;
    }
    // `TLS_AES_128_GCM_SHA256` (TLS 1.3): bulk cipher only. `TLS_GROUP`-style
    // identifiers are handled by the curve and group rules below.
    if (/^TLS_AES|^TLS_CHACHA20|^TLS_ARIA/.test(text)) {
      push(m.index, m.index + text.length, decomposeTlsSuite(text), text);
    }
  }

  // OpenSSL-style elements. The lookbehind keeps `!ECDSA` (an exclusion) out.
  const osslRe = /(?<![A-Za-z0-9_!-])(?:ECDHE|ECDH|DHE|DH|RSA)(?:[+-][A-Za-z0-9_]+)+/g;
  while ((m = osslRe.exec(content)) !== null) {
    push(m.index, m.index + m[0].length, decomposeOpensslCipher(m[0]), m[0]);
  }

  // Registered curves. `X25519`/`X448` keep their own family; every other
  // curve is a parameter of the EC family. A group-list context adds ECDH, a
  // signing context adds ECDSA — the curve alone never picks a role.
  CURVE_RE.lastIndex = 0;
  while ((m = CURVE_RE.exec(content)) !== null) {
    const canon = m[0];
    const low = canon.toLowerCase();
    const line = lineOf(content, m.index).text;
    const canonical = CURVE_CANON.get(low) || canon;
    const isMont = low === 'x25519' || low === 'x448' || low === 'curve25519' || low === 'curve448';
    const fam = low === 'x25519' || low === 'curve25519' ? 'X25519'
      : low === 'x448' || low === 'curve448' ? 'X448'
        : `EC-${canonical}`;
    const algs = [fam];
    const kex = KEX_CONTEXT.test(line);
    if (kex) algs.push(isMont ? `ECDH-${canonical.toLowerCase()}` : `ECDH-${canonical}`);
    if (!isMont && SIGN_CONTEXT.test(line)) algs.push('ECDSA');
    push(m.index, m.index + m[0].length, algs, canon);
  }

  // FFDHE / MODP / SSH-DH / IKE-ECP groups.
  for (const [kind, re] of DH_GROUP_RES) {
    re.lastIndex = 0;
    while ((m = re.exec(content)) !== null) {
      const bits = m[1];
      if (kind === 'ecp') {
        // IKE names EC groups `ecp256`; the curve is P-256.
        push(m.index, m.index + m[0].length, [`EC-P-${bits}`, 'ECDH'], m[0]);
      } else {
        push(m.index, m.index + m[0].length, [`DH-${kind}${bits}`], m[0]);
      }
    }
  }

  // Signature schemes, JWA `alg`, SSH key algorithms, hybrid KEM names.
  for (const [re, template] of SIGNATURE_RES) {
    re.lastIndex = 0;
    while ((m = re.exec(content)) !== null) {
      const fam = template.replace(/\$(\d+)/g, (_, i) => m[Number(i)] || '');
      const algs = [fam];
      // `X25519MLKEM768` names two algorithms; so does `secp256r1MLKEM768`.
      if (/ML-KEM-\d+/.test(fam) && /x448/i.test(m[0]) && !/X448/.test(fam)) algs.push('X448');
      if (/ML-KEM-\d+/.test(fam) && /x25519|secp256r1|p256/i.test(m[0])) {
        if (/x25519/i.test(m[0])) algs.push('X25519');
        else algs.push('EC-secp256r1');
      }
      push(m.index, m.index + m[0].length, algs, m[0]);
    }
  }

  return sites;
}

/** Key size in bits for a component name this module produced, else null. */
function registrySize(name) {
  const dh = /^DH-(?:ffdhe|modp)(\d{3,4})$/.exec(name);
  if (dh) return Number(dh[1]);
  // RFC 3526 group numbers, by modulus size.
  const g = /^DH-group(\d+)$/.exec(name);
  if (g) return { 1: 1024, 14: 2048, 15: 3072, 16: 4096, 17: 6144, 18: 8192 }[g[1]] || null;
  if (/^X25519$/.test(name)) return 255;
  if (/^X448$/.test(name)) return 448;
  if (/^EdDSA-Ed25519$/.test(name)) return 255;
  if (/^EdDSA-Ed448$/.test(name)) return 448;
  const m = /^(?:EC|ECDH)-.*?(\d{2,4})/.exec(name);
  if (m) return Number(m[1]);
  return null;
}

module.exports = { collectRegistrySites, registrySize, CURVE_CANON };
