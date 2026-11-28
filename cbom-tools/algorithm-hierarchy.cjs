// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// algorithm-hierarchy.cjs — algorithm family / parameter-set lookup.
// Used by cbom-scan.cjs for provenance dedup and confidence scoring.
//
// `params: null` marks a family-level (generic) name. A generic hit is
// dropped when a parameterised hit of the same family covers it on the
// same line, so `camellia-256-cbc` yields one Camellia-256 component
// instead of Camellia-256 plus Camellia.
//
// Names that are missing here are still emitted by the scanner; they just
// do not take part in generic/specific absorption (see deduplicateOccurrences).
// Keep this list aligned with `sourcePatterns` in cbom-scan.cjs and with
// algo-metadata.json; test/legacy-recall.test.cjs asserts the alignment.

const HIERARCHY = {
  // ── ML-DSA / ML-KEM ──────────────────────────────────────────────
  'ML-DSA-44':  { family: 'ML-DSA', params: '44' },
  'ML-DSA-65':  { family: 'ML-DSA', params: '65' },
  'ML-DSA-87':  { family: 'ML-DSA', params: '87' },
  'ML-DSA':     { family: 'ML-DSA', params: null },
  'ML-KEM-512':  { family: 'ML-KEM', params: '512' },
  'ML-KEM-768':  { family: 'ML-KEM', params: '768' },
  'ML-KEM-1024': { family: 'ML-KEM', params: '1024' },
  'ML-KEM':      { family: 'ML-KEM', params: null },
  'Kyber-512':   { family: 'Kyber', params: '512' },
  'Kyber-768':   { family: 'Kyber', params: '768' },
  'Kyber-1024':  { family: 'Kyber', params: '1024' },
  'Kyber':       { family: 'Kyber', params: null },
  'Dilithium-2': { family: 'Dilithium', params: '2' },
  'Dilithium-3': { family: 'Dilithium', params: '3' },
  'Dilithium-5': { family: 'Dilithium', params: '5' },
  'Dilithium':   { family: 'Dilithium', params: null },

  // ── hash: classical ──────────────────────────────────────────────
  MD5:           { family: 'MD5', params: null },
  'SHA-1':       { family: 'SHA-1', params: null },
  'SHA-224':     { family: 'SHA-224', params: null },
  'SHA-256':     { family: 'SHA-256', params: null },
  'SHA-384':     { family: 'SHA-384', params: null },
  'SHA-512':     { family: 'SHA-512', params: null },
  // `SHA-3` is the name people write; `SHA3-256` is the name the scanner
  // emits. Both point at the one SHA3 family so metadata resolves either way.
  'SHA-3':       { family: 'SHA3', params: null },
  'SHA3-224':    { family: 'SHA3', params: '224' },
  'SHA3-256':    { family: 'SHA3', params: '256' },
  'SHA3-384':    { family: 'SHA3', params: '384' },
  'SHA3-512':    { family: 'SHA3', params: '512' },
  'SHA3':        { family: 'SHA3', params: null },

  // ── hash: Keccak / BLAKE2 ────────────────────────────────────────
  'Keccak-224':  { family: 'Keccak', params: '224' },
  'Keccak-256':  { family: 'Keccak', params: '256' },
  'Keccak-384':  { family: 'Keccak', params: '384' },
  'Keccak-512':  { family: 'Keccak', params: '512' },
  'Keccak':      { family: 'Keccak', params: null },
  'Blake2b-256': { family: 'Blake2b', params: '256' },
  'Blake2b-384': { family: 'Blake2b', params: '384' },
  'Blake2b-512': { family: 'Blake2b', params: '512' },
  'Blake2b':     { family: 'Blake2b', params: null },
  'Blake2s-256': { family: 'Blake2s', params: '256' },
  'Blake2s':     { family: 'Blake2s', params: null },

  // ── symmetric ────────────────────────────────────────────────────
  'AES':          { family: 'AES', params: null },
  'AES-GCM':      { family: 'AES', params: 'GCM' },
  'AES-CBC':      { family: 'AES', params: 'CBC' },
  'AES-CTR':      { family: 'AES', params: 'CTR' },
  'AES-CFB':      { family: 'AES', params: 'CFB' },
  'AES-OFB':      { family: 'AES', params: 'OFB' },
  'AES-ECB':      { family: 'AES', params: 'ECB' },
  'DES':          { family: 'DES', params: null },
  '3DES':         { family: '3DES', params: null },
  'Blowfish':     { family: 'Blowfish', params: null },
  'Poly1305':     { family: 'Poly1305', params: null },
  'ChaCha20-Poly1305': { family: 'ChaCha20-Poly1305', params: null },
  'Camellia-128': { family: 'Camellia', params: '128' },
  'Camellia-192': { family: 'Camellia', params: '192' },
  'Camellia-256': { family: 'Camellia', params: '256' },
  'Camellia':     { family: 'Camellia', params: null },
  'ARIA-128':     { family: 'ARIA', params: '128' },
  'ARIA-192':     { family: 'ARIA', params: '192' },
  'ARIA-256':     { family: 'ARIA', params: '256' },
  'ARIA':         { family: 'ARIA', params: null },

  // ── SM (GB/T 32918, 32905, 32907) ────────────────────────────────
  'SM2':          { family: 'SM2', params: null },
  'SM3':          { family: 'SM3', params: null },
  'SM4':          { family: 'SM4', params: null },
  'SM4-GCM':      { family: 'SM4', params: 'GCM' },
  'SM4-CBC':      { family: 'SM4', params: 'CBC' },
  'SM4-CTR':      { family: 'SM4', params: 'CTR' },
  'SM4-CFB':      { family: 'SM4', params: 'CFB' },
  'SM4-OFB':      { family: 'SM4', params: 'OFB' },
  'SM4-ECB':      { family: 'SM4', params: 'ECB' },

  // ── KDF / password hashing ───────────────────────────────────────
  'Argon2i':      { family: 'Argon2i', params: null },

  // ── classical public key ─────────────────────────────────────────
  'RSA':          { family: 'RSA', params: null },
  'DSA':          { family: 'DSA', params: null },
  'ECDSA':        { family: 'ECDSA', params: null },
  'ECDH':         { family: 'ECDH', params: null },
  // Ed25519/Ed448 and X25519/X448 are single-curve names, not parameter
  // sets, so they stay `params: null` and never absorb one another.
  'Ed25519':      { family: 'EdDSA', params: null },
  'Ed448':        { family: 'EdDSA', params: null },
  // Family-qualified spellings emitted for registered identifiers. The
  // bare curve names above stay, because a source file may write
  // `crypto_sign` (monocypher) or `ed25519-dalek` and nothing else.
  'EdDSA':         { family: 'EdDSA', params: null },
  'EdDSA-Ed25519': { family: 'EdDSA', params: 'Ed25519' },
  'EdDSA-Ed448':   { family: 'EdDSA', params: 'Ed448' },
  'X25519':       { family: 'XDH', params: null },
  'X448':         { family: 'XDH', params: null },

  // ── post-quantum families beyond NIST round 3 winners ────────────
  'SLH-DSA':        { family: 'SLH-DSA', params: null },
  'Falcon-512':     { family: 'Falcon', params: '512' },
  'Falcon-1024':    { family: 'Falcon', params: '1024' },
  'Falcon':         { family: 'Falcon', params: null },
  'HQC-128':        { family: 'HQC', params: '128' },
  'HQC-192':        { family: 'HQC', params: '192' },
  'HQC-256':        { family: 'HQC', params: '256' },
  'HQC':            { family: 'HQC', params: null },
  'BIKE-l1':        { family: 'BIKE', params: 'l1' },
  'BIKE-l3':        { family: 'BIKE', params: 'l3' },
  'BIKE-l5':        { family: 'BIKE', params: 'l5' },
  // Older BIKE spellings: the rule accepts `bike-128/192/256` as well.
  'BIKE-128':       { family: 'BIKE', params: '128' },
  'BIKE-192':       { family: 'BIKE', params: '192' },
  'BIKE-256':       { family: 'BIKE', params: '256' },
  'BIKE':           { family: 'BIKE', params: null },
  'MAYO-1':         { family: 'MAYO', params: '1' },
  'MAYO-2':         { family: 'MAYO', params: '2' },
  'MAYO-3':         { family: 'MAYO', params: '3' },
  'MAYO-5':         { family: 'MAYO', params: '5' },
  'MAYO':           { family: 'MAYO', params: null },
  'NTRU-Prime':     { family: 'NTRU', params: 'prime' },
  // Generic NTRU must exist for NTRU-Prime to absorb a bare `ntru` hit on
  // the same line; without it both components ship (issue #186 follow-up).
  'NTRU':           { family: 'NTRU', params: null },
  'CROSS':          { family: 'CROSS', params: null },
  'UOV':            { family: 'UOV', params: null },
  'SNOVA':          { family: 'SNOVA', params: null },
  'SQIsign':        { family: 'SQIsign', params: null },
  'SDitH':          { family: 'SDitH', params: null },
  'MQOM':           { family: 'MQOM', params: null },
  'QR-UOV':         { family: 'QR-UOV', params: null },
  'Classic-McEliece': { family: 'Classic-McEliece', params: null },
  'FrodoKEM':       { family: 'FrodoKEM', params: null },
};

function lookup(name) {
  return HIERARCHY[name] || null;
}

module.exports = { HIERARCHY, lookup };
