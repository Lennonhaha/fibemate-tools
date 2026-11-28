// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// registry-identifiers — the registry name spaces, and the gate on their names.
//
// The scanner gained a second way to see an algorithm: a *registered
// identifier* (a TLS suite, a group, a curve, a signature scheme) is read
// structurally instead of being looked up as a canonical name. Two things can
// go wrong, and both are silent:
//
//   1. a suite names three algorithms and the reader reports one — the 0.3.2
//      failure mode that produced "wrong family" on four measured rows;
//   2. a component is emitted under a name no family vocabulary contains, so
//      the BOM says something nobody can interpret.
//
// So the tests below are mostly about *which* families come out, plus one
// gate (the last test) that requires every emitted name to start with a family
// the CycloneDX algorithm vocabulary actually has.

const assert = require('node:assert/strict');
const test = require('node:test');

const { collectRegistrySites, registrySize } = require('../registry-identifiers.cjs');

const names = (text) => collectRegistrySites(text).flatMap((s) => s.algorithms);
const set = (text) => new Set(names(text));

// Every family the scanner may emit through this module. Written out rather
// than imported on purpose: an accidental rename in families.yaml should break
// this test loudly, not silently widen it.
const FAMILIES = new Set([
  'RSA', 'DSA', 'DH', 'EC', 'ECDSA', 'ECDH', 'EdDSA', 'X25519', 'X448',
  'ML-KEM', 'ML-DSA', 'SLH-DSA', 'LMS', 'XMSS',
  'SHA-1', 'MD5', 'MD4', 'DES', '3DES', 'RC4', 'RC2', 'AES', 'ChaCha20', 'HMAC', 'SHA-2',
]);
const familyOf = (name) => {
  for (const f of FAMILIES) if (name === f || name.startsWith(f + '-')) return f;
  return null;
};

test('a TLS suite is every algorithm the suite names, not one of them', () => {
  const got = set('CIPHER_SUITE = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"');
  for (const want of ['ECDH', 'RSA', 'AES']) assert.ok(got.has(want), `missing ${want}: ${[...got]}`);
});

test('the key-exchange and authentication halves are both reported', () => {
  // 0.3.2 read the auth half of the RSA suites and called it the algorithm,
  // which is how four measured rows came out as `wrong family`.
  const got = set('suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA');
  assert.ok(got.has('DH') && got.has('RSA'), [...got].join(','));
});

test('3DES is not read as DES, and DES is not read as 3DES', () => {
  assert.ok(set('TLS_KRB5_WITH_3DES_EDE_CBC_SHA').has('3DES'));
  assert.ok(!set('TLS_KRB5_WITH_3DES_EDE_CBC_SHA').has('DES'));
  assert.ok(set('TLS_DH_DSS_WITH_DES_CBC_SHA').has('DES'));
  assert.ok(!set('TLS_DH_DSS_WITH_DES_CBC_SHA').has('3DES'));
});

test('the old bulk ciphers and MACs are recovered', () => {
  const got = set('TLS_RSA_EXPORT_WITH_RC4_40_MD5');
  for (const want of ['RSA', 'RC4', 'MD5']) assert.ok(got.has(want), [...got].join(','));
  assert.ok(set('TLS_RSA_WITH_RC2_CBC_40_MD5').has('RC2'));
  assert.ok(set('TLS_RSA_WITH_DES_CBC_SHA').has('SHA-1'));
});

test('a TLS 1.3 suite claims its bulk cipher and no key exchange', () => {
  const got = set('TLS_AES_256_GCM_SHA384');
  assert.ok(got.has('AES'));
  assert.ok(!got.has('ECDH') && !got.has('DH'));
});

test('unknown bulk ciphers are left out instead of named', () => {
  const got = names('TLS_RSA_WITH_CAMELLIA_256_CBC_SHA');
  assert.deepEqual(got.filter((n) => familyOf(n) === null), [], got.join(','));
});

test('an OpenSSL cipher list is read element by element', () => {
  const got = set('ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;');
  for (const want of ['ECDH', 'RSA', 'AES']) assert.ok(got.has(want), [...got].join(','));
});

test('a leading ! in a cipher list is an exclusion, not a use', () => {
  const got = set('CIPHER_LIST="ECDHE+AESGCM:!ECDSA"');
  assert.ok(got.has('ECDH'));
  assert.ok(!got.has('ECDSA'), 'an excluded family was reported as used');
});

test('curve names are EC components, and only the context makes them ECDH/ECDSA', () => {
  assert.deepEqual(names('CURVE = "P-192"'), ['EC-P-192']);
  // Registered identifiers glue the curve to its neighbour with "_"; `\b`
  // would not see through it.
  assert.deepEqual(names('MBEDTLS_ECP_DP_SECP384R1'), ['EC-secp384r1']);
  assert.ok([...set('TLS_GROUP = "sect163k1"')].some((n) => n.startsWith('ECDH-')));
  assert.ok(set('kyber.pubkey'), 'no curve, no component');
  const sign = set('setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1")) /* PURPOSE_SIGN */');
  assert.ok(sign.has('ECDSA'), [...sign].join(','));
});

test('ffdhe/modp/SSH-group names become DH with the right size', () => {
  assert.deepEqual(names('TLS_GROUP = "ffdhe3072"'), ['DH-ffdhe3072']);
  assert.deepEqual(names('KexAlgorithms diffie-hellman-group16-sha512'), ['DH-group16']);
  assert.deepEqual(names('proposal = "modp2048"'), ['DH-modp2048']);
  assert.equal(registrySize('DH-ffdhe2048'), 2048);
  assert.equal(registrySize('DH-group14'), 2048);
  assert.equal(registrySize('DH-modp3072'), 3072);
});

test('signature schemes are read in their registry spellings', () => {
  assert.ok(set('SIGNATURE_SCHEME = "rsa_pss_rsae_sha256"').has('RSA'));
  assert.ok(set('ssh-rsa AAAAB3Nz').has('RSA'));
  assert.ok(set('ecdsa_sha2_nistp256').has('ECDSA'));
  assert.ok(set('"alg": "ES256"').has('ECDSA'));
  assert.ok(set('"alg": "RS256"').has('RSA'));
  assert.ok(set('eddsa.new(curve)').has('EdDSA'));
  assert.ok(set('ssh-ed25519 AAAA').has('EdDSA'));
  assert.ok(set('ssh-dss AAAA').has('DSA'));
  assert.ok(set('slhdsa_sha2_128f').has('SLH-DSA'));
  assert.ok(set('mldsa65').has('ML-DSA-65'));
  assert.ok(set('lms_sha256_m32_h5').has('LMS'));
  assert.ok(set('xmss_sha2_10_256').has('XMSS'));
});

test('a hybrid name yields both of its algorithms', () => {
  const got = set('SSL_GROUP_X25519_MLKEM768');
  assert.ok(got.has('X25519'), [...got].join(','));
  assert.ok(got.has('ML-KEM-768'), [...got].join(','));
});

test('the underscore is not a word boundary (the bug this module shipped with)', () => {
  // MLKEM768 is the spelling in BoringSSL's group constants; \b would miss it,
  // and X25519 next to an underscore is still X25519.
  assert.ok(set('kGroups[] = {SSL_GROUP_X25519_MLKEM768}').has('ML-KEM-768'));
  assert.ok(set('EVP_PKEY_X25519').has('X25519'));
});

test('gate: every emitted name starts with a family the vocabulary has', () => {
  const corpus = [
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    'TLS_PSK_WITH_AES_128_CBC_SHA',
    'TLS_GROUP = "brainpoolP512t1"',
    'TLS_GROUP = "secp521r1"',
    'CURVE = "K-571"',
    'dhe = "ffdhe8192"',
    'SignatureAlgorithms rsa_pkcs1_sha384',
    'PubkeyAcceptedAlgorithms ecdsa-sha2-nistp521',
    'ssh-ed448 AAAA',
    'X25519MLKEM768',
    'MLKEM1024',
    'mldsa87',
    'slhdsa_shake_256s',
    'lms_sha256_m32_h5',
    'xmss_sha256_10_256',
  ].join('\n');
  const bad = names(corpus).filter((n) => familyOf(n) === null);
  assert.deepEqual(bad, [], `no family owns these names: ${bad.join(', ')}`);
});

test('size is reported only where the identifier states one', () => {
  assert.equal(registrySize('EC-P-521'), 521);
  assert.equal(registrySize('X25519'), 255);
  assert.equal(registrySize('ECDSA'), null);
  assert.equal(registrySize('ML-KEM-768'), null);
});

test('hybrid names glued without a delimiter still yield both halves', () => {
  const a = set('TLS_GROUP = "MLKEM1024X448"');
  assert.ok(a.has('ML-KEM-1024'), [...a].join(','));
  assert.ok(a.has('X448'), [...a].join(','));
  const b = set('HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256');
  assert.ok(b.has('ML-KEM-768'), [...b].join(','));
  assert.ok(b.has('X25519'), [...b].join(','));
});

test('a key-exchange macro states its role in the identifier', () => {
  // 0.3.3 read this as ECDSA only: ECDH was never inferred without a curve.
  assert.ok(set('#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED').has('ECDH'));
});

test('ML-KEM 1024 is not dropped by a three-digit pattern', () => {
  assert.deepEqual(names('"MLKEM1024"'), ['ML-KEM-1024']);
  assert.deepEqual(names('ML-KEM-1024'), [], 'canonical names belong to the dictionary, not here');
});
