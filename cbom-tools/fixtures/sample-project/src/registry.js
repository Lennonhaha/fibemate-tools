// SPDX-License-Identifier: Apache-2.0
//
// Fixture source: the algorithm registry this sample project advertises, read as
// data rather than called. It exists so the sample BOM shows parameterised and
// family-level names side by side.

'use strict';

const SUPPORTED_SUITES = [
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
  'ML-DSA-44',
  'ML-DSA-65',
  'ML-DSA-87',
  'SLH-DSA',
  'X25519',
  'Ed25519',
];

const LEGACY_SUITES = ['ECDH', 'RSA'];

const HASHES = ['SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'keccak256'];

const CN_SUITES = ['SM2', 'SM3', 'SM4'];

module.exports = { SUPPORTED_SUITES, LEGACY_SUITES, HASHES, CN_SUITES };
