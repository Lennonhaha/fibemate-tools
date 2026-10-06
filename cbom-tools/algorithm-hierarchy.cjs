// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// algorithm-hierarchy.cjs — algorithm family / parameter-set lookup.
// Used by cbom-scan.cjs for provenance dedup and confidence scoring.

const HIERARCHY = {
  'ML-DSA-44':  { family: 'ML-DSA', params: '44' },
  'ML-DSA-65':  { family: 'ML-DSA', params: '65' },
  'ML-DSA-87':  { family: 'ML-DSA', params: '87' },
  'ML-DSA':     { family: 'ML-DSA', params: null },
  'ML-KEM-512':  { family: 'ML-KEM', params: '512' },
  'ML-KEM-768':  { family: 'ML-KEM', params: '768' },
  'ML-KEM-1024': { family: 'ML-KEM', params: '1024' },
  'ML-KEM':      { family: 'ML-KEM', params: null },
  'Keccak-224':  { family: 'Keccak', params: '224' },
  'Keccak-256':  { family: 'Keccak', params: '256' },
  'Keccak-384':  { family: 'Keccak', params: '384' },
  'Keccak-512':  { family: 'Keccak', params: '512' },
  'Keccak':      { family: 'Keccak', params: null },
  'SLH-DSA':     { family: 'SLH-DSA', params: null },
};

function lookup(name) {
  return HIERARCHY[name] || null;
}

module.exports = { HIERARCHY, lookup };