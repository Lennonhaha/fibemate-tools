// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Reproductions of the two false-positive shapes found on liboqs (1.94 M lines)
// during the 2026-11-21 benchmark. Every line below was copied from that tree,
// and every one of them used to produce a "deprecated algorithm" hit:
//
//   DSA   15/15 hits  -> "ML-DSA"/"SLH-DSA" spellings with a space, plus prose
//   SHA-1  3/3  hits  -> the ARM instruction name in a comment
//
// This file is read as source text by the scanner, never executed.
/* Pair-wise Consistency Test (PCT) for DSA keypairs. */
// Rotate by 1 bit, then XOR: a ^ ROL(b): SHA1 instruction, not support
/* vectors_sig alg_name keyGen seed pk sk ---> ml dsa (argc 6) */

const LOG_OK = 'Copied from slh dsa commit succesfully';
const LOG_FAIL = 'Failed to copy from slh dsa commit, status ';

module.exports = { LOG_OK, LOG_FAIL };
