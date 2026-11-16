// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Fixture for test/legacy-recall.test.cjs.
// Twelve algorithms an audit must never miss. Deliberately ASCII-only and
// syntactically plausible, so the file reads like real code to the scanner.
'use strict';

const crypto = require('crypto');
const key = Buffer.alloc(32, 1);
const iv = Buffer.alloc(16, 2);

const md5 = crypto.createHash('md5').update('x').digest('hex');
const sha1 = crypto.createHash('sha1').update('x').digest('hex');
const blake2b = crypto.createHash('blake2b512').update('x').digest('hex');
const des3 = crypto.createCipheriv('des-ede3-cbc', key.subarray(0, 24), iv);
const blowfish = crypto.createCipheriv('bf-cbc', key.subarray(0, 16), iv);
const camellia = crypto.createCipheriv('camellia-256-cbc', key, iv);
const aria = crypto.createCipheriv('aria-256-gcm', key, iv);
const poly1305 = crypto.createHmac('poly1305', key).update('x').digest('hex');
const ed448 = crypto.generateKeyPairSync('ed448');
const x448 = crypto.generateKeyPairSync('x448');
const dsa = crypto.generateKeyPairSync('dsa');
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

module.exports = {
  md5, sha1, blake2b, des3, blowfish, camellia,
  aria, poly1305, ed448, x448, dsa, rsa,
};
