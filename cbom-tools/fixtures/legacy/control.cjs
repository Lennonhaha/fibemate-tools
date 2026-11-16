// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// Positive control for test/legacy-recall.test.cjs: the same call style with
// algorithms that were already detected before issue #186. If these stop
// being found, the regression is in the scanner, not in the dictionary.
'use strict';

const crypto = require('crypto');
const key = Buffer.alloc(32, 1);
const iv = Buffer.alloc(12, 2);

const sha256 = crypto.createHash('sha256').update('x').digest('hex');
const sha3 = crypto.createHash('sha3-256').update('x').digest('hex');
const sha512 = crypto.createHash('sha512').update('x').digest('hex');
const aesgcm = crypto.createCipheriv('aes-256-gcm', key, iv);

module.exports = { sha256, sha3, sha512, aesgcm };
