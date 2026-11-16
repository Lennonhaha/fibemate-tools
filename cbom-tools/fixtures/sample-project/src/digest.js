// SPDX-License-Identifier: Apache-2.0
//
// Second fixture file: manifest-only and legacy names that must not disappear.

'use strict';

const crypto = require('node:crypto');

function digest(data) {
  return crypto.createHash('sha-256').update(data).digest();
}

function fingerprint(data) {
  return crypto.createHash('sha-512').update(data).digest('hex');
}

function checksum(data) {
  return crypto.createHash('sha3-512').update(data).digest();
}

module.exports = { digest, fingerprint, checksum };
