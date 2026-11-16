// SPDX-License-Identifier: Apache-2.0
//
// Fixture source for cbom-tools/cbom-cyclonedx.json. It exists to exercise the
// scanner, not to run: a hybrid handshake that uses one algorithm per evidence
// shape (parameter set, family-level, merges with the manifest).

'use strict';

const { ml_kem768 } = require('@noble/post-quantum/ml-kem');
const { ml_dsa_65 } = require('@noble/post-quantum/ml-dsa');
const crypto = require('node:crypto');

// Key-agreement identifier, read as data by the TLS layer under test.
const KEY_AGREEMENT = 'ecdh';

function establish(peerPublicKey) {
  const { publicKey, secretKey } = ml_kem768.keygen();
  const shared = ml_kem768.encapsulate(peerPublicKey);
  const session = crypto.createHash('sha3-256').update(shared).digest();
  return { publicKey, secretKey, session };
}

function sign(payload, secretKey) {
  return ml_dsa_65.sign(payload, secretKey);
}

function encrypt(session, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', session, iv);
  return { iv, ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]) };
}

function derive(ecdhKey, peerKey) {
  return ecdhKey.computeSecret(peerKey);
}

module.exports = { establish, sign, encrypt, derive, KEY_AGREEMENT };
