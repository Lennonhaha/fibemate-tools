'use strict';
// 对照样例：真实 API、定长比较、无秘密相关分支。
// 用途：假阳性测试——检测器在这里报任何东西都是误报。
const { randomBytes, timingSafeEqual, createCipheriv } = require('node:crypto');
const { ml_kem768, x25519 } = require('@noble/ciphers');
const { sha3_256 } = require('@noble/hashes/sha3');

function digest(bytes) {
  return sha3_256(bytes);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function hybridHandshake() {
  const kem = ml_kem768.keygen();
  const curve = x25519.keygen();
  const nonce = randomBytes(12);
  const key = digest(Buffer.concat([kem.publicKey, curve.publicKey]));
  const cipher = createCipheriv('aes-256-gcm', key.slice(0, 32), nonce);
  return { cipher, kem, curve, nonce };
}

module.exports = { digest, constantTimeEqual, hybridHandshake };
