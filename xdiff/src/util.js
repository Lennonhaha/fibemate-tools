// SPDX-License-Identifier: Apache-2.0
'use strict';

const nodeCrypto = require('crypto');

function toBuf(x) {
  if (x == null) return null;
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x.buffer, x.byteOffset, x.byteLength);
  if (Array.isArray(x)) return Buffer.from(x);
  throw new TypeError('无法转换为 Buffer: ' + Object.prototype.toString.call(x));
}

function toHex(b) {
  return toBuf(b).toString('hex');
}

function fromHex(h) {
  return Buffer.from(String(h), 'hex');
}

/**
 * 只看前缀，避免报告里塞满 1088 字节的十六进制。
 * 入参既可能是 Buffer 也可能是已经是 hex 的字符串，两者都要接受。
 */
function shortHex(b, n) {
  if (b == null) return 'null';
  const h = (Buffer.isBuffer(b) || b instanceof Uint8Array) ? toHex(b) : String(b);
  const k = n || 16;
  return h.length <= k * 2 ? h : h.slice(0, k) + '…';
}

function sha3_256(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(toBuf(p));
  return h.digest();
}

function sha3_512(...parts) {
  const h = nodeCrypto.createHash('sha3-512');
  for (const p of parts) h.update(toBuf(p));
  return h.digest();
}

/** FIPS 203 的最终共享密钥：K = SHA3-256(K̄ ‖ H(ct)) */
function finalK(kbar, ct) {
  return sha3_256(toBuf(kbar), sha3_256(toBuf(ct)));
}

function equalBytes(a, b) {
  const x = toBuf(a);
  const y = toBuf(b);
  if (!x || !y || x.length !== y.length) return false;
  return nodeCrypto.timingSafeEqual(x, y);
}

/** 翻转第 bitIdx 位（按字节序），用于失败性解密测试。 */
function flipBit(buf, bitIdx) {
  const out = toBuf(buf);
  const b = Buffer.from(out);
  const byte = Math.floor(bitIdx / 8) % b.length;
  b[byte] ^= 1 << (bitIdx % 8);
  return b;
}

function nowMs() {
  const t = process.hrtime.bigint();
  return Number(t) / 1e6;
}

module.exports = { toBuf, toHex, fromHex, shortHex, sha3_256, sha3_512, finalK, equalBytes, flipBit, nowMs };
