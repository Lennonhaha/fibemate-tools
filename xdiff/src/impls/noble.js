// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('fs');
const path = require('path');
const { ImplUnavailable } = require('../errors');
const U = require('../util');

/**
 * @noble/post-quantum 的 ml_kem768。
 * 是 ESM，只能动态 import。签名与 fibemate 系不同：
 *   keygen()                 → { publicKey, secretKey }
 *   encapsulate(pk)          → { cipherText, sharedSecret }   ← 注意是 cipherText
 *   decapsulate(ct, sk)      → ss                             ← 参数顺序与 fibemate 相反
 */
async function create(spec) {
  const dir = path.resolve(spec.path);
  if (!fs.existsSync(dir)) throw new ImplUnavailable('noble 包目录不存在', { path: spec.path });

  let mod;
  const candidates = ['ml-kem.js', 'index.js'];
  let lastErr = null;
  for (const c of candidates) {
    const p = path.join(dir, c);
    if (!fs.existsSync(p)) continue;
    try { mod = await import('file:///' + p.split(path.sep).join('/')); break; }
    catch (e) { lastErr = e; }
  }
  if (!mod) {
    throw new ImplUnavailable('noble 模块无法 import', { path: spec.path, message: lastErr && lastErr.message });
  }

  const ns = mod.ml_kem768 || (mod.default && mod.default.ml_kem768) || null;
  if (!ns || typeof ns.keygen !== 'function') {
    throw new ImplUnavailable('未找到 ml_kem768 导出', { got: Object.keys(mod).slice(0, 24) });
  }

  return {
    spec,
    kind: 'noble-mlkem',
    keygen() {
      const k = ns.keygen();
      return { pk: U.toBuf(k.publicKey), sk: U.toBuf(k.secretKey) };
    },
    encaps(pk) {
      const e = ns.encapsulate(U.toBuf(pk));
      // 不同版本字段名可能是 cipherText 或 ciphertext
      const ct = e.cipherText !== undefined ? e.cipherText : e.ciphertext;
      return { ct: U.toBuf(ct), ss: U.toBuf(e.sharedSecret) };
    },
    decaps(sk, ct) {
      return U.toBuf(ns.decapsulate(U.toBuf(ct), U.toBuf(sk)));
    },
    /**
     * KAT 对拍用：noble 的 keygen 直接收 64 字节种子 (d‖z)，不走全局 RNG。
     * z 不影响 ek，与 js 系注入 [d, z] 等价。
     */
    derandKeygen(d, z) {
      const seed = Buffer.concat([U.toBuf(d), U.toBuf(z)]);
      const k = ns.keygen(new Uint8Array(seed));
      return { result: { pk: U.toBuf(k.publicKey), sk: U.toBuf(k.secretKey) }, calls: [64] };
    },
    /** KAT 对拍用：noble 的 encapsulate 第二参即 32 字节消息随机数 m。 */
    derandEncaps(ek, m) {
      const e = ns.encapsulate(new Uint8Array(U.toBuf(ek)), new Uint8Array(U.toBuf(m)));
      const ct = e.cipherText !== undefined ? e.cipherText : e.ciphertext;
      return { result: { ct: U.toBuf(ct), ss: U.toBuf(e.sharedSecret) }, calls: [32] };
    }
  };
}

module.exports = { create };
