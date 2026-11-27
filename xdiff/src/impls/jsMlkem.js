// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('fs');
const path = require('path');
const { ImplUnavailable } = require('../errors');
const U = require('../util');

/**
 * fibemate 系纯 JS 实现（fibemate-core / 主仓 packages/pqc-kem）。
 * 签名：generateKeypair() / encapsulate(pk) / decapsulate(sk, ct)
 * 注意 decapsulate 参数顺序是 (secretKey, ciphertext)。
 */
function create(spec) {
  if (!fs.existsSync(spec.path)) {
    throw new ImplUnavailable('实现文件不存在', { id: spec.id, path: spec.path });
  }

  const target = path.resolve(spec.path);
  const root = fs.statSync(target).isDirectory() ? target : path.dirname(target);

  // fibemate-core resolves globalThis.crypto once at module load and keeps the
  // reference. Loading it before a seed shim is installed therefore pins the
  // real RNG, and determinism silently stops being about the implementation.
  // Re-require inside the seeded call, then drop it again so the next call
  // cannot keep a dead shim.
  function freshRequire() {
    for (const k of Object.keys(require.cache)) {
      if (k === target || k.startsWith(root + path.sep)) delete require.cache[k];
    }
    return require(target);
  }
  function dropFresh() {
    for (const k of Object.keys(require.cache)) {
      if (k === target || k.startsWith(root + path.sep)) delete require.cache[k];
    }
  }

  let mod;
  try {
    if (fs.existsSync(spec.path) && fs.statSync(spec.path).isDirectory()) {
      mod = require(path.resolve(spec.path));
    } else {
      mod = require(path.resolve(spec.path));
    }
  } catch (e) {
    throw new ImplUnavailable('模块加载失败', { id: spec.id, path: spec.path, message: e.message });
  }

  const has = (n) => typeof mod[n] === 'function';
  if (!has('generateKeypair') || !has('encapsulate') || !has('decapsulate')) {
    throw new ImplUnavailable('接口不齐（需要 generateKeypair / encapsulate / decapsulate）', {
      id: spec.id,
      got: Object.keys(mod).slice(0, 24)
    });
  }

  return {
    spec,
    kind: 'js-mlkem',
    // 原语若被导出，可被 keySchedule 用例借作参考尺子（主仓版本导出了 sha3_512 等）
    module: mod,
    keygen() {
      const m = freshRequire();
      try {
        const k = m.generateKeypair();
        return { pk: U.toBuf(k.publicKey), sk: U.toBuf(k.secretKey) };
      } finally { dropFresh(); }
    },
    encaps(pk) {
      const m = freshRequire();
      try {
        const e = m.encapsulate(U.toBuf(pk));
        return { ct: U.toBuf(e.ciphertext), ss: U.toBuf(e.sharedSecret) };
      } finally { dropFresh(); }
    },
    decaps(sk, ct) {
      const m = freshRequire();
      try {
        return U.toBuf(m.decapsulate(U.toBuf(sk), U.toBuf(ct)));
      } finally { dropFresh(); }
    },
    /**
     * KAT 对拍用：显式注入 (d, z) 做 keygen。
     * 实现按 [32,32] 两次抽取；z 不影响 ek，只影响 sk 尾部与隐式拒绝。
     */
    derandKeygen(d, z) {
      const { installExplicitRng } = require('../rng');
      const h = installExplicitRng([U.toBuf(d), U.toBuf(z)]);
      try {
        return { result: this.keygen(), calls: h.calls.slice() };
      } finally {
        h.restore();
      }
    },
    /** KAT 对拍用：显式注入 m 做 encaps。 */
    derandEncaps(ek, m) {
      const { installExplicitRng } = require('../rng');
      const h = installExplicitRng([U.toBuf(m)]);
      try {
        return { result: this.encaps(ek), calls: h.calls.slice() };
      } finally {
        h.restore();
      }
    }
  };
}

module.exports = { create };
