// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * 确定性随机源注入。
 *
 * 已实测：fibemate-core、主仓 packages/pqc-kem、@noble/post-quantum 三方
 * 都通过 globalThis.crypto.getRandomValues 取随机数（noble 经 @noble/hashes/utils
 * 转发到同一个入口）。因此替换这一个点，就能让三方的 keygen / encaps 变成
 * 可复现的确定性过程，从而做逐字节差分。
 *
 * DRBG 用 SHA3-256 的 CTR 模式，不追求密码学强度，只要求：
 *   - 同一种子必定产生同一字节流
 *   - 不同种子产生无关字节流
 */

const nodeCrypto = require('crypto');

/** SHA3-256(seed || counter_be32) —— 每块 32 字节。 */
function drbgBlock(seed, counter) {
  const h = nodeCrypto.createHash('sha3-256');
  const c = Buffer.alloc(4);
  c.writeUInt32BE(counter >>> 0, 0);
  h.update(seed);
  h.update(c);
  return h.digest();
}

class Drbg {
  constructor(seedBytes, label) {
    // label 参与派生，让 keygen 与 encaps 用同一个主种子也不会共用同一段流
    const h = nodeCrypto.createHash('sha3-256');
    h.update(Buffer.from(label || '', 'utf8'));
    h.update(Buffer.from(seedBytes));
    this.seed = h.digest();
    this.counter = 0;
    this.buf = Buffer.alloc(0);
    this.off = 0;
    this.calls = [];   // RNG 调用序列，即该实现的随机消耗指纹
  }

  _next(n) {
    const out = Buffer.alloc(n);
    let filled = 0;
    while (filled < n) {
      if (this.off >= this.buf.length) {
        this.buf = drbgBlock(this.seed, this.counter++);
        this.off = 0;
      }
      const take = Math.min(n - filled, this.buf.length - this.off);
      this.buf.copy(out, filled, this.off, this.off + take);
      this.off += take;
      filled += take;
    }
    return out;
  }

  fill(view) {
    const n = view.length;
    this.calls.push(n);
    const b = this._next(n);
    // 兼容 Uint8Array / Buffer / DataView 之外的一切 TypedArray
    if (view instanceof Buffer) b.copy(view);
    else view.set(b);
    return view;
  }
}

/**
 * 安装 RNG shim。
 * @param {object} o
 * @param {Buffer} o.seed  主种子
 * @param {string} o.label 用途标签
 * @returns {{restore: Function, drbg: Drbg}}
 */
function installRng({ seed, label }) {
  const drbg = new Drbg(seed, label);
  const g = globalThis;
  const prevDesc = Object.getOwnPropertyDescriptor(g, 'crypto');
  const prev = g.crypto;

  const shim = Object.create(null);
  // 保留原 crypto 上除 getRandomValues 之外的能力（subtle 等实现内部可能用到）
  if (prev) {
    let proto = prev;
    while (proto) {
      for (const k of Object.getOwnPropertyNames(proto)) {
        if (k === 'getRandomValues' || k === 'constructor') continue;
        try { shim[k] = typeof prev[k] === 'function' ? prev[k].bind(prev) : prev[k]; } catch (_) { /* noop */ }
      }
      proto = Object.getPrototypeOf(proto);
    }
  }
  shim.getRandomValues = (view) => drbg.fill(view);
  if (!shim.randomUUID) shim.randomUUID = () => '00000000-0000-4000-8000-000000000000';

  Object.defineProperty(g, 'crypto', { value: shim, configurable: true, writable: true });

  return {
    drbg,
    restore() {
      if (prevDesc) Object.defineProperty(g, 'crypto', prevDesc);
      else delete g.crypto;
    }
  };
}

/** 主种子派生：master + caseIndex + purpose → 子种子。 */
function subSeed(master, caseIndex, purpose) {
  const h = nodeCrypto.createHash('sha3-256');
  h.update(Buffer.from('xdiff/subseed/1', 'utf8'));
  h.update(Buffer.from(master));
  const idx = Buffer.alloc(4);
  idx.writeUInt32BE(caseIndex >>> 0, 0);
  h.update(idx);
  h.update(Buffer.from(String(purpose || ''), 'utf8'));
  return h.digest();
}

/**
 * 显式字节注入：按顺序向实现提供精确的随机字节（用于 KAT 对拍）。
 * 实现每次调用 getRandomValues 时，取队列中的下一份；长度不符或取空即抛错——
 * 宁可报错也不静默错位。
 */
function installExplicitRng(buffers) {
  const queue = buffers.map((b) => Buffer.from(b));
  const calls = [];
  const g = globalThis;
  const prevDesc = Object.getOwnPropertyDescriptor(g, 'crypto');
  const prev = g.crypto;

  const shim = Object.create(null);
  if (prev) {
    let proto = prev;
    while (proto) {
      for (const k of Object.getOwnPropertyNames(proto)) {
        if (k === 'getRandomValues' || k === 'constructor') continue;
        try { shim[k] = typeof prev[k] === 'function' ? prev[k].bind(prev) : prev[k]; } catch (_) { /* noop */ }
      }
      proto = Object.getPrototypeOf(proto);
    }
  }
  shim.getRandomValues = (view) => {
    calls.push(view.length);
    if (!queue.length) throw new Error('explicit-rng: 实现的随机抽取次数超出提供的字节份数（' + calls.length + ' 次）');
    const next = queue.shift();
    if (next.length !== view.length) {
      throw new Error('explicit-rng: 长度不符，实现要 ' + view.length + ' 字节，队列里是 ' + next.length + ' 字节');
    }
    if (view instanceof Buffer) next.copy(view);
    else view.set(next);
    return view;
  };
  if (!shim.randomUUID) shim.randomUUID = () => '00000000-0000-4000-8000-000000000000';

  Object.defineProperty(g, 'crypto', { value: shim, configurable: true, writable: true });

  return {
    calls,
    leftover: () => queue.length,
    restore() {
      if (prevDesc) Object.defineProperty(g, 'crypto', prevDesc);
      else delete g.crypto;
    }
  };
}

module.exports = { Drbg, installRng, installExplicitRng, subSeed, drbgBlock };
