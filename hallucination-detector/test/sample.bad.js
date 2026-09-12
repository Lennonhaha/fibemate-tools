// 真实 AI 幻觉案例合集（用于验证检测器命中，非生产代码）
// @secret sk  注意：sk 是秘密

// 1) 编造的伪 API：noble.kem（真实应为 @noble/ciphers 的 ml_kem768）
const { cipher } = noble.kem.mlkem.encaps(sk);

// 2) 秘密相关分支（潜在时序侧信道）
function verifyTag(tag, expected) {
  if (tag === expected) {        // 早返回：可区分成功/失败
    return true;
  }
  return false;
}

// 3) 数组下标使用秘密（潜在缓存时序）
function lookup(table, sk) {
  return table[sk & 0xff];        // sk 做索引
}

// 4) 声明定常但实现有秘密分支（声明与实现矛盾）
// This function is constant-time and side-channel safe.
function scalarMul(point, sk) {
  let r = point;
  for (let i = 0; i < 256; i++) {
    if (sk & 1) {                 // 秘密相关分支 — 与上方声明矛盾
      r = add(r, point);
    }
    sk >>= 1;
  }
  return r;
}

// 5) 对秘密的非定常比较
function eq(a, b) {
  return a !== b;                  // 可能非定常
}
