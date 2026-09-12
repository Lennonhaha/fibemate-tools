// 对照样例：无明显侧信道味道、使用真实 API（用于验证不误报）
const { ml_kem768, sha3_256 } = require('@noble/ciphers');

function derive(seed) {
  return sha3_256(seed);          // 非秘密相关
}

function constantTimeEqual(a, b) {
  // 使用定常比较（WebCrypto timingSafeEqual 或自写 ct-equal）
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]);
  }
  return diff === 0;
}

module.exports = { derive, constantTimeEqual, ml_kem768 };
