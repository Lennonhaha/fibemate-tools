'use strict';
// 对照样例：一组「看起来很像真的、实际不存在」的调用。
// 用途：真阳性测试——每一条都必须被 api-misuse 标出来。
// 这些名字是编造的，但形态与 AI 生成的密码学代码高度相似。
const noble = require('@noble/ciphers');
const box = require('tweetnacl');

async function fabricated() {
  const pair = noble.mlkem.generateKeyPair();              // 真实为 ml_kem768.keygen()
  const shared = await crypto.subtle.mlkemEncapsulate(pair.publicKey); // WebCrypto 无此 API
  const hash = noble.sha3(Buffer.from('x'));               // 真实为 noble-hashes 的 sha3_256
  const opened = box.secretbox.open(new Uint8Array(1), new Uint8Array(1), new Uint8Array(1));
  return { pair, shared, hash, opened };
}

module.exports = { fabricated };
