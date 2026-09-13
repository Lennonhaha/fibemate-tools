// 类 9 对照样例：文件名含 ml-kem-768，常量正确（用于验证 domain-params 不误报）
// 与 NIST FIPS 203 ML-KEM-768 一致：q=3329 n=256 k=3。

function buildKem() {
  const q = 3329;
  const n = 256;
  const k = 3;
  return { q, n, k };
}

module.exports = { buildKem };
