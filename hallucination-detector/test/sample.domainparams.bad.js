// 类 9 命中样例：文件名含 ml-kem-768，但常量错误（用于验证 domain-params 命中，非生产代码）
// 真实 ML-KEM-768 应为 q=3329 n=256 k=3；此处故意写错以触发 suspect。

function buildKem() {
  const q = 3330;   // 应为 3329
  const n = 256;
  const k = 4;      // 应为 3
  return { q, n, k };
}

module.exports = { buildKem };
