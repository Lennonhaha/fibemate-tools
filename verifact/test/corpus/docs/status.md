# 语料：状态页

这一份文档对应 `../artifacts/metrics.json`，每一个数字都能在产出物里找到同名指标。
作用不是"像真文档"，而是**让真实门禁有一条必须保持为绿的基线**：#111 的教训是
门禁从没跑过真实文档，所以解析器坏了也一直是绿的。

| Module | Verification |
|--------|--------------|
| ML-KEM-768 | KAT 10,000/10,000 |

握手延迟 p95=78.5ms，覆盖 coverage: 99.1%。

43/43 cross-validation tests PASS。

原始 signature_bytes 1,024 bytes。
