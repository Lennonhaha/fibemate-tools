# TODO: verifact 绑定修正

11 条 drift 因「绑定到错误 artifact」被 ignore。修完绑定后移除对应规则。

| 文档 | 当前绑定 | 正确绑定 |
|---|---|---|
| PQC_MIGRATION_PLAN.md (kem-keygen) | pqc-hw-bench/README.md（硬件） | packages/pqc-kem/test/bench/（JS） |
| TECHNICAL-VERIFICATION.md (wns) | pqc-hw-bench/docs/cost-model.md | 时序约束文档自身 |
| TECHNICAL-VERIFICATION.md (keygen-s) | pqc-hw-bench/README.md | JS benchmark 输出 |
| TECHNICAL-VERIFICATION.md (decaps-s) | pqc-hw-bench/README.md | JS benchmark 输出 |
| performance-benchmarks-2026-07-18.md (keygen, keygen-ms) | pqc-hw-bench/README.md | JS benchmark 输出 |

修完绑定后 → 移除 `verifact/verifact.json` 里对应 ignore 规则。