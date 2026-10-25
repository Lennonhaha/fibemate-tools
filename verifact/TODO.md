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
---

## 2026-10-25：绑定修正第一轮（drift 10 → 0，gate PASSED）

- 新增**声明级 `deny`**（保留声明、拒绝自动绑定、note 写理由；与 `ignore` 的区别是不计入 ignored 而是单列 denied）。6 条规则覆盖本轮 8 条 drift，见 `verifact.json` 顶层 `deny`。
- 核心判定：`pqc-hw-bench/README.md#L99` 的 **262µs 是 liboqs 0.16.0 CPU 基线**（gcc 15.2 + AVX2），不是本仓 C addon 的产出物 ⇒ 所有与它绑定的 C addon / JS benchmark 数字一律拒绑，**不改文档**（若按「用 262 覆盖 103」改，会把正确文档改坏）。
- 真滞后 2 条改文档：`fibemate-core/README.md`（654 → 841 行）、`docs/launch-announcement-2026-08-31.md`（WNS 9.869 → +9.733 ns，附 hardware/README.md 出处）。
- 同一处 launch-announcement 的「103µs (15.8× JS)」改为**分环境表**：15.8× 与同段 1.19 ms JS 基线不自洽（1.19 ms ÷ 103 µs = 11.6×），不再跨机拼装比例；103 µs 作为历史值保留在脚注。
- `RELEASE_NOTES.md` 的「OPK 3 invariants」是**文档错**（`docs/tla/OPK.cfg` 自 2026-07-15 首版起即 7 条），已改为 7，并同时拒绑——防止它被 cars-scorecard 里 C2 handshake 的 7 条对上（两个模型不是一回事）。
- `docs.roots` / `artifacts.roots` 改为**相对配置文件解析**（`__baseDir`），不再随 cwd 漂移：旧行为下从 `verifact/` 目录跑会让 root 全部落空 → 0 产出物 → 全 unbound 的假绿。
- 仍未解决：`fibemate/docs/tls-hybrid-deployment.md:3` 引用的 **TSR lg-079 全盘不存在**（编号缺口 079/080），不能补造时间戳；待决定删引用还是补发新 TSR。`ref-missing` 仍为 1。
