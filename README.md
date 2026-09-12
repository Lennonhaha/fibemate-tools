# FIBEMATE Tools

FIBEMATE 的独立工具集（与 `fibemate` 主仓分离，独立 license）。

> 本仓承载**辅助工具**（静态分析 / 历史追踪 / 证明骨架），**不实现任何密码学算法**——
> 仅做可复现验证、代码质量信号、证据生成。符合"不拿推测当事实"的纪律。

## 工具清单

| 工具 | 语言 | 作用 | 状态 |
|---|---|---|---|
| `hallucination-detector` | Node (零依赖) | 检测 AI 生成的密码代码中的幻觉/侧信道不安全模式 | 可跑，样本 PASS，误报已修 (A+B) |
| `crypto-time-machine` | Python (仅标准库) | 把密码学 API 的引入/变更变成可查询 git 时间轴 | 可跑，真实历史测试 PASS |
| `undecryptable-prover` | Rust + Lean4 | 多轮覆写销毁 + 证据链 + Lean 证明骨架 | 可跑，`cargo build` + `run` PASS |

## 设计纪律（全部工具共守）

- **信号 vs 判决分离**：输出 `needs-human-review` / 证据链，**绝不自我认证或宣判漏洞**。
- **零依赖优先**：检测器零依赖；时间机器仅标准库；证明器仅 `zeroize`。
- **可复现验证**：所有结论基于真实 git 历史 / 真实编译产物，不凭记忆。
- **诚实标注**：Lean 模板明确"骨架非完整证明"；证明器明确"evidence only"。

## 仓库结构

```
fibemate-tools/
├── README.md
├── LICENSE                  (Apache-2.0)
├── .github/
│   ├── workflows/           (detector-ci / time-machine-ci / prover-ci)
│   └── dependabot.yml
├── hallucination-detector/  (Node)
├── crypto-time-machine/     (Python)
└── undecryptable-prover/    (Rust + Lean)
```

## 快速试用

```bash
# 检测器
cd hallucination-detector
node test/sample.test.js          # 自带样本测试
node src/cli.js your-file.js      # 分析你的代码

# 时间机器（REPO 环境变量指向任意 git 仓，默认 D:\FIBEMATE\fibemate）
cd crypto-time-machine
REPO=/path/to/repo python test/local_test.py

# 证明器
cd undecryptable-prover
cargo run --release               # 生成 evidence.json
```

## License

Apache-2.0。详见 [LICENSE](./LICENSE)。

> 注：本仓独立于 `fibemate` 主仓（GPL-3.0）。工具不进入主仓即不继承其传染性许可。
