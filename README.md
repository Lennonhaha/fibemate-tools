# FIBEMATE Tools

FIBEMATE 的独立工具集（与 `fibemate` 主仓分离，独立 license）。

> 本仓承载**辅助工具**（静态分析 / 历史追踪 / 证明骨架 / 互操作差分），**不实现任何密码学算法**——
> 仅做可复现验证、代码质量信号、证据生成。符合"不拿推测当事实"的纪律。

> **设计原则**：见 [fibemate/PRINCIPLES.md](https://github.com/LennonHaha/fibemate/blob/main/PRINCIPLES.md)

**状态**：`verifact` 已发布 npm `0.2.5`（`npx verifact`）· CycloneDX 3 个待审 PR（`specification` #1176 #1177 · `tool-center` #170 已合并）

> **数字纪律**：本 README 里每个计数都由 `node scripts/check-docs-sync.cjs` 复跑工具测试得出，CI 上对不上即红。
> 跨仓数字（文档份数 / 声明条数 / verified / drift）只有本机存在 `../fibemate` 时才校验，否则打印 `SKIP`——
> `SKIP` 不计为通过。

## 工具清单（10 个）

| 工具 | 语言 | 作用 | 状态 |
|---|---|---|---|
| `hallucination-detector` | Node (零依赖) | 检测 AI 生成的密码代码中的幻觉/侧信道不安全模式 | 可跑，12 项样本 PASS（含域参数 / 测试覆盖回归） |
| `crypto-time-machine` | Python (仅标准库) | 把密码学 API 的引入/变更变成可查询 git 时间轴 | 可跑，10 项 PASS（真实主仓历史） |
| `undecryptable-prover` | Rust + Lean4 | 多轮覆写销毁 + 证据链 + Lean 证明骨架 | 可跑，12 项测试 PASS（`cargo test --release`）；Lean 主定理 0 `sorry`、1 条显式 axiom，`#print axioms` 可审计 |
| `crypto-time-ledger` | TypeScript (pkijs) | RFC 3161 锚定的密码算法状态账本（add/verify/query/export CLI） | 可跑，78 项测试 + `tsc --noEmit` PASS |
| `tla-verifier` | Bash + TLA+ TLC | 钉版 TLC 持续验证主仓 C-2 模型 7 条不变式（nightly） | 可跑，实测 exit 0 / 26,115 distinct states |
| `verifact` | Node (零依赖) | 事实哨兵：把文档里的硬数字声明绑定到产出物上逐条核验，漂移即红 + 本地看板 | 可跑，86 项回归 PASS；npm 已发布 `verifact@0.2.5`；主仓 260 份文档 / 1421 条声明 / verified 107 · drift 0（2026-11-23 实测；比对集不含 audit-log / www 镜像 / 安全评估快照 / p0_evidence 等记录类文档） |
| `xdiff` | Node (零依赖) + C 桥接 | 差分哨兵：多套 ML-KEM-768 实现同种子逐字节差分、互操作矩阵、密钥派生根因定位 | 可跑，20 项回归 PASS；实测抓到 fibemate-core 漏拼域分隔符 k（2026-09-25 同结论） |
| `cbom-tools` | Node (零依赖) | CBOM 生成 / 差分 / 合规视图（scan / diff / compliance 三个 CLI 入口） | 可跑，195 项测试（194 pass / 1 skip）；npm 已发布 `cbom-tools@0.3.2` |
| `falcon` | Node (零依赖) | FALCON 资产扫描 + 断言检查，两个模式串在一个退出码后 | 可跑，12 项测试 PASS |
| `interop-matrix` | Node | 多实现对拍矩阵：同一组向量跑 pqc-kem / noble，四种失败方式全覆盖 | 可跑，62/62 checks PASS（harness 自测 12 项） |

## 设计纪律（全部工具共守）

- **信号 vs 判决分离**：输出 `needs-human-review` / 证据链，**绝不自我认证或宣判漏洞**。
- **零依赖优先**：检测器零依赖；时间机器仅标准库；证明器仅 `zeroize`。
- **可复现验证**：所有结论基于真实 git 历史 / 真实编译产物，不凭记忆。
- **诚实标注**：Lean 主定理**不含 `sorry`**，唯一未证明处是显式 `axiom overwrite_erases`（每次编译由 `#print axioms` 打印）；证明器只输出证据链，不宣称密码学保证。
- **数字由脚本产生**：README 的计数不接受手写，`scripts/check-docs-sync.cjs` 复跑测试并逐项比对，不一致即红。

## 仓库结构

```
fibemate-tools/
├── README.md
├── LICENSE                  (Apache-2.0)
├── .github/
│   ├── workflows/           (detector-ci / time-machine-ci / prover-ci / ledger-ci / codeql / docs-sync)
│   └── dependabot.yml
├── scripts/
│   ├── check-docs-sync.cjs  (README 数字 ↔ 实测 的门禁)
│   └── …                    (create-pr / merge-pr / server-sync / release-audit)
├── hallucination-detector/  (Node)
├── crypto-time-machine/     (Python)
├── crypto-time-ledger/      (TypeScript)
├── tla-verifier/            (Bash + TLA+ TLC)
├── verifact/                (Node，零依赖)
├── xdiff/                   (Node，零依赖 + C 桥接)
├── cbom-tools/              (Node，零依赖，0.3.2)
├── falcon/                  (Node，零依赖)
├── interop-matrix/          (Node，对拍矩阵)
└── undecryptable-prover/    (Rust + Lean)
```

## 快速试用

```bash
# 检测器
cd hallucination-detector
node test/sample.test.js          # 自带样本测试（12 项）
node src/cli.js your-file.js      # 分析你的代码

# 时间机器（CTM_TEST_REPO 环境变量指向任意 git 仓，默认分析当前目录）
cd crypto-time-machine
CTM_TEST_REPO=/path/to/repo python test/local_test.py

# 证明器
cd undecryptable-prover
cargo run --release                 # 生成 evidence.json（默认 32 字节 × 3 轮）
cargo run --release -- --len 32 --rounds 3   # 显式指定；末轮 zeroize
cargo test --release                # 12 项测试（release 才有 DCE，debug 绿不算数）

# 事实哨兵（verifact）：核验文档硬数字与产出物是否一致
npx verifact verify                            # 经 npm 直接运行，无需 clone
cd verifact
node bin/verifact.js verify                    # 按 verifact.json 跑，drift 时退出码 1
node bin/verifact.js verify --format md --out report.md
node bin/verifact.js diff                      # 对比两次运行之间的状态迁移
node bin/verifact.js serve                     # 本地看板 http://127.0.0.1:8787

# 差分哨兵（xdiff）：多套实现同种子逐字节差分
cd xdiff
node bin/xdiff.js list                         # 列出实现及其可用性
node bin/xdiff.js run                          # 互操作矩阵 + 密钥派生根因定位
node bin/xdiff.js run --format md --out r.md
node test/run.js                               # 20 项回归

# CBOM 工具（scan / diff / compliance）
cd cbom-tools
node bin/cbom-scan.cjs <path> --format cyclonedx   # 生成 CBOM
node bin/cbom-diff.cjs a.json b.json               # 两份 CBOM 的差异
node bin/cbom-compliance.cjs report.json --redact   # 合规视图（可脱敏后离机）
npm test                                           # 195 项测试

# FALCON 资产扫描 + 断言检查
cd falcon
node test/falcon-gate.test.cjs

# 对拍矩阵
cd interop-matrix
node selftest.cjs --pqc-kem /path/to/fibemate/packages/pqc-kem \
  --noble /path/to/fibemate/node_modules/@noble/post-quantum
node run.cjs --pqc-kem … --noble …

# README 数字门禁（本仓自检）
node scripts/check-docs-sync.cjs
node scripts/check-docs-sync.cjs --selftest   # 证明这个门禁会红
```

## Scripts

本仓自带的运维脚本（Apache-2.0，零依赖）。它们绕过 `gh` CLI 在 Windows 上的已知 bug（`gh pr create` / `gh pr merge` 调不到 `git merge` 子命令），并封装「服务器锁目录 → pull → 重锁」的部署 SOP。

| 脚本 | 作用 | 何时用 |
|---|---|---|
| `scripts/check-docs-sync.cjs` | 复跑工具测试，逐项比对 README 的计数；不一致退出 1 | CI / 改 README 后 |
| `scripts/create-pr.js` | 通过 GitHub REST API 开 PR（绕 `gh` Windows bug） | `gh pr create` 在 Windows 失败 |
| `scripts/merge-pr.js`  | 通过 GitHub REST API squash / merge / rebase 合并 PR | `gh pr merge` 在 Windows 失败 |
| `scripts/server-sync.sh` | `chattr -i` → `git pull --ff-only` → `chattr +i` 同步 SOP | 部署到带锁工作树的服务器 |

**令牌纪律**：三个 GitHub 脚本都从环境变量 `$GITHUB_TOKEN`（或 `$GH_TOKEN`）读令牌。**绝不硬编码令牌，绝不提交令牌。**

**示例**：

```bash
# 开 PR（需先准备好 PR body 文件）
GITHUB_TOKEN=ghp_xxx \
  node scripts/create-pr.js \
  --repo Lennonhaha/fibemate-tools \
  --head chore/scripts-archival-20260913 \
  --base main \
  --title "chore(scripts): archive github-api + server-sync helpers" \
  --body-file ./pr-body.md

# 合并 PR
GITHUB_TOKEN=ghp_xxx \
  node scripts/merge-pr.js \
  --repo Lennonhaha/fibemate-tools \
  --pr 12 \
  --method squash

# 服务器同步（示例路径）
REPO_DIR=/opt/fibemate-repo \
LOCKED_DIRS="/opt/fibemate-repo/www /opt/fibemate-repo/packages /opt/fibemate-repo/docs" \
REMOTE=origin BRANCH=main \
  bash scripts/server-sync.sh
```

> 注意：本仓的 commit 必须遵守 DCO（Developer Certificate of Origin）。
> 每条 commit 末尾带 `Signed-off-by: <name> <email>` trailer，否则 PR 的 DCO check 直接 FAIL。
> 推荐 `git config --global --add format.signOff always`，或在补救时用
> `git commit --amend --signoff --no-edit` + `git push --force-with-lease`。

## License

Apache-2.0。详见 [LICENSE](./LICENSE)。

> 注：本仓独立于 `fibemate` 主仓（GPL-3.0）。工具不进入主仓即不继承其传染性许可。
