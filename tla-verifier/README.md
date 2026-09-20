# tla-verifier — FIBEMATE C-2 TLA+ 持续验证器

> 工具仓 `fibemate-tools` 子模块（Apache-2.0，**no crypto algorithms**）
> 本目录只驱动 TLA+ 官方工具 TLC 去验证**主仓 `fibemate`** 里的协议模型，
> 自身不含任何密码学实现。

## 它做哪件事

把 FIBEMATE Path C-2 混合握手状态机（`C2.tla` / `C2.cfg`，位于主仓 `docs/tla/`）
的 **K3 强密钥独立等 7 条不变式**纳入持续验证（nightly），让"验证产物"
从一次性快照变成常驻门禁。这修复了 `seam-c2-gate-gap` 文档里记录的 **G1 接缝**
（CI 不跑 TLC、验证仅历史快照 `d73a5b9`、协议升级后旧验证 silently 失效）。

## 关键事实（实测，非记忆）

- 主仓 `C2.tla` 在 2026-09-19 修复了一处 **deadlock（liveness 缺陷，非安全 bug）**：
  新增 `ClosingLoopC(i)` / `ClosingLoopS(i)` 为 `closing` 状态补 stuttering。
  修复前 TLC exit 11（deadlock），修复后 **exit 0 / VIOLATED 0 / distinct states = 26,115**
  （与历史快照一致，generated 133,891 完整跑完）。
- `tla2tools.jar` 钉 **v1.7.4**（仓库 `tlaplus/tlaplus`），**不用 latest**——
  floating 引用会破坏可复现性，正是 G1 要反对的方法论。
- G2（liveness `L_Handshake`）**不在本验证范围**：C2.tla 作者自注
  `Do not claim verified`，无机器证据，留研究线。

## 用法

```bash
# 本地：MAIN_REPO_DIR 指向 fibemate checkout 根
MAIN_REPO_DIR=/path/to/fibemate bash tla-verifier/c2-tlc-nightly.sh
# 或复用已下载的 jar：
TLA2TOOLS_JAR=/tmp/tla2tools.jar MAIN_REPO_DIR=/path/to/fibemate \
  bash tla-verifier/c2-tlc-nightly.sh
```

## 接入主仓 nightly（CI）

本目录**不含 workflow 文件**——CI job 必须写在**触发运行的仓库**里。
因为验证对象是主仓协议模型、目的是主仓门禁常驻，job 应并入
**主仓 `fibemate/.github/workflows/nightly-phase1.yml`**。

参考 job 定义（已 draft，待并入主仓；注意 `permissions: read-all`
下不 cache，每次 curl 2.27MB；setup-java 须钉 commit SHA）：

```yaml
  c2-tlc:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@<pinned-sha>          # 主仓（含 docs/tla/C2.*）
      - uses: actions/checkout@<pinned-sha>          # 工具仓（取脚本）
        with: { repository: Lennonhaha/fibemate-tools, path: fibemate-tools }
      - name: Setup Java 17
        uses: actions/setup-java@<pinned-sha>        # TODO: 替换真实 SHA
        with: { distribution: temurin, java-version: '17' }
      - name: C-2 TLA+ invariants (TLC)
        env:
          MAIN_REPO_DIR: .
          TLA2TOOLS_URL: https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
        run: bash fibemate-tools/tla-verifier/c2-tlc-nightly.sh
        # FAIL on TLC non-zero（发现不变式违反 → nightly 红）
```

## 文件

- `c2-tlc-nightly.sh` — 可复用验证脚本（跨仓拉主仓模型，路径由 `MAIN_REPO_DIR` 注入；G1 专用，仅 C2）
- `seam-checker.js` — **接缝检查器 v1**（G 层门禁 + S 层接缝映射；见下）
- `README.md` — 本文件

## seam-checker.js（接缝检查器 v1）

把 `seam-checker-v0` 原型落成正式工具。职责两层：

**G 层（模型内门禁，执行层取证）**：对每个模型（C2/OPK）复制 `.tla+.cfg` 到临时目录跑 TLC，
按 **exit code + 逐 `INVARIANT` VIOLATED** 判 `PARSE_FAIL / INV_VIOLATED / DEADLOCK / PASS`。
**不凭 `.cfg` 存在判“通过”** —— 这正是 C-2 门禁接缝（G1）和 OPK 从未跑过（M 类）要抓的纪律。

**S 层（层间接缝，声明式映射表）**：把 `seam-checklist-v1` 的 S1/S2/S4/G2/M 项做成硬编码映射
（期望证据 + 当前状态），输出每条 `CLOSED / OPEN / MODEL_DEFECT`。
v1 不自动 grep 代码库（避免误判），证据变化时由人工/CI 更新。

### 用法
```bash
MAIN_REPO_DIR=/path/to/fibemate \
TLA2TOOLS_JAR=/tmp/tla2tools.jar \
  node tla-verifier/seam-checker.js
```

### 实测（2026-09-20，主仓工作树含 OPK 未提交编辑）
```
### C2 -> PASS (exit 0)   cfg invariants: TypeOK, K1..K5 (7 条)  真实机器证据 133891/26115
### OPK -> INV_VIOLATED (exit 12)  违反 O4_ConsumedNotReusable
S 层: CLOSED=2  OPEN=11  MODEL_DEFECT=3
G 层（模型门禁）: FAIL   (exit 1 → CI 红)
```

### 关键纪律（已落 memory）
> "有 `.cfg` / 有 `INVARIANT` 行" ≠ "跑过" ≠ "通过"。声明层（文件在、cfg 在）与执行层
> （exit 0 + VIOLATED=0）是两回事。OPK 是活标本：声明层配了 O1–O6，执行层 O4 失败。

### 待推进（不在此 v1）
- v2：S 层自动 grep 实现仓库（mlkem-kat/gm-crossval/握手集成测试）断言 S1 项闭合
- v2：S2 层接 TVLA 流水线结果；S4 层接外部标准引用表自动校验可追溯
- G2：nightly TLC 加 `PROPERTY L_Handshake` / `T1/T2`（当前 C2.cfg 未列）
- 是否提升进主仓 `docs/` + 并入 `nightly-phase1.yml`，需用户授权（DCO sign-off）
