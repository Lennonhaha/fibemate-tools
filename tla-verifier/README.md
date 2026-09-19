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

- `c2-tlc-nightly.sh` — 可复用验证脚本（跨仓拉主仓模型，路径由 `MAIN_REPO_DIR` 注入）
- `README.md` — 本文件
