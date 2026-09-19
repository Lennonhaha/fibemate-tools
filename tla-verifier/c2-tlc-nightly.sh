#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# FIBEMATE C-2 TLA+ 持续验证器（G1 修复：K3 强不变式门禁化）
# ---------------------------------------------------------------
# 本工具属于 fibemate-tools（Apache-2.0, no crypto algorithms）：
#   - 本脚本本身不含任何密码学实现，只驱动 TLA+ 官方工具 TLC 去验证
#     主仓 fibemate 里的协议模型 C2.tla / C2.cfg
#   - 被测模型留在主仓 docs/tla/（属密码学协议规格，不进工具仓）
#
# 跨仓依赖：模型从主仓来。CI 用 actions/checkout 同时拉主仓与工具仓，
#   或设 MAIN_REPO_DIR 指向主仓 checkout 根。脚本只接受路径，不 clone。
#
# 设计要点（基于实测，非记忆）：
#   - 不将 tla2tools.jar 提交进任何 git 仓库（避免污染历史 + 破坏可复现）
#   - 从官方 Release 钉版本下载（v1.7.4，仓库 tlaplus/tlaplus），
#     不用 latest（floating 引用会破坏"验证产物与代码事实绑定"
#     的方法论纪律 —— 正是 C-2 门禁接缝的反例）
#   - 只跑 C2.cfg 列出的 7 条不变式（TypeOK + K1~K5，含 K3/K3p 强形式）
#   - 不碰 L_Handshake liveness（G2 留研究线，见 C2.tla 作者自注
#     "Do not claim verified"）
#   - G3（re-run 触发）由 nightly 每次 checkout 当前 HEAD 自动满足：
#     任何改动 .tla/.cfg 的 PR 合入后，下一次 nightly 自然重跑
#
# 前置：bash + java 17（GitHub Actions 用 actions/setup-java 钉 SHA）
# 调用：bash tla-verifier/c2-tlc-nightly.sh
# ---------------------------------------------------------------
set -uo pipefail   # 不用 -e：需在 java 非零退出时捕获 rc

# 主仓 checkout 根（CI 中由 checkout 动作注入；本地默认当前目录）
MAIN_REPO_DIR="${MAIN_REPO_DIR:-.}"
TLA_DIR="$MAIN_REPO_DIR/docs/tla"
MODEL="${MODEL:-C2}"
CFG="$TLA_DIR/$MODEL.cfg"
TLA="$TLA_DIR/$MODEL.tla"

# Windows/git-bash 路径归一化：把反斜杠/盘符路径转成 MSYS 可识别形式。
# Linux CI 下 cygpath 不存在，跳过（保持原样，Linux 路径本就标准）。
if command -v cygpath >/dev/null 2>&1; then
  # -w 输出 Windows 原生 D:\... 格式（Java File API 在 Windows 上最稳）
  CFG="$(cygpath -w "$CFG")"
  TLA="$(cygpath -w "$TLA")"
fi

# 钉版本，不用 latest（可复现性）。可用 env 覆盖做测试。
TLA2TOOLS_URL="${TLA2TOOLS_URL:-https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar}"
JAR="${TLA2TOOLS_JAR:-/tmp/tla2tools.jar}"
JAVA_OPTS="${JAVA_OPTS:--Xmx2g -XX:+UseParallelGC}"

# Windows/git-bash：java 是原生程序，MSYS 风格路径（/tmp/...、/d/...）它读不到。
# 与上面 CFG/TLA 同理做 cygpath 归一化；实测缺失时
# "Error: Unable to access jarfile /tmp/tla2tools.jar"（exit 1）。
if command -v cygpath >/dev/null 2>&1; then
  JAR="$(cygpath -w "$JAR")"
fi

# 0. 输入检查
[ -f "$CFG" ] || { echo "MISSING: $CFG (set MAIN_REPO_DIR to fibemate checkout root)"; exit 2; }
[ -f "$TLA" ] || { echo "MISSING: $TLA (set MAIN_REPO_DIR to fibemate checkout root)"; exit 2; }

# 1. 取 jar（若未提供则由 env 指定路径复用）
if [ ! -f "$JAR" ]; then
  echo "==> Downloading tla2tools.jar (pinned v1.7.4, repo tlaplus/tlaplus)"
  curl -fsSL "$TLA2TOOLS_URL" -o "$JAR"
fi

# 2. 跑 TLC（仅不变式，无 liveness —— 对应 G2 不在此 job）
echo "==> Running TLC on $MODEL (Spec + 7 invariants; liveness excluded per G2)"
java $JAVA_OPTS -jar "$JAR" -config "$CFG" -workers auto "$TLA" || rc=$?
rc=${rc:-0}
echo "==> TLC exit code: $rc"
# TLC 非 0 = 发现违反或异常 → 让 nightly 红
exit "$rc"
