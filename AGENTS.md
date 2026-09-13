# AGENTS.md - fibemate-tools Workspace

> Companion to [`Lennonhaha/fibemate` AGENTS.md](https://github.com/Lennonhaha/fibemate/blob/main/AGENTS.md).
> This file is fibemate-tools-specific; the main repo's AGENTS.md is the
> authority on the broader push / encoding / health discipline. Where they
> disagree, the main repo wins.

## Repository Map (this repo only)

- `hallucination-detector/` — Node.js (zero-dependency) static analysis
- `crypto-time-machine/` — Python (stdlib only) git history query
- `undecryptable-prover/` — Rust + Lean4 evidence generator
- `docs/` — GitHub Pages site (separate branches per showcase, see below)
- `scripts/` — maintenance scripts (this repo's own deploy / GitHub API
  helpers; see `README.md` §Scripts)
- `.github/workflows/` — per-tool CI: detector-ci / time-machine-ci / prover-ci

Showcase branches (intentionally split so each PR can land independently):

| Branch | Lives at | Pushed to |
|---|---|---|
| `docs/detector-showcase` | `docs/detector/` | GitHub Pages `detector/` |

Future showcase pages (time-machine, prover) will follow the same
`docs/<tool>-showcase` convention.

## Iron Rules (违反即事故)

1. **推送前必须先征求用户同意**，逐仓逐 commit 请示。不得自行 push。
2. **严禁混线**：研究代码 / 实验脚本不得 commit 到主仓 main；
   本仓 Apache-2.0 与主仓 GPL-3.0 是有意分离，不要把 main 仓代码
   mirror 进来做"测试"用途。
3. **真源唯一**：算法实现真源 = 主仓，本仓的 `hallucination-detector`
   / `crypto-time-machine` / `undecryptable-prover` 三个工具
   **不实现任何密码学算法**——只读取主仓数据，做静态 / 历史 / 证据分析。
4. **命令前先 `git status -sb` + `git log --oneline -1`**，确认在
   正确仓库、正确分支、正确 HEAD 再操作。
5. **推送用 SSH `-p 22`**（QMTAP 挡 443）：
   `$env:GIT_SSH_COMMAND = "ssh -p 22 -o StrictHostKeyChecking=no"`。
   PowerShell 把 git stderr 当 RemoteException 报 exit 1 是**误报**，
   看 `main -> main` 那一行判断真伪。
6. **commit 必须 DCO sign-off**（跨仓纪律，与主仓 AGENTS.md 铁律 #7 同源）：
   每个 commit 末尾必须有 `Signed-off-by: <name> <email>` trailer。
   DCO check 是 PR 合并门禁，缺签名直接 FAIL。
   推荐 `git config --global --add format.signOff always`；
   **但 `format.signOff=always` 在以下情况「不会」自动注入 trailer，必须显式加 `-s`/`--signoff`**：
   - `git commit -F <file>`（从文件读 message 时——`-F` 绕过了 interactive 注入路径）
   - `git commit --amend`（含 amend 后补 signoff 的场景）
   - merge commit（`git merge` / `git merge --no-edit` 产生的合并提交）
   默认动作：**`git commit -s -F <msgfile>`**（既读文件又显式签名），不要只写 `-F`。
   补救：`git commit --amend --signoff --no-edit`。
   推送前用 `git cat-file -p HEAD` 确认 trailer 行存在，否则 CI 的 DCO check 必 FAIL。
   教训：A 线（PR #4）和 B 线（PR #5）各踩过一次 `-F` 不注入，本条即为此固化。
7. **DCO 门禁绕不开**：本仓 PR 一律走 squash merge，
   `gh pr create` / `gh pr merge` 在 Windows 上会因 gh 老 bug
   （找不到 `git merge` 子命令）失败，**统一走 `scripts/create-pr.js` +
   `scripts/merge-pr.js`**（GitHub REST API，零依赖）。

## Encoding Discipline (推送前必查)

- 任何新 `.md`/`.html`/`.js` 落地前：**字节级验证** UTF-8
  （`read` 工具 / Node `TextDecoder(fatal:true)` / U+FFFD 计数=0），无 BOM。
- 禁止用 PowerShell 显示层（GBK）判定乱码——那是显示假象，不是文件损坏。
- 写 .md 举例乱码符号必须用转义 `\uFFFD`，禁写字面 `\uFFFD`。
- 本仓 `README.md` 是 **Apache-2.0 公开文件**，不要写入：
  任何 token / SSH 私钥 / 服务器 IP / 个人邮箱电话。

## Scripts (this repo's maintenance tools)

> See `scripts/` for actual files. They live here because this repo is
> Apache-2.0 and has a clean separation from the main repo's GPL-3.0 code.

| Script | What it does | When to use |
|---|---|---|
| `scripts/create-pr.js` | Open a PR via GitHub REST API | When `gh pr create` fails on Windows |
| `scripts/merge-pr.js`  | Squash-merge a PR via GitHub REST API | When `gh pr merge` fails on Windows |
| `scripts/server-sync.sh` | `chattr -i` → `git pull --ff-only` → `chattr +i` SOP | When deploying to a server with locked working tree |
| `scripts/pilotB_run_gpt.py` | **PARKED** runner that calls a real GPT endpoint (transport-only, model string taken from API response, never impersonates Claude) | **Do NOT run by default** — needs `OPENAI_API_KEY` + egress to `api.openai.com`, both absent in this sandbox; archived here for future use only |

**Token discipline:** all three scripts read `$GITHUB_TOKEN` (or `$GH_TOKEN`)
from the environment. Never hardcode a token, and never commit a token.

## Daily Pre-flight Check

Before starting work each day on this repo, run three commands:

```bash
git -C path/to/fibemate-tools log -1 --oneline   # am I on the right commit?
git -C path/to/fibemate-tools status --short     # what's actually staged/changed?
gh pr list --repo Lennonhaha/fibemate-tools      # is the release status as expected?
```

This catches 80% of surprises (stale commits, unexpected staging, PR drift)
before they become incidents.

## Why this repo is Apache-2.0 and the main repo is GPL-3.0

The split is intentional. fibemate-tools' three utility tools are
designed to be read-only, dependency-light, and license-compatible with
practically any downstream consumer (Apache-2.0 is one of the most
permissive open-source licenses). The main fibemate repo, by contrast,
ships a full cryptography stack and uses GPL-3.0 to keep the
implementation copyleft while allowing the demo to be embedded.

If you ever feel the urge to "import the algorithm from the main repo
just to make this tool self-contained" — don't. The signal is in the
gap between the two repos, not the merging.
