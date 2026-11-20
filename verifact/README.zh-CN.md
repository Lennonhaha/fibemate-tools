# verifact — 事实哨兵

> English version: [README.md](./README.md)

**把文档里的硬数字声明绑定到真实产出物上逐条核验，漂移即红。**

Markdown 文档里的性能基准、测试计数、版本号——这些数字会漂移。代码改了三轮，README 里的数字还是三个月前的。verifact 自动化「文档声明 vs 产出物」的交叉比对，把核对从肉眼 grep 变成门禁。

Zero external dependencies. Pure Node.js.

## 这个工具不做什么

三件容易被误解的事，写在最前面：

- **不扫漏洞。** 它不分析代码、不查 CVE、不做污点分析。它只核对「文档里写的数字」与「仓库里的产出物」是否一致。没有产出物可对的声明会落到 `unbound`，那是「缺证据」，不是「安全」。
- **不保证安全。** `drift 0` 只代表本次扫描范围内没有发现数值漂移。它不是合规结论，也不能替代渗透测试或第三方审计。
- **不执行被审代码。** 扫描过程只读文件、解析文本与 JSON，不运行仓库里的任何脚本或二进制。

报告长什么样、怎么读：<https://fibemate.net/tools/verifact-demo/>（那个页面只渲染 JSON，不做任何判定）。

判定边界写在 `VERIFACT-DESIGN.md`。绑不上的声明会被列出来，工具不会替你补一个数字。

## 与 OWASP CycloneDX 规范的关系

本工具对「字段缺失」与「显式零值」的区分，与 OWASP CycloneDX 密码学属性（cryptoProperties）语义澄清的方向一致。作者就该语义向上游规范仓库提交了澄清提案，已获规范维护者评审通过；**提案尚未合并，合并前不代表规范文本已变更**。

## 核心流程

```
[文档] ──→ 抽取带单位的关键数字 ──→ 按键名+数值绑定到产出物 ──→ 六态判定
                                              ↑
                                     [基准/日志/TSR 等产出物]
```

### 六态判定

| 判定 | 含义 | 处置 |
|:--|:--|:--|
| `verified` | 文档值与产出物在容差内一致 | 绿 |
| `drift` | 绑定成功但数值超出容差 | 🔴 门禁拦截 |
| `ambiguous` | 多个产出物候选冲突 | 交人工 |
| `unbound` | 找不到产出物依据 | 交人工 |
| `ref-matched` | 声明引用 `lg-XXX` 等实体，在扫描范围内找到 | 绿 |
| `ref-missing` | 引用实体不在扫描范围内 | 交人工 |

## 安装

```bash
npm i -g verifact      # 全局安装，得到 verifact 命令
npx verifact --help    # 免安装试用
```

零外部依赖。从源码检出运行时，下文的 `verifact` 可替换为 `node bin/verifact.js`。

### 核验文档

```bash
verifact verify                   # 默认配置，drift 即退出码 1
verifact verify --fail-on none    # 仅报告，不拦截
verifact verify --format md --out report.md
```

### 审查单条声明

```bash
verifact explain <claimId>
```

### 历史对比

```bash
verifact diff --since 3    # 最近 3 次运行的状态迁移
```

### 本地看板

```bash
verifact serve --port 8080
```

## 退出码

| 码 | 含义 |
|---|-------|
| 0 | 核验通过 / 无命中门禁条件 |
| 1 | 命中门禁条件（存在 drift 等） |
| 2 | 用法或配置错误 |

## 配置

项目根目录放置 `verifact.json`：

- `docs.roots` / `artifacts.roots` — 要扫描的目录或文件；**相对路径以配置文件所在目录为基准**（不是 cwd）
- `artifacts` — 产出物目录列表
- `ignore` — 已知可忽略的声明（不计入统计）
- `deny` — 人工拒绑：声明仍留在报告与总数里，但不做自动绑定，note 写出理由

详见 [`verifact.json.example`](./verifact.json.example)。

## 设计

详见 [`VERIFACT-DESIGN.md`](./VERIFACT-DESIGN.md)：六态判定设计、绑定算法、ignore/deny 策略。

## 测试与覆盖率

`node test/run.js` 跑回归；`npm run test:coverage` 用 npx 临时调 c8（不新增依赖）。

退出码用子进程跑 CLI 断言：报告里写 `gate.failed: true` 不算门禁，`exit 1` 才算。每条门禁用例都配一条只改策略的对照跑（`--fail-on none`，未绑定用 `--fail-on review`），避免把“对照组也绿”当成“门禁生效”。

覆盖范围：`src/` 与 `bin/`。看板（`serve`）只有一条 smoke 测试（`/api/health`、`/api/config`），下发核验与历史页面当前无人测，属已知缺口。`src/server/www/app.js` 是浏览器代码，Node 跑出来的 0% 不代表它坏了。池化扫描（`pooled-scan.js` + `worker.js`）用差分测试覆盖：十个文件强制走池，逐个与内联提取器对比，两份扫描循环不能悄悄漂移。

CI 不设覆盖率阈值：基线还没稳定时定阈值，只会教人删断言。

## 项目状态

| 项 | 状态 |
|---|-------|
| 回归测试 | ✅ 77 项 (`node test/run.js`) |
| CI 集成 | ✅ sentinel 门禁（`fail-on-drift`）+ 语料门禁（变异必红） |
| 平台 | Node.js ≥18，零外部依赖 |
| 发布 | npm 公共包 `verifact`（无 scope，公开；`npm i -g verifact`） |
| 许可证 | Apache-2.0 |

## LICENSE

Apache-2.0 — see [LICENSE](./LICENSE).