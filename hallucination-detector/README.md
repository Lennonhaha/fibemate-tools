# crypto-hallucination-detector

启发式静态检测器：标记「AI 易编造 / 易漏」的密码代码风险模式。

## 定位

**不是**漏洞扫描器，**不是** AST 解析器。它基于轻量结构扫描（字符串掩码 + 括号配平）识别需人工核验的**气味信号**：

- **侧信道味道**：秘密相关分支 / 数组下标使用秘密 / switch-on-secret / 声明定常却非定常
- **伪造 API**：AI 常编造的伪 noble / WebCrypto 命名（如 `noble.kem.mlkem`、`crypto.subtle.mlkem`）
- **测试覆盖**：有实现但缺对应测试文件
- **非定常比较**：对秘密值用 `!= / ===` 而非 ct-equal

每条 finding 给出 file/line/severity/justification，**绝不宣判漏洞**——输出是 `needs-human-review`，由人定夺。

## 运行

```bash
npm test                  # 自带样本验证（命中幻觉模式 + 不误报良好代码）
node src/cli.js <dir>     # 扫描目录
node src/cli.js <dir> --fail-on high   # CI 门禁：存在 >=high 的 finding 则退出码 1
```

`--fail-on <low|medium|high>` 让 CLI 在存在「该级别及以上」的 finding 时以退出码 1 失败（可作 CI 门禁）；缺参或非法值退出码 2。注意：`api-misuse` / `domain-params` / `test-coverage` 三类 finding 没有 `severity` 字段，统一按 `medium` 归并——所以 `--fail-on high` 会放过 `medium` 级 finding（含这三类）；若要连这三类一起拦截，用 `--fail-on low`。

## 架构

| 文件 | 职责 |
|---|---|
| `src/ast-scanner.js` | 零依赖结构扫描：注释 / 调用 / 分支 / 函数 / 秘密变量传播 |
| `src/pattern-scanner.js` | 基于 ast 的启发式模式匹配（侧信道味道） |
| `src/api-misuse.js` | 伪 API 白名单+可疑命名检测 |
| `src/test-coverage.js` | 测试文件覆盖检查 |
| `src/constant-time.js` | 聚合侧信道相关 finding |
| `src/index.js` | 统一入口（聚合输出结构化报告） |
| `src/cli.js` | 命令行入口 |

## 关键纪律（对应 FIBEMATE 工程纪律）

- **API 白名单不是真理**：`api-misuse.js` 的白名单针对 FIBEMATE 技术栈，**任何新项目使用前须按自家依赖核实**（"不拿推测当事实"的代码化）。
- **零外部依赖**：不引入 acorn/esprima，避免把"完整 AST"当承诺；掩码扫描是启发式，定位透明。
- **不误报优先**：良样本 `sample.good.js` 必须零 finding，测试守护此约束。

## 已知局限

- 启发式，可能漏报（混淆写法）或误报（字符串里恰好出现模式）；输出供人复核。
- 不解析语言语义，仅结构特征。生产集成建议作为 PR 非阻塞检查。
