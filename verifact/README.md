# verifact — 事实哨兵

**把文档里的硬数字声明绑定到真实产出物上逐条核验，漂移即红。**

Markdown 文档里的性能基准、测试计数、版本号——这些数字会漂移。代码改了三轮，README 里的数字还是三个月前的。verifact 自动化「文档声明 vs 产出物」的交叉比对，把核对从肉眼 grep 变成门禁。

Zero external dependencies. Pure Node.js.

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

## 用法

```
npm install    # 零依赖，仅安装
```

### 核验文档

```bash
node bin/verifact.js verify                   # 默认配置，drift 即退出码 1
node bin/verifact.js verify --fail-on none    # 仅报告，不拦截
node bin/verifact.js verify --format md --out report.md
```

### 审查单条声明

```bash
node bin/verifact.js explain <claimId>
```

### 历史对比

```bash
node bin/verifact.js diff --since 3    # 最近 3 次运行的状态迁移
```

### 本地看板

```bash
node bin/verifact.js serve --port 8080
```

## 退出码

| 码 | 含义 |
|---|-------|
| 0 | 核验通过 / 无命中门禁条件 |
| 1 | 命中门禁条件（存在 drift 等） |
| 2 | 用法或配置错误 |

## 配置

项目根目录放置 `verifact.json`：

- `docs.roots` — 要扫描的文档目录
- `artifacts` — 产出物目录列表
- `ignore` — 已知可忽略的 drift 条目（白名单）
- `deny` — 禁止出现的声明模式

详见 [`verifact.json.example`](./verifact.json.example)。

## 设计

详见 [`VERIFACT-DESIGN.md`](./VERIFACT-DESIGN.md)：六态判定设计、绑定算法、ignore/deny 策略。

## 项目状态

| 项 | 状态 |
|---|-------|
| 回归测试 | ✅ 15 项 (`node test/run.js`) |
| CI 集成 | ✅ sentinel 门禁（`fail-on-drift`） |
| 平台 | Node.js ≥18，零外部依赖 |
| 发布 | 私有包（`@fibemate/verifact`），未发布 npm |
| 许可证 | Apache-2.0 |

## LICENSE

Apache-2.0 — see [LICENSE](../LICENSE).