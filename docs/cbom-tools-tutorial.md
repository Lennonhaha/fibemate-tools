# 用 cbom-tools 做一次真实的 PQC 迁移审计：从 ECDH + SM2 + SHA-256 到 ML-KEM + SHA3

> 这篇不是"介绍一下 CBOM"。它是一条可以照着跑通的链路：**扫出资产 → 算就绪度 → 用 diff 卡住回归 → 把三者塞进 CI**。
> 所有输出都是实跑结果，不是示意。
>
> 工具：`cbom-tools@0.2.8`（Apache-2.0，零依赖，纯 Node.js）
> 规格：CycloneDX 1.7（`--spec 1.6` 可选）
>
> **版本说明**：0.2.8 截至 2026-11-15 **尚未发布到 npm**。发布前，把命令里的
> `npx cbom-tools …` 换成仓库内的 `node cbom-tools/cli.cjs …`（输出一致）；
> `npx cbom-tools@0.2.7` 仍可用于扫描，但 §7 坑 1 描述的那个 `exit 1` 缺陷在
> 0.2.7 上依然存在。

---

## 0. 先划边界：它不做什么

写在前面的三句话，比后面所有命令都重要：

1. **它不找漏洞。** 没有 CVE 查询、没有污点分析、不判断算法选得对不对。它只回答"**哪些地方调用了密码学 API**"。
2. **它不保证清单完整。** 检测是"按语言/库的模式匹配"。**一次干净的扫描 = 这一版规则表没匹配到**，不等于"这里没有密码学"。运行期拼出来的算法名（`process.env`、网络下发、变量拼接）、原生绑定、vendor 二进制，都可能漏。
   - 例外（已实现）：**字面量**拼出来的名字会先还原再匹配——`'sha' + '256'`、`['sh','a256'].join('')`、`` `ml-kem-${'768'}` ``、base64、`\x` 转义。`test/fixtures/evasion/` 每个形态一个 fixture，这条声明是可执行的。
3. **它不执行被扫的代码。** 只读文件、只做解析。

所以：**CBOM 是待审的库存，不是合规结论**。

---

## 1. 一条命令先看东西

```bash
npx cbom-tools scan --dir ./my-service --out cbom.json
```

```
cbom-scan: wrote 5 algorithms to cbom.json (CycloneDX 1.7)
```

`--spec` 只接受 `1.6` / `1.7`（`--spec=1.7` 也行），**其他值直接 exit 2**，不会静默退回默认值——一份声称自己符合某版本却不符合的 BOM，比没有 BOM 更糟。

扫描范围（实测，`cbom-scan.cjs`）：

| 项 | 行为 |
|---|---|
| 源码 | `.js .cjs .mjs .ts .tsx .jsx`，正则匹配 |
| 依赖 | `package.json` 的 dependencies，走声明式规则表 |
| 跳过目录 | `node_modules` `dist` `build` `coverage` `.git` `.cache`，以及所有 `.` 开头的目录 |
| 单文件上限 | 8 MB，超了**跳过并告警**，其余继续扫 |
| 不可读文件 | 告警 + 跳过，不当成"干净" |

---

## 2. 造一个真实的迁移场景

三个目录，同一份服务的三个阶段。`legacy` 是必须迁移的那一版：

```js
// legacy/src/session.js
const crypto = require('crypto');
const sm = require('sm-crypto');

function digestPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

function signPayload(payload, privateKey) {
  return sm.sm2.doSignature(payload, privateKey);
}

function sessionKey() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}
```

```json
// legacy/package.json
{ "dependencies": { "sm-crypto": "^0.3.13", "express": "^4.19.2" } }
```

迁移后（`migrated`）换成 ML-KEM + SHA3：

```js
// migrated/src/session.js
const { sha3_256 } = require('@noble/hashes/sha3');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem');

function digestPassword(pw) {
  return Buffer.from(sha3_256(pw)).toString('hex');
}

function sessionKey() {
  return ml_kem768.keygen();
}
```

```json
{ "dependencies": { "@noble/post-quantum": "^0.4.0", "@noble/hashes": "^1.5.0", "express": "^4.19.2" } }
```

第三个目录 `regressed` 是"迁移完之后有人又把 SM2 加回来"的那种 PR——后面用它演示 exit 3。

---

## 3. 扫描：三份 CBOM，三种命运

```bash
npx cbom-tools scan --dir ./legacy    --out before.json    # 5 algorithms
npx cbom-tools scan --dir ./migrated  --out after.json     # 5 algorithms
npx cbom-tools scan --dir ./regressed --out regressed.json # 7 algorithms
```

```
cbom-scan: wrote 5 algorithms to before.json (CycloneDX 1.7)
cbom-scan: wrote 5 algorithms to after.json (CycloneDX 1.7)
cbom-scan: wrote 7 algorithms to regressed.json (CycloneDX 1.7)
```

注意 **`migrated` 里有 5 个，不是 2 个**。这不是噪声，是两套规则叠加：

- 源码规则：`sha3_256` → `SHA3-256`；`ml_kem768` → `ML-KEM-768`
- 包规则：`@noble/post-quantum` → **`ML-KEM`、`ML-DSA`、`SLH-DSA` 三个一起报**（保守推断，见 §7 坑 2）

---

## 4. 打开的 CBOM 长什么样

`before.json` 里一个组件（`ECDH`）的真实内容：

```json
{
  "type": "cryptographic-asset",
  "name": "ECDH",
  "bom-ref": "crypto:ECDH",
  "evidence": {
    "identity": [
      {
        "field": "name",
        "confidence": 0.7,
        "concludedValue": "ECDH",
        "methods": [
          { "technique": "source-code-analysis", "confidence": 0.7, "value": "ecdh" }
        ]
      }
    ],
    "occurrences": [
      { "location": "src/session.js", "line": 13, "symbol": "ecdh" },
      { "location": "src/session.js", "line": 14, "symbol": "ecdh" },
      { "location": "src/session.js", "line": 15, "symbol": "ecdh" }
    ]
  },
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "key-agree" }
  },
  "properties": [
    { "name": "fibemate:implementationLanguages",  "value": "c" },
    { "name": "fibemate:testingStatus",            "value": "known-answer-tested" },
    { "name": "fibemate:quantumSecurity:level",    "value": "vulnerable" }
  ]
}
```

三个字段值得记住，因为后面所有判断都建在它们上面：

| 字段 | 含义 | 谁在用 |
|---|---|---|
| `evidence.occurrences` | 文件 + 行号 + 符号，每算法最多 50 条、去重 | 人：追到调用点；`evidence.count` 参与 diff |
| `cryptoProperties.assetType` | 资产类型。**扫描器一律写 `"algorithm"`** | `cbom-diff` 的风险分级（见 §7 坑 1） |
| `properties[fibemate:quantumSecurity:level]` | `vulnerable` / `weak` / `safe` | 就绪度计算、diff 的 exit 3 判定 |

**一个刻意的缺席**：`nistQuantumSecurityLevel` 扫描器**永不发出**。文件级扫描没有资格声称任何 NIST 类别——连 `0` 都不行，因为 `0` 是"评估过、没有任何类别满足"，而"没评估"是另一件事。每份 BOM 都带一条机器可读注释说明这个缺席的意思：

```json
{ "name": "fibemate:nistQuantumSecurityLevel:semantics", "value": "..." }
```

---

## 5. 就绪度：工具不给你打分，20 行代码给

`cbom-tools` 没有 `readiness` 子命令，这是有意的：**"就绪度"是策略，不是格式**。但原始数据都在 CBOM 里，算出来只需要 20 行。

```js
#!/usr/bin/env node
// readiness.cjs — turn a CBOM into a quantum-readiness verdict with an exit code.
const fs = require('node:fs');

const file = process.argv[2];
const allow = process.argv.includes('--allow-vulnerable');
if (!file) {
  console.error('usage: node readiness.cjs <cbom.json> [--allow-vulnerable]');
  process.exit(2);
}

const bom = JSON.parse(fs.readFileSync(file, 'utf8'));
const levelOf = (c) => {
  const p = (c.properties || []).find((x) => x.name === 'fibemate:quantumSecurity:level');
  return p ? p.value : 'unknown';
};

const buckets = { vulnerable: [], weak: [], safe: [], unknown: [] };
for (const c of bom.components || []) (buckets[levelOf(c)] || buckets.unknown).push(c.name);

for (const k of ['vulnerable', 'weak', 'safe', 'unknown']) {
  console.log(`${k.padEnd(11)} ${String(buckets[k].length).padStart(2)}  ${buckets[k].join(', ')}`);
}

const total = (bom.components || []).length;
const ready = total > 0 && buckets.vulnerable.length === 0 && buckets.unknown.length === 0;
console.log(`\nquantum-ready: ${ready ? 'yes' : 'no'}  (${total} algorithms, ${buckets.vulnerable.length} vulnerable)`);

if (buckets.vulnerable.length > 0 && !allow) process.exit(1);
```

跑三份：

```bash
$ node readiness.cjs before.json
vulnerable   2  ECDH, SM2
weak         3  SHA-256, SM3, SM4
safe         0
unknown      0

quantum-ready: no  (5 algorithms, 2 vulnerable)
# exit 1

$ node readiness.cjs after.json
vulnerable   0
weak         0
safe         5  Keccak, ML-DSA, ML-KEM, ML-KEM-768, SLH-DSA
unknown      0

quantum-ready: yes  (5 algorithms, 0 vulnerable)
# exit 0

$ node readiness.cjs regressed.json
vulnerable   1  SM2
weak         2  SM3, SM4
safe         4  ML-DSA, ML-KEM, ML-KEM-768, SLH-DSA
unknown      0

quantum-ready: no  (7 algorithms, 1 vulnerable)
# exit 1
```

三个设计决定，都是刻意的：

- **`unknown` 不算就绪。** 没有 `quantumSecurity:level` 的组件（别的工具产出的 CBOM）不能默认当成安全。
- **`weak` 不阻断。** 迁移期 SHA-256 还在跑是常态；只有 `vulnerable` 拦门，`weak` 靠 diff 治理。
- **`--allow-vulnerable` 是逃生口**，用于"存量遗留，本月不修"的白名单期——但必须显式写在命令行上，不能悄悄配在配置文件里。

---

## 6. diff：四种退出码，四种真实场景

`cbom-diff` 的全部价值在退出码上。下面四个都是实跑。

### exit 0 — 没有任何变化

```bash
$ npx cbom-tools diff after.json after.json
## CBOM Diff `… → …`

| 属性 | 值 |
|------|-----|
| 旧版本 | 1 |
| 新版本 | 1 |
| 版本 | same |
| 严重性 | **none** (exit=0) |

### ✅ 无变更
> 前后 CBOM 完全一致，5 算法无变化。
```

### exit 1 — 信息性变更：新增了一个安全算法

迁移路上最常见的良性变更就是「又加了一个安全算法」。给 `migrated` 增加一处
`sha3-512` 调用（原本只有 `sha3_256`）：

```bash
$ npx cbom-tools diff after.json after-sha512.json
## CBOM Diff `… → …`

| 属性 | 值 |
|------|-----|
| 旧版本 | 1 |
| 新版本 | 1 |
| 版本 | same |
| 严重性 | **info** (exit=1) |

### ➕ 新增算法

| 名称 | 类型 | 风险 |
|------|------|------|
| SHA3-512 | algorithm | 🟢 info |

### ℹ️ 信息性变更
> 5 算法保持原样。（2026-11-15T05:40:10.478Z）

$ echo $?
1
```

**这一格是可用的门禁分界线**：`info` = 「新增的是安全算法」，`warning` = 「删了东西或新增的是弱算法」。

> ⚠️ 在 **0.2.7** 上这条命令会得到 `🟡 warning` / `exit=2`：分级当时只看
> `assetType`，而扫描器恒写 `"algorithm"`，于是所有新增都落到 `warning`。
> 见 §7 坑 1（0.2.8 已修）。

同一个退出码的另一个来源是「属性变了，算法没增没减」。例如厂商 CBOM 把
`ML-KEM-768` 的 `assetType` 写作 `kem`，而扫描器写 `algorithm`：

```bash
$ npx cbom-tools diff after.json after-vendor.json
## CBOM Diff `… → …`

| 属性 | 值 |
|------|-----|
| 严重性 | **info** (exit=1) |

### 🔄 属性变更 (1 项)

**ML-KEM-768**
- `assetType`: `algorithm` → `kem`

### ℹ️ 信息性变更
> 4 算法保持原样。（2026-11-15T03:28:04.644Z）
```

### exit 2 — 警告：删了算法，或新增强度不足的算法

迁移本身就会落在这里：删掉 5 个、加上 5 个。

```bash
$ npx cbom-tools diff before.json after.json
## CBOM Diff `… → …`

| 属性 | 值 |
|------|-----|
| 严重性 | **warning** (exit=2) |

### ➕ 新增算法

| 名称 | 类型 | 风险 |
|------|------|------|
| Keccak | algorithm | 🟢 info |
| ML-DSA | algorithm | 🟢 info |
| ML-KEM | algorithm | 🟢 info |
| ML-KEM-768 | algorithm | 🟢 info |
| SLH-DSA | algorithm | 🟢 info |

### ➖ 删除算法

| 名称 | 类型 |
|------|------|
| ECDH | algorithm |
| SHA-256 | algorithm |
| SM2 | algorithm |
| SM3 | algorithm |
| SM4 | algorithm |

### ⚠️ 警告
> 检测到值得关注的变更，请确认是否符合预期。
```

**这一条要读懂**：`exit 2` 在这里**不是**「迁移失败」，而是「**删除了算法**」触发的——注意新增的五个都是 `🟢 info`，把严重性抬到 `warning` 的是删除栏里的五个。删算法是破坏性变更——老客户端还在用 SM2 签名的话，删了就是线上 500。所以它要求人看一眼，而不是自动放行。

### exit 3 — 严重：新引入了量子脆弱算法

`regressed` 相对 `migrated` 只多了一个 `sm.sm2.doSignature`：

```bash
$ npx cbom-tools diff after.json regressed.json
## CBOM Diff `… → …`

| 属性 | 值 |
|------|-----|
| 严重性 | **critical** (exit=3) |

### ➕ 新增算法

| 名称 | 类型 | 风险 |
|------|------|------|
| SM2 | algorithm | 🔴 critical |
| SM3 | algorithm | 🟡 warning |
| SM4 | algorithm | 🟡 warning |

### ➖ 删除算法

| 名称 | 类型 |
|------|------|
| Keccak | algorithm |

### 🔴 严重
> 检测到量子脆弱算法被引入，**请立即审查**。
```

exit 3 的定义（[issue #43](https://github.com/Lennonhaha/fibemate-tools/issues/43) 里定的）：

> `fibemate:quantumSecurity:level == vulnerable` 的算法出现在 after、但不在 before。

两条推论同样是刻意的：

- **一直脆弱不算回归。** 存量代码不会因为"它原来就脆弱"而把构建变红——否则第一次扫描整个遗留库，全红，然后就没人看了。
- **单份 CBOM 没有基线，最高只到 exit 1。** 没有 before 就没有"新引入"。

### exit 2（另一条路）— 用法错误，不是扫描结果

这是本工具最容易被误读的一格，也是 0.2.7 专门修的地方：**跑不起来的扫描，绝不能长得像"扫了没东西"**。

```bash
$ npx cbom-tools scan --dir ./nope --out x.json
usage: cbom-scan [--dir <path>] [--out <file>] [--spec 1.6|1.7]
  --dir not found: ./nope (ENOENT)
# exit 2

$ npx cbom-tools scan --dir ./legacy --spec 1.5
usage: cbom-scan [--dir <path>] [--out <file>] [--spec 1.6|1.7]
  --spec must be one of 1.6, 1.7 (got "1.5")
# exit 2
```

0.2.7 之前，`--dir` 打错会输出一份空 CBOM 并 **exit 0**——在流水线里读起来就是"这棵树没有密码学"。这是最恶劣的假绿，已经在 0.2.7 改成 exit 2。

---

## 7. 三个必须知道的坑（实测，不是文档抄的）

### 坑 1（0.2.7 及以前，已修复）：分级只看 `assetType`，`exit 1` 对自产 CBOM 不可达

`classifyRisk()` 判断「新增算法值不值得警告」时，原本只看 **`cryptoProperties.assetType`**：

```js
// 0.2.7
if (quantum === 'vulnerable') return 'critical';
const type = (cryptoProps.assetType || '').toLowerCase();
if (/kem|sign|signature|post.quantum|pqc|mlkem|mldsa|slh/i.test(type)) return 'info';
if (/ecc|ecdh|p-256|sm2|curve/i.test(type)) return 'warning';
if (/sym|sm4|aes|gcm/i.test(type)) return 'info';
return 'warning';   // ← assetType 是 "algorithm" 的，全部落这里
```

而扫描器给每个组件写的 `assetType` **恒为 `"algorithm"`**，它不匹配任何一条 `info` 正则，于是：

> **0.2.7 上，自己扫出来的 CBOM 里任何一个新增算法都至少是 `warning`（exit 2），永远到不了 exit 1。**

同一份 CBOM，两个版本的实测对比：

| 场景 | 0.2.7 | 0.2.8 |
|---|---|---|
| 新增 `SHA3-512`（hash，safe） | `🟡 warning` / exit 2 | `🟢 info` / exit 1 |
| 新增 `ChaCha20-Poly1305`（weak） | `🟡 warning` / exit 2 | `🟡 warning` / exit 2（本就应该如此） |

后果不是排版问题：门禁若写成「`exit 1` 放行、`exit 2` 拦截」，**「引入了一个新的安全算法」会被拦**，而真正该拦的「新增了一个弱算法」也是同一个码——两类事件分不开。

0.2.8 改成按 **`algorithmProperties.primitive`** 分级（`kem`/`signature`/`hash`/`xof`/`block-cipher`/`aead`/`stream-cipher` → `info`；`key-agree`/`key-derive`/`key-wrap`/`other` → `warning`），`assetType` 与组件名只做兜底。两个刻意的保留：

- **`vulnerable` 永远短路成 `critical`**，哪怕它的 primitive 看起来无害（RSA 的 `pke` 就是这种情况）；
- **`pke` 不被当作 `info`**：RSA 和 ML-KEM-768 共享这个 primitive，单看词无法区分安全与脆弱。

因此还有一条**仍然有效的边界**：语义未知、primitive 又是 `pke` 的组件，一律 `warning`——宁可让人看一眼，也不默默放过。

### 坑 2：包级推断是保守的，会多报

`@noble/post-quantum` 一条依赖，报出 `ML-KEM` / `ML-DSA` / `SLH-DSA` 三个族；`sm-crypto` 一条依赖，报出 `SM2` / `SM3` / `SM4` 三个。**它不知道你到底 import 了哪一个。**

对审计是好事（宁可多报），对"就绪度百分比"是坏事（分母虚高）。所以上面的 `readiness.cjs` 不用百分比，只数 `vulnerable` 的绝对个数。

### 坑 3：报告标题的路径会被截断

```
## CBOM Diff `C:\Users → C:\Users`
```

两个不同的文件都显示成 `C:\Users`。这是排版函数取路径时的截断问题（不影响任何判定，退出码照常）。在 CI 日志里看到别慌，但如果你把标题贴进工单，记得自己补上真实文件名。

---

## 8. 塞进 CI：三段式门禁

目标：**基线 diff 卡回归，全量扫描算就绪度，两者都失败才算失败**。

```yaml
name: cbom

on:
  pull_request:
  push:
    branches: [main]

jobs:
  cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      # 1) 扫当前分支
      - name: Scan this commit
        run: npx --yes cbom-tools@0.2.7 scan --dir . --out cbom-now.json

      # 2) 就绪度：vulnerable 必须为 0（存量期可加 --allow-vulnerable 并挂 TODO）
      - name: Quantum readiness gate
        run: node scripts/readiness.cjs cbom-now.json

      # 3) 回归门：和 main 上的基线比，新引入 vulnerable 直接红
      - name: Fetch the baseline
        if: github.event_name == 'pull_request'
        run: |
          git show origin/${{ github.base_ref }}:cbom-baseline.json > cbom-base.json 2>/dev/null || echo '{"components":[]}' > cbom-base.json

      - name: Regression gate
        if: github.event_name == 'pull_request'
        run: |
          set +e
          npx --yes cbom-tools@0.2.7 diff cbom-base.json cbom-now.json > diff.md
          rc=$?
          set -e
          cat diff.md >> "$GITHUB_STEP_SUMMARY"
          case $rc in
            0|1) exit 0 ;;          # 无变化 / 信息性变化
            2)   echo "::warning::CBOM warning (algorithm removed or new weak algorithm)"; exit 0 ;;
            3)   echo "::error::a quantum-vulnerable algorithm was newly introduced"; exit 1 ;;
            *)   echo "::error::cbom-diff could not run (rc=$rc)"; exit 1 ;;
          esac

      # 4) 合并后刷新基线
      - name: Refresh baseline on main
        if: github.event_name == 'push'
        run: cp cbom-now.json cbom-baseline.json
```

三个要点：

1. **`exit 2` 不要一律拦。** 删算法确实要人看，但它不该阻塞一次正常的迁移 PR——用 `::warning::` 让人看见，让人判断。
2. **`exit 3` 必须拦。** 这是唯一"新引入量子脆弱算法"的信号，也是整个工具存在的理由。
3. **基线要跟着 main 走。** 不然第一次扫描会把所有历史问题一次性点亮（见 §6 的两条推论）。

---

## 9. 一次完整迁移的时间线（把上面这些连起来）

| 步骤 | 命令 | 退出码 | 决策 |
|---|---|---|---|
| 1. 扫描存量 | `cbom-tools scan --dir . --out before.json` | 0 | 5 个算法，2 个 vulnerable |
| 2. 算就绪度 | `node readiness.cjs before.json` | 1 | 阻断：ECDH + SM2 必须进迁移计划 |
| 3. 改代码，重扫 | `cbom-tools scan --dir . --out after.json` | 0 | 5 个算法，0 vulnerable |
| 4. 出口校验 | `node readiness.cjs after.json` | 0 | 通过 |
| 5. 前后对比 | `cbom-tools diff before.json after.json` | 2 | 警告来自"删除 5 个"，人工确认兼容性 |
| 6. CI 基线门 | `cbom-tools diff cbom-base.json cbom-now.json` | 0/1/2 放行，3 拦截 | 防止 SM2 被重新引入 |
| 7. 归档 | 把 `after.json` 与 `before.json` 一起入库 | — | CBOM 是证据，diff 是叙事 |

---

## 10. 复现脚本

想要一个能跑的 demo，不必手抄上面三个目录：

```bash
mkdir -p demo && cd demo
# legacy / migrated / regressed 三个目录的源码见 §2，packages 同上
# migrated-sha512：在 migrated 基础上多一处 crypto.createHash('sha3-512')
npx cbom-tools scan --dir legacy         --out before.json
npx cbom-tools scan --dir migrated       --out after.json
npx cbom-tools scan --dir regressed      --out regressed.json
npx cbom-tools scan --dir migrated-sha512 --out after-sha512.json

node readiness.cjs before.json;  echo "exit=$?"   # 1
node readiness.cjs after.json;   echo "exit=$?"   # 0
npx cbom-tools diff before.json after.json;          echo "exit=$?"   # 2（删了算法）
npx cbom-tools diff after.json after-sha512.json;    echo "exit=$?"   # 1（新增安全算法）
npx cbom-tools diff after.json regressed.json;       echo "exit=$?"   # 3（重新引入 SM2）
npx cbom-tools diff after.json after.json;           echo "exit=$?"   # 0
npx cbom-tools scan --dir ./nope --out x.json;       echo "exit=$?"   # 2（没扫成）
```

---

## 11. 最后：这份清单能证明什么

- 能证明：**在扫描范围内、按这一版规则表，命中了哪些密码学调用，以及它们各自的行号**。
- 不能证明：这份代码里的密码学是完整的、安全的、合规的。

PQC 迁移真正难的不是"换成 ML-KEM"，而是**知道自己在换什么、换掉了多少、有没有漏**。CBOM 解决的是第二件事——把"我知道有哪些"从记忆变成可 diff 的文件。

规则表可扩展（`cbom-scan.cjs` 里的 source rules + `algo-metadata.json`），漏报时应当加规则，而不是在评审意见里写"我记得这里还有一处"。
