# fibemate-xdiff

ML-KEM-768 的确定性跨实现对拍工具：把随机源钉死，逐字节比较 `ek / sk / ct / ss`，并在报告里给出差异的根因定位。

对拍解决的是「两个实现都自称 FIPS 203，但互操作失败」这类问题：只看 roundtrip 都通过，看不出谁偏离了规范。把随机源换成确定的，字节才有可比性。

> 包名是 `fibemate-xdiff`，可执行文件名是 `xdiff`；两者不同属预期。

## 安装与运行

```bash
# 不安装直接跑
npx fibemate-xdiff run

# 或全局安装
npm i -g fibemate-xdiff
xdiff run
```

首次使用先落一份配置样例：

```bash
xdiff init                 # 生成 xdiff.json
xdiff list                 # 已注册实现及其可用性
xdiff run                  # 跑全套检查，写 .xdiff/
xdiff explain <findingId>  # 展开某条差异的完整细节
```

## 配置

`xdiff.json` 描述要对拍的实现和要跑的检查：

```json
{
  "version": 1,
  "algorithm": "ML-KEM-768",
  "sizes": { "pk": 1184, "sk": 2400, "ct": 1088, "ss": 32 },
  "params": { "k": 3, "eta1": 2, "eta2": 2 },
  "masterSeed": "<deterministic-seed>",
  "implementations": [
    { "id": "a", "type": "js-mlkem", "path": "${ROOT}/impl-a/ml-kem-768.js" },
    { "id": "b", "type": "noble-mlkem", "path": "${ROOT}/node_modules/@noble/post-quantum" },
    { "id": "c", "type": "liboqs-bridge", "path": "${ROOT}/xdiff/tools/oqsbridge", "enabled": false }
  ],
  "output": { "dir": ".xdiff", "failOn": "error" }
}
```

`path` 是**运行期输入**，指向本机的实现副本，不随包发布。`${ROOT}` 由配置里的根目录或环境变量代入，仓库内的样例配置不含任何绝对路径。

三种实现类型：

| type | 说明 |
|---|---|
| `js-mlkem` | 纯 JS 实现，导出 `keygen / encapsulate / decapsulate` |
| `noble-mlkem` | `@noble/post-quantum` 的 `ml_kem768`，作为独立第三方参照 |
| `liboqs-bridge` | liboqs C 实现，经 `tools/oqsbridge` 长期进程桥接（需自行编译，见下） |

## 检查项

| 检查 | 判据 |
|---|---|
| `lengthCompliance` | pk/sk/ct/ss 长度与规范一致 |
| `roundtrip` | 每个实现自身 keygen → encaps → decaps 一致 |
| `crossInterop` | A 封装、B 解封装；共享密钥逐字节相同 |
| `determinism` | 同种子两次运行输出完全相同 |
| `seedAlignment` | 随机消耗总量对齐后才做字节比对，未对齐本身即判失败 |
| `keySchedule` | 由 ρ 反推密钥派生根因（`standard` / `missingDomainSep` / `reversedOrder` / `unknown`） |
| `kat` | 对 NIST `.rsp` 向量逐条核验 |
| `katProvenance` | 向量是否真由该实现的 seed 派生，而非复制他处 |
| `katFileHygiene` | KAT 文件自身的结构、结尾与 provenance |
| `entropy` | 重复样本、低熵输出 |
| `implicitRejection` | 篡改密文必须走隐式拒绝，而不是抛错或返回明文 |
| `rngProfile` | 记录各实现消耗随机字节的形态（如 `[32,32]` 与 `[64]`） |
| `timing` | 各阶段耗时，仅作观测 |

## 判定与退出码

每条发现分三级：`error` 有客观答案的检查未通过；`warn` 可疑但可能合理；`info` 观察记录。

- `--fail-on error|warn|none` 决定哪一级导致非零退出（默认 `error`）
- 退出码：`0` 通过 · `1` 有达到阈值的问题 · `2` 配置或用法错误

## 输出

默认写入 `.xdiff/`，`--format text|md|json` 选择报告形态，`--out <file>` 指定路径，`--quiet` 只留结论。每条发现都有稳定 id，可用 `xdiff explain <id>` 展开。

## 为什么要对齐随机消耗

两个实现在 keygen 里抽取随机字节的形态常常不同：一个可能连抽两次 32 字节，另一个一次抽 64 字节。`[32,32]` 与 `[64]` 拿到的是同一段连续字节，所以**能否做字节级比对，看的是总量而不是形状**。总量不一致时直接判失败，而不是比较一个注定巧合相同的结果——否则「随机抽取顺序不同」会变成永久借口。

## 一个真实案例

对一个独立实现做对拍时，`ρ = SHA3-512(seed)` 的前 32 字节与 9 个候选输入逐一比对后唯一命中一项：它的密钥派生用了 `G(d)`，漏掉了域分隔符 `k`（`G(d‖k)`）。

修正这一处后 `keySchedule` 归位为 `standard`，但 pk 仍有 1148 字节不同，互操作仍失败。继续把 keygen 的矩阵索引改成标准顺序 `XOF(ρ‖j‖i)` 后，该实现自身的 roundtrip 从 24/24 掉到 16/24——说明它的 keygen 与 encaps 是成对自洽的（`A` 与 `Aᵀ` 互为转置），单点修改只会破坏内部一致性。结论是结构性偏离，需要按 FIPS 203 逐段核对，不是一行补丁。所有验证都在副本上进行，未改动源实现。

这类「单点修复让结果更差」正是跨实现对拍比单实现自测有价值的地方。

## 构建 liboqs 桥接

`tools/oqsbridge` 是 liboqs 的 CLI 桥接，**构建产物不入仓**，源码 `tools/oqsbridge.c` 顶部有说明：

```bash
gcc -O2 -o oqsbridge oqsbridge.c -I <liboqs>/include -L <liboqs>/lib -loqs
```

liboqs 0.16 移除了 `OQS_KEM_ml_kem_768_length_*` 这类静态符号，桥接改用 `OQS_KEM_new()` 动态取长度。若本机 liboqs 在构建时禁用了该算法，`OQS_KEM_new()` 返回 NULL，xdiff 会把该实现标为 `unavailable`——**不会假装它是可用的参考实现**。

## 限制

- 只覆盖 ML-KEM-768；其它参数集不在范围内。
- 字节比对要求随机消耗总量一致，做不到就只报对齐失败，不给「看起来相同」的结论。
- `timing` 是观测数据，不构成侧信道结论。
- liboqs 桥接需要自行编译，包内不含二进制。

## 许可

Apache-2.0。
