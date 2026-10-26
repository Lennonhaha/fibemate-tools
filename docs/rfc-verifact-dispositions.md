# RFC: 处置分类（Dispositions）—— 让 verifact 区分「没有证据」与「不适用证据」

- Status: Partially implemented（Phase 1 合并于 2026-10-26 `0756c92`；Phase 2 因 #96 暂缓；第五类未实现）
- Date: 2026-10-26（同日增补 `external-snapshot` 与已知限制，见 §2.1.1、§4.1.1、§9）
- Author: 刘天赫 `<research@fibemate.net>`
- Applies to: `verifact/` 0.1.x
- Related: `VERIFACT-DESIGN.md` §五（ignore / deny）、#95、#96、#97
- Tracking issue: #92

---

## 0. TL;DR

现状：285 条受判声明里,`verified` 19 条,核验率 **6.7%**;`unbound` 214 条。但 214 条里很大一部分并不是「缺证据」,而是**verifact 没有词汇说出「这条不是产物属性」**:

- `measure` 类 99 条,只有 2 条可核验 —— 性能数字本质上是**某一次运行的测量**,不是「当前代码的属性」;
- `ratio` 类 116 条,大量是 `0/28`、`199/199` 这种**清单进度**,不是比值声明;
- `kv` 类 82 条,大量是 `n=40, q=1009` 这种**实验参数**,属于叙事。

**提议**:引入 `disposition`(处置分类),四个取值 `code-artifact`(默认)、`measured-once`、`progress`、`narrative`,以及 2026-10-26 增补的第五类 `external-snapshot`(外部服务拥有的数字,§2.1.1)。非 `code-artifact` 的声明**不计入覆盖率分母,但仍然被计数、被打印、被可见**;并且每一种豁免都必须**指名这个数字由谁拥有**,否则解析即报错。

**一句话边界**:本 RFC 不会把 6.7% 变成 60%。它只会把**误导性的 6.7%** 变成**诚实的、更小的分母**。真正的覆盖率要靠把性能数字绑到基准产物上(本 RFC 之后的 A 项工作)。

---

## 1. Motivation(动机)

### 1.1 实测数据(2026-10-26,`--format json` `--no-cache`)

```
docs 32   artifacts 4851   claims(受判) 285   ignored 29
verified 19 (6.7%)   drift 0   ambiguous 51   unbound 214   ref-found 1
```

按 kind × status 拆开:

| kind | 总数 | verified | ambiguous | unbound | ignored |
|---|---:|---:|---:|---:|---:|
| `measure` | 99 | 2 | 21 | 48 | 28 |
| `ratio` | 116 | 14 | 25 | 76 | 1 |
| `kv` | 82 | 3 | 4 | 75 | 0 |
| `count` | 13 | 0 | 1 | 12 | 0 |
| `loc` / `ref` | 4 | 0 | 0 | 3 | 0 |

`unbound` 的**原因**分布(这是关键,不是"214 条都缺测试"):

| reason | 数量 |
|---|---:|
| `no_artifact_entry` | 137 |
| `below_score_threshold` | 39 |
| `no_comparable_shape` | 35 |
| `loc_file_not_in_scope` | 2 |
| `resolution_disabled` | 1 |

Top 文件:`performance-benchmarks-2026-07-18.md`(90 条,其中 52 unbound)、`TECHNICAL-VERIFICATION.md`(39/29)、`vwz-lwe-reduction-gaps.md`(26/25)、`tsa/2026-07-17-lg-gen/lg-075-README.md`(25/18)、`status-2026-10.md`(19/14)、`SECURITY-AUDIT-CHECKLIST.md`(24/12)。

### 1.2 三种数,verifact 只有一种处理方式

| 文档里的数 | 真实身份 | 今天的结果 | 应当的处置 |
|---|---|---|---|
| `0/28`、`199/199` | 清单进度 | `unbound`(永远绑不上) | `progress` |
| `7.8µs`、`5ms` | 某次基准的测量 | `unbound` 或 `ambiguous` | `measured-once` |
| `n=40, q=1009, β=2~20` | 实验参数 | `unbound` | `narrative` |
| `103µs`(当前实现 keygen) | 代码属性 | `verified` / `drift` | `code-artifact`(默认) |

第三行不是失败,是**工具没有第三种答案**。当工具只会说「找不到依据」时,文档作者唯一能做的动作就是:编一个假绑定。**这正是我们要避免的**。

### 1.3 为什么现有的 `ignore` 不够

`ignore` 已经存在(`VERIFACT-DESIGN.md` §五),当前配置里有 29 条。它解决的是**「同一个数字,两份产物口径不同」**,不是「这条数字压根不是产物声明」。拿它兜 214 条会有三个问题:

1. **集中式配置不成比例**:`verifact.json` 已 8.8 KB,再塞 214 条会变成垃圾桶,且没有评审视野。
2. **意图与句子分离**:读者看 `status-2026-10.md` 的 `0/28` 时,永远不会知道它在某份 8 KB 的 JSON 里被豁免了。豁免必须是**就地可见**的。
3. **语义混淆**:`ignore` 现在同时承担了两种完全不同的意思 —— 「比较器口径不对,别用它判」和「这根本不是产物声明」。前者是工具的问题,后者是声明者的声明。**混在一起的代价是审计时无法区分。**

### 1.4 四者的分工(本 RFC 的核心区分)

| 机制 | 回答的问题 | 谁说了算 | 计入分母 |
|---|---|---|---|
| `code-artifact`(默认) | 这个数字能不能绑到产物 | 工具 | 是 |
| `ignore` | 绑上了,但口径不同,别用这条判 | 复核人(集中配置) | 是(仍受判) |
| `deny` | 结构上就不该比(如对照列) | 复核人 | 是(仍受判) |
| **`disposition`** | **这个数字压根不是产物属性** | **声明者(就地)** | 否 |

---

## 2. Proposed Solution(提议方案)

### 2.1 四种 disposition + 增补第五类

| disposition | 含义 | 绑定要求(必须指名拥有者) | 进分母 |
|---|---|---|---|
| `code-artifact` | 默认,今天的全部行为 | 无 | 是 |
| `measured-once` | 某次运行/某次构建的测量值 | **必须** `artifact=<path>`,且该产物存在;`since=<date>` 建议 | 否 |
| `progress` | 清单/看板的进度统计 | **必须** `owner=<path or issue url>` | 否 |
| `narrative` | 实验参数、外部引用、描述性数字 | **必须** `why="<一句话>"` | 否 |
| `external-snapshot` | 外部服务（Scorecard / 告警数 / 覆盖率）的当前值 | **必须** `source=<命令或 URL>`；`asof=<date>` 建议 | 否 |

`measured-once` 保留一件事:**产物存在性仍然检查**。缺产物的 `measured-once` 不是「豁免」,是**红**(`broken-disposition`),因为它在声称「我有出处」。

### 2.1.1 `external-snapshot`(2026-10-26 增补)

`status-2026-10.md` 里有一整片数字既不属于产物,也不由我们产生:OpenSSF Scorecard `8.1 / 10` 与那张子项表、
Dependabot / CodeQL 的开放数、ACVP 覆盖。共同特征:

- 数字的所有者是**外部服务**,不是本次构建;
- 文档本身已写清复核命令(`curl api.securityscorecards.dev/...`、`gh api .../alerts`);
- 仓里**没有也不该有**对应产物 —— 有产物反而是抄了一份注定过期的快照。

所以它既不能 `measured-once`(要求 `artifact=`),也不该 `progress`(那是看板进度,硬套等于给外部评分发豁免)。

判据不是「产物索引里有没有」,而是「照 `source` 重跑一遍,能不能得到同一个数」。
写成 `source=` 的必须是**一条可执行命令或一个稳定 URL**,不能是一句描述。

**明确它不做什么**:verifact 无出站网络(§8),因此它**不代为复核**。这条 disposition 只做一件事:
把一个「我们控制不了、但能复核」的数字,与其复核方式绑在一起,并移出「本该由代码证明」的分母。
真正判定它是否过期是另一个工具的活(读 `source`、对比、报 `stale-external`)。

**实现状态:本条未实现(Phase 4)。** 当前解析器遇到 `external-snapshot` 会 fail closed
(`未知 disposition="external-snapshot"`),这是正确行为 —— 不要为了试用去放宽解析器。
实现时需要一并处理 `source="..."`:它包含空格与 `:`、`/`,必须走带引号的参数解析(与 `why="..."` 同一条路径)。

### 2.2 反洗白条款(anti-laundering)

Disposition 的天然风险是被用来把「没证据」改名成「不需要证据」。所以以下七条是硬性的:

1. **无 note / 无 owner / 无 why → 解析错误**,不是静默通过。
2. **未知 disposition 值 → 错误**(fail closed)。拼错的 `narrativ` 不允许被当成 `narrative`,也不允许退化成默认值。
3. **`begin` 区域没有 `end` → 错误**,不允许「一直延伸到文件末尾」这种善意推断。
4. **整份文档 100% 都是非 `code-artifact` → 报告里单列警示**(`all-narrative file`),因为那通常意味着这份文档不该被扫。
5. **全部声明中非 `code-artifact` 占比 > 50% → 报告顶部警示**。这个数是有意义的健康指标:一个仓库如果一半以上的硬数字都不针对产物,那它的问题不在 verifact。
6. **`progress` 的 `owner` 可以继承,但不可以缺席**。单条 `disposition=progress` 未写 `owner=` 时,继承所在 `region` 在 `begin` 声明的 `owner=`;单条与区域都没有 → **报错**。写清单的人只需在区域头写一次 owner,不必逐条重复,但「无主数字」永远不被接受。
7. **只有 `owner` 可以继承**。`artifact` / `since` / `why` 必须就地声明 —— 它们是逐条不同的事实,继承会把「每条都有自己的出处」变成「整个区域共用一句借口」。
8. **`external-snapshot` 必须给非空 `source=`**,且不得是自然语言描述。没有复核方式的「外部数字」等于不可复核的外部数字,按报错处理。

### 2.3 报告形态:双数并列,永不折叠成一个数

```
claims 285  (code-artifact 161, progress 42, measured-once 52, narrative 30)
verified 19   coverage 11.8% of code-artifact claims   (6.7% of all claims)
drift 0   ambiguous 51   unbound 214
```

规则:**覆盖率永远打印两个分母**。只打印「覆盖率上升了」而没有说明分母变了,是本 RFC 明令禁止的汇报方式。CI 门禁(默认 `--fail-on drift`)行为不变 —— disposition 不改变「红只留给 drift」的立场。

---

## 3. Implementation Details(实现细节)

### 3.1 语法:HTML 注释,三种作用域

选 HTML 注释的理由:GitHub 渲染不可见、不影响阅读、`git grep` 可查、不污染正文、不依赖 markdown 扩展。

**文件级**(必须出现在文件前 5 行内):

```markdown
<!-- verifact: disposition=narrative why="7/31 的 LLL / BKZ 实验快照,参数属实验记录" -->
```

**区域级**(必须成对,显式 `end`):

```markdown
<!-- verifact: begin disposition=measured-once artifact=<产物路径，必须存在> since=2026-07-18 -->
... 52 条基准数字 ...
<!-- verifact: end -->
```

区域头也可以携带 `owner=`,供区域内的单条 `progress` 继承(见 §2.2 规则 6、7):

```markdown
<!-- verifact: begin disposition=progress owner=docs/SECURITY-AUDIT-CHECKLIST.md -->
| 合计 | 199/199 | ✅ |
| 元数据 | 8/10 | ⚠️ |
<!-- verifact: end -->
```

外部服务拥有的数字(§2.1.1):

```markdown
<!-- verifact: begin disposition=external-snapshot source="curl -s https://api.securityscorecards.dev/projects/github.com/Lennonhaha/fibemate" asof=2026-10-25 -->
- 主仓 OpenSSF Scorecard **8.1 / 10**
<!-- verifact: end -->
```

**单条级**(写在同一行尾,或紧邻的上一行):

```markdown
| **合计** | **199/199** | | **✅ 全绿** | <!-- verifact: disposition=progress owner=docs/SECURITY-AUDIT-CHECKLIST.md -->
```

区域可以嵌套同种 disposition,但**不允许嵌套不同 disposition**(歧义无法消解,直接报错)。

**被否决的语法**:

| 方案 | 否决理由 |
|---|---|
| 正文前缀 `(progress) 0/28` | 可见噪音,污染文档;而且作者会忘 |
| YAML front-matter | 只能整文件,拿不到区域粒度;且与站点渲染器耦合 |
| 只在 `verifact.json` 里配 | 见 §1.3:意图与句子分离 |
| `\<!-- verifact:ignore --\>`(无参数) | 无法区分四种情况,等于把问题藏起来 |

### 3.2 解析位置

`src/core/claims.js` 的 `extractClaims` 已经有 fence 状态机(跳过代码块)。新增一个**同层**的 disposition 栈:

- 逐行扫描时优先匹配 `<!-- verifact: ... -->`;
- 命中 `begin` → push;命中 `end` → pop(空栈 pop 报错);
- 命中 file/inline → 记在 `pendingByLine` 上;
- 每条 claim 落盘时,按 `region 栈 > inline > file > config` 决定 `disposition` 与 `dispositionSource`;
- EOF 时栈非空 → 错误。

注释行本身不参与数字抽取(现有 `stripNoise` 已处理),所以不会自我命中。

### 3.3 判定流水线插入点

`src/engine.js`:

1. `extractClaims` 后立刻打标签 —— 在 `resolveClaim` **之前**,不是之后。先判「要不要判」,再判「判什么」。
2. 非 `code-artifact` 的 claim 跳过 `resolveClaim`,直接以 `disposition` 状态入结果集。
3. `stats` 增加 `codeArtifact`、`dispositionCounts{}`、`allNarrativeFiles[]`、`brokenDispositions[]`。
4. `evaluateGate` **不改**:`drift` 仍然是唯一的红;`broken-disposition` 建议也归红(它是一条假声明)。

### 3.4 数据模型

```json
{
  "id": "docs/performance-benchmarks-2026-07-18.md:L45:measure:keygen",
  "disposition": "measured-once",
  "dispositionSource": "region",
  "dispositionAt": 42,
  "dispositionArgs": { "artifact": "docs/bench/2026-07-18.json", "since": "2026-07-18" },
  "status": "measured-once"
}
```

`dispositionAt` = 声明该 disposition 的行号,`verifact explain <id>` 直接指过去。审计时能回答「谁豁免了它、在哪一行豁免的」,这是 `ignore` 今天做不到的。

### 3.5 优先级与冲突

```
deny  >  disposition  >  ignore  >  正常判定
```

理由:`deny` 是结构性的(对照组不能比),优先于任何作者声明;`disposition` 是作者对「这是什么数」的声明,优先于复核人针对口径的 `ignore`(如果作者说它压根不是产物声明,口径问题不存在)。

### 3.6 迁移(29 条既有 `ignore`)

写一次性脚本 `scripts/migrate-ignore-dispositions.cjs`,逐条打印并人工判定:

- 口径不同但仍是产物属性(如 JS 基准 vs 硬件基准)→ **保留 `ignore`**;
- 结构对照列 → **保留 `deny`**;
- 非产物属性 → **转成 `narrative` / `progress`**,并把 note 原文搬进 `why`。

迁移完成后 `ignore` 条目应显著减少。**减少本身是验收标准**:如果迁移后 `ignore` 还很多,说明 §1.4 的区分没被真正理解。

### 3.8 禁止推断(不可协商)

`ratio` 的语义**不得**由形状、上下文或邻近文本推断:

- `3/5` 在形状上永远是 `3/5`:它可能是「5 个样本过了 3 个」(真声明),也可能是进度 3/5。**形状里没有这个信息。**
- 任何基于形状的推断,都会在某个边界产生假阳性或假阴性。本项目已经在两个同族问题上各栽过一次:宽松构建让 `sorry` 假绿(`quick_and_dirty`),`version || 0` 把「缺失」折叠成「显式默认值」(cbom-diff)。**「看起来对」的自动推断,是假绿的主要来源。**
- **规则**:缺声明 → 按默认 `code-artifact` 判定;绑不上 → 留在 `unbound`,由作者决定「补声明」还是「补证据」。工具不猜。
- 同族禁令:`measure` 不因为「看起来像基准数字」就自动降级为 `measured-once`;`kv` 不因为「长得像实验参数」就自动归 `narrative`。

这条规则的作用,是给未来每一次「要不要让工具自动识别进度」的讨论一个**否决依据**,而不是一句「应尽量避免」。

---

## 4. Impact Analysis(影响分析)

### 4.1 定量:disposition 不会买来覆盖率

拿今天的真实数据做一次**文件级**最粗的试算(把三个状态文档 + 一个基准报告整份标为非 `code-artifact`):

| | 分母 | verified | 覆盖率 |
|---|---:|---:|---:|
| 今天 | 285 | 19 | 6.7% |
| 文件级 disposition 后 | 161 | 12 | 7.5% |
| 差值 | −124 | −7 | **+0.8 pt** |

**结论要写在这里,不许含糊**:换标签只挪了 0.8 个百分点。6.7% 的真相是「只有 19 条数字真的绑上了产物」,不是「分类分错了」。

> **引用约束(写入本 RFC,对引用者生效)**:任何人引用本 RFC 时,不得把 6.7% → 7.5% 描述为覆盖率改善。真正的缺口在 `measure`:99 条中只有 2 条可核验。本 RFC 解决的是「分母里混入了不该计入的数字」,**不是**「数字被证明的程度」。

真正的杠杆在别处:`measure` 类 99 条里只有 2 条可核验 —— 说明**基准产物的键名和文档的键名对不上**,或产物根本没导出成机器可读格式。那是 A 项的活,不是 B 项的。

#### 4.1.1 修正(2026-10-26,实测后)

上面「文件级 disposition 后 161 条 / 7.5%」那一行**建立在错误假设上,已作废**:
它假设那四份文档整份都不是 `code-artifact` 声明。实际打开看不是 —— 它们大多是**真声明、只是缺产物**
(基准页 52 条测量、校验页 29 条 `N=5,000` 的 TVLA 样本量)。真正整份叙事的只有两份文档,实测:

| | 分母 | verified | 覆盖率 |
|---|---:|---:|---:|
| 标注前 | 285 | 19 | 6.7% |
| 标注后(两份文档) | 247 | **18** | **7.3%** |

注意 verified 19 → 18:移出的 38 条里有 **1 条本来是 verified**(`ok-e2e = 31/31`)。
所以 6.7% → 7.3% 是**分子减少 + 分母减少**共同造成的比值变化,**连「0.8 pt 的诚实提升」都算不上,是纯分母效应**。

结论更新:**B 项不会带来任何覆盖率改善。** 它的收益只有两条:报告不再把「不适用证据」算成「缺证据」,
以及每条豁免都带名字。

### 4.2 定性收益

| 收益 | 说明 |
|---|---|
| 报告可信 | 6.7% 变成「19/161,另有 94 条已声明为非产物属性」,两个数都能被审 |
| 减少假绑定冲动 | 作者有了合法出口,不必为了指标去写假断言 |
| 审计可追溯 | 每条豁免带行号与理由,集中在报告里可枚举 |
| 把问题分给对的人 | 「缺产物」归工程,「不适用」归作者,不再是同一堆 unbound |

### 4.3 风险与缓解

| 风险 | 缓解 |
|---|---|
| 滥用 disposition 洗白没证据的数字 | §2.2 五条硬规则 + `broken-disposition` 归红 |
| 解析器自己出 bug 导致静默放过 | 与 `count-obligations.cjs` 同法:**变异测试** —— 故意拼错 disposition 值、删掉 end 标记,测试必须变红 |
| 旧缓存/旧 JSON 消费方缺字段 | JSON 只增字段,不改既有字段;`schema` 版本号 +1 |
| CI 行为漂移 | `--fail-on drift` 语义不变;新状态不进默认门禁 |

### 4.4 工作量

| 项 | 估计 |
|---|---|
| `claims.js` disposition 解析(栈 + 参数) | ~120 行 |
| `engine.js` 分流 + stats | ~40 行 |
| 测试(成对用例:该豁免/不该豁免) | 12 例 |
| 迁移脚本 + 29 条人工判定 | 半天 |
| 文档(`VERIFACT-DESIGN.md` §五改写 + README 局限节) | 半天 |

---

## 5. Alternatives Considered(备选方案)

**A. 只扩 `ignore` 配置。** 否决:集中配置、意图与句子分离、语义混在一起(§1.3)。

**B. 降低 `minScore` 或放松容差,让更多 claim「绑上」。** 否决,而且是最危险的:它会把真的 unbound 变成假的 verified。**假绿比红灯贵得多。**

**C. Markdown front-matter 声明整文件。** 部分采纳:文件级需求真实存在,但 front-matter 与站点渲染耦合,HTML 注释同样能做到且不引依赖。

**D. 不做 disposition,直接删掉这些段落。** 否决:基准报告和状态文档有独立价值(它们记录的是历史),删掉是**销毁证据**,不是治理。

---

## 6. Decisions and Open Questions(裁决与待议)

**已裁决(2026-10-26)**

1. **`progress` 的 `owner` 强制,通过区域级声明 + 单条继承来平衡易用性**(§2.2 规则 6、7)。只在整个区域写一次 `owner`,下面的条目自动继承;单条与区域都缺 → 报错。守住了「无主数字不能存在」,又没让写文档变成重复劳动。
2. **`ratio` 必须显式声明,禁止推断**(§3.8)。缺声明 → 默认 `code-artifact`;绑不上 → 留在 `unbound`。解析器不得依据数值形状、上下文或邻近文本推断语义。
3. **`expires` 不纳入 disposition**。新鲜度检查是独立机制,读 `measured_at` / `source_artifact`(允许但不强制),不由 disposition 的取值变化触发。理由:一旦 `expires` 能让 CI 变红,最省力的做法就是把 `measured-once` 改成 `narrative` 消红,而不是去重测 —— 那是标准的指标腐化路径。
4. **增补第五类 `external-snapshot`**(2026-10-26,§2.1.1)。分数/告警数/覆盖率的拥有者在外部服务,且文档已给出复核命令;塞进 `measured-once` 或 `progress` 都会污染那两类的语义。**实现待做。**
5. **drift 历史不能用 `id` 比对**(2026-10-26)。`id` 含行号,插一行注释即全文件改名,`diffRuns` 会把纯排版改动读成大规模迁移(#96)。稳定键是 Phase 2 的前置条件,不是可选项。

**仍待议**

4. `narrative` 占比超过多少该红?现在提议 50% 只**警示**不红。要不要进 CI?

---

## 7. Rollout(落地顺序)

1. **Phase 1(已完成,`0756c92`)**:解析 + JSON 字段 + 报告双数并列。当时所有声明默认 `code-artifact`,314 条声明逐条比对 0 差异。
2. **Phase 2(暂缓)**:迁移 29 条 `ignore`;加 `brokenDispositions`(缺产物的 `measured-once`)。**前置条件:稳定 claim 键(#96)** —— 否则标注动作本身就在制造假迁移。
3. **Phase 3(部分完成,#97)**:§2.2 第 4、5 条警示已实现(整文件全非 `code-artifact` 单列;占比 > 50% 顶部警示)。
4. **Phase 4(待做)**:实现 `external-snapshot`;决定 `broken-disposition` 是否进 CI。

每一步都可单独回退:disposition 是增量字段,删掉注释即回到今天的行为。

---

## 8. Non-goals(不做什么)

- 不做 AST:立场不变(见 `VERIFACT-DESIGN.md` §四)
- 不自动改文档:verifact 只报,不改
- 不追溯 git 历史:disposition 只描述当前文件
- **不提高覆盖率数字**:本 RFC 只让分母诚实

---

## 9. 已知限制(实测发现,2026-10-26)

1. **没留下产物的基准页无法诚实标 `measured-once`**。`performance-benchmarks-2026-07-18.md` 的 52 条测量,
   那一次运行没有导出机器可读结果,`artifact=` 无从指。只剩两条路:今后基准必须提交输出产物;
   或标 `narrative` —— 而后者会触发 §2.2 第 4 条警示。**那是设计意图,不是缺陷。**
2. **TSA 存证目录永远不能标注**。`www/docs/tsa/**` 里有些文件本身就是被时间戳的对象(`lg-075-README.md`),
   插注释会改哈希、破坏存证。这里只能靠 config 层 scope 排除,不能靠 disposition。
3. **claim 的 `id` 含行号**(`src/core/claims.js:254`),插注释会让整份文件的 id 改名,drift 历史被造假迁移(#96)。
   所以 Phase 2 的第一步是稳定键,不是标注释。
4. **一般抽取崩溃仍被降级成计数**(`src/pooled-scan.js`,#95):文档整份解析失败时声明数变少、报告仍绿。
   处置声明写错已经是 fatal,一般抽取崩溃还不是。
