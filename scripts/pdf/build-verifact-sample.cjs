#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// build-verifact-sample.cjs
// Renders the verifact sample report to A4 HTML.
// See README.md in this directory for inputs and usage.
const fs = require('fs');
const path = require('path');

const argOf = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const dataDir = path.resolve(argOf('data-dir', path.join(__dirname, 'data')));
const outDir = path.resolve(argOf('out-dir', path.join(__dirname, 'out')));

const need = (name) => {
  const p = path.join(dataDir, name);
  if (!fs.existsSync(p)) {
    console.error('missing input: ' + p);
    console.error('pass --data-dir <dir>; the three snapshots are described in README.md');
    process.exit(2);
  }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
};

const fb = need('_fb.json').counts;
const lib = need('_liboqs-report.json').counts;
const ev = need('_ignore-drifts.json');
fs.mkdirSync(outDir, { recursive: true });

// 正文里的直引号统一成中文引号（只处理含中文的成对引号，属性值不受影响）
const cnQuotes = (s) =>
  s.replace(/"([^"<>]{1,60})"/g, (m, inner) => (/[\u4e00-\u9fff]/.test(inner) ? '\u201c' + inner + '\u201d' : m));

const css = `
@page { size: A4; margin: 18mm 16mm 26mm 16mm; }
* { box-sizing: border-box; }
body { font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif; color:#1b1f24; font-size:10.5pt; line-height:1.62; margin:0; }
h1 { font-size:22pt; margin:0 0 4mm; letter-spacing:-.2pt; }
h2 { font-size:13.5pt; margin:7.5mm 0 3mm; padding-bottom:2mm; border-bottom:1.2pt solid #d8dde3; }
h3 { font-size:11pt; margin:6mm 0 2mm; color:#2c3540; }
p, li { margin:0 0 2.2mm; }
small, .muted { color:#6b7684; font-size:8.6pt; }
.cover { padding-top:28mm; }
.cover .rule { height:3pt; background:#1b1f24; width:38mm; margin:6mm 0; }
.kicker { font-size:9pt; letter-spacing:2.4pt; color:#6b7684; text-transform:uppercase; }
.sub { font-size:12pt; color:#3a4552; margin-top:3mm; }
.meta { margin-top:16mm; font-size:9pt; color:#4a5563; }
.meta td { padding:1.4mm 6mm 1.4mm 0; vertical-align:top; }
table { width:100%; border-collapse:collapse; margin:3mm 0 4mm; font-size:9.2pt; }
th, td { border-bottom:.6pt solid #dde2e8; padding:1.6mm 2.4mm; text-align:left; vertical-align:top; }
th { background:#f4f6f8; font-weight:600; }
tr { break-inside: avoid; page-break-inside: avoid; }
h2, h3 { break-after: avoid; page-break-after: avoid; }
thead { display: table-header-group; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
.big { display:flex; gap:6mm; margin:5mm 0; }
.card { flex:1; border:1pt solid #dde2e8; border-radius:2mm; padding:4mm; }
.card .v { font-size:20pt; font-weight:700; font-variant-numeric:tabular-nums; }
.card .l { font-size:8.6pt; color:#6b7684; margin-top:1mm; }
pre { background:#f6f7f9; border-left:2.4pt solid #99a3ae; padding:3mm 4mm; font-size:8.2pt; line-height:1.5;
      font-family:Consolas,"Cascadia Mono",monospace; white-space:pre-wrap; word-break:break-all; }
.warn { background:#fff6f5; border-left:2.4pt solid #d0453a; padding:3mm 4mm; margin:3mm 0; }
.ok { background:#f3faf5; border-left:2.4pt solid #2f8a52; padding:3mm 4mm; margin:3mm 0; }
.tag { display:inline-block; font-size:8pt; padding:.4mm 1.6mm; border:.6pt solid #b9c2cc; border-radius:1.4mm; color:#4a5563; margin-right:1.4mm; }
.pb { page-break-before: always; }
footer { position:fixed; bottom:0; left:0; right:0; font-size:7.6pt; color:#8b95a1; text-align:center; }
`;

const now = '2026-10-30';
const f = (n) => String(n);

// ---------------- 报告一：样例扫描报告 ----------------
const libDocPct = ((lib.verified / Math.max(1, lib.claims)) * 100).toFixed(1);
const fbPct = ((fb.verified / Math.max(1, fb.codeArtifactClaims)) * 100).toFixed(1);

const driftRows = ev.map((r, i) =>
  `<tr><td>${i + 1}</td><td><code>${r.file}:${r.line}</code></td><td>${r.key}</td><td class="num">${r.doc}</td><td>${r.artifact}</td><td class="num">${r.score}</td></tr>`
).join('\n');
const driftRowsCount = ev.length;
const exemptionTotal = 19;

const report1 = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>${css}</style></head><body>
<div class="cover">
  <div class="kicker">Verifact · 数字溯源样例报告</div>
  <h1>文档里的每一个数字<br>都能指回一个产物吗？</h1>
  <div class="rule"></div>
  <p class="sub">对两个真实代码库的只读扫描：liboqs（第三方 PQC 参考实现）与 FIBEMATE（自有全栈仓库）。</p>
  <table class="meta">
    <tr><td>工具</td><td>@fibemate/verifact 0.2.4（Node.js，本地运行，无网络出站）</td></tr>
    <tr><td>扫描日期</td><td>${now}</td></tr>
    <tr><td>版本说明</td><td>本报告替代 2026-10-26 的 0.1.0 版；旧文件已从站点下线，避免两份数字并存。</td></tr>
    <tr><td>扫描方式</td><td>只读。不修改被扫描仓库，不写入任何属性，不上传任何内容。</td></tr>
    <tr><td>判定内容</td><td>文档写的值与产物里的值是否一致，以及两者各自的位置。</td></tr>
    <tr><td>不判定内容</td><td>哪一方"正确"；是否存在漏洞；安全性、合规性或性能优劣。</td></tr>
  </table>
</div>

<h2>一、为什么需要这件事</h2>
<p>工程文档里的数字——密钥长度、测试通过数、基准耗时、覆盖率——通常以三种状态存在：<b>能指回产物</b>、<b>指不回产物</b>、<b>根本不该被当作产物属性</b>。审阅者看到的是一段文字，无法区分这三者。</p>
<p>结果是两类错误同时发生：真数字因为找不到证据而被当作空话；假数字因为没人核对而长期存活。<b>问题不在于谁在撒谎，而在于没有账本。</b></p>

<h2>二、方法</h2>
<ol>
  <li><b>抽取</b>：从 Markdown 中抽出带数字的断言，给每条一个稳定标识（内容寻址，不是行号）。</li>
  <li><b>建索引</b>：扫描仓库产物（JSON/CSV/日志/报告/时间戳文件），建立可比较的形状索引。</li>
  <li><b>绑定</b>：按文件、键名、数值形状为每条断言寻找候选产物，记录相似度。</li>
  <li><b>判定</b>：一致为 <span class="tag">verified</span>，不一致为 <span class="tag">drift</span>，找不到为 <span class="tag">unbound</span>，多个候选为 <span class="tag">ambiguous</span>。</li>
</ol>
<p class="muted">关键设计：<b>"没有证据"和"不需要证据"必须分开</b>。作者可以声明某段是叙事、某次测量、或外部快照，但每一种豁免都必须署名并写明理由，没有名字的例外会让报告变成装饰。</p>

<h2>三、结果 A：liboqs（第三方，只读）</h2>
<p>liboqs 是 Open Quantum Safe 项目的 C 语言 PQC 库，是本领域的公共参考实现之一。扫描范围：仓库内全部 Markdown 文档 ${lib.docs} 个、产物 ${f(lib.artifacts)} 条。</p>
<div class="big">
  <div class="card"><div class="v">${f(lib.claims)}</div><div class="l">带数字的断言</div></div>
  <div class="card"><div class="v">${f(lib.verified)}</div><div class="l">可绑定到产物</div></div>
  <div class="card"><div class="v">${libDocPct}%</div><div class="l">绑定率</div></div>
  <div class="card"><div class="v">${f(lib.drift)}</div><div class="l">与产物不一致</div></div>
</div>
<p>该库的算法文档把参数写成表格，而对应的 <code>*.yml</code> 里存在同名的结构化定义，因此 24 条断言里有 ${lib.verified} 条可以逐条对上，例如：</p>
<pre>docs/algorithms/sig_stfl/xmss.md:43   xmssmt-sha2 = 20/2   →   docs/algorithms/sig_stfl/xmss.yml</pre>
<p>另外 ${lib.unbound} 条找不到可绑定产物，典型是治理文档里的表决比例（<code>2/3</code>）与构建说明里的开关默认值——它们不是代码产物的属性。这正是"不应被计入覆盖率"的一类，而不是"缺失证据"。</p>

<h2>四、结果 B：FIBEMATE（自有仓库）</h2>
<p>范围：按 <code>verifact.json</code> 全仓配置扫描 ${f(fb.docs)} 个文档、${f(fb.artifacts)} 条产物（含时间戳存证、形式化验证产物、基准输出）。<span class="muted">快照时间：2026-10-30 12:31；文档根覆盖 <code>fibemate</code>、<code>fibemate-tools</code>、<code>fibemate-core</code>，排除 <code>docs/pr-archive</code>、<code>CHANGELOG.md</code>、<code>scripts/</code> 与 <code>tools/</code>。</span></p>
<table>
  <tr><th>指标</th><th class="num">数值</th><th>说明</th></tr>
  <tr><td>抽取到的断言总数</td><td class="num">${f(fb.claimsTotal)}</td><td>含被分类、被忽略、被拒绑的条目</td></tr>
  <tr><td>进入判定的断言</td><td class="num">${f(fb.codeArtifactClaims)}</td><td>真正应当有产物的部分</td></tr>
  <tr><td>已验证</td><td class="num">${f(fb.verified)}</td><td>文档值与产物值逐条一致</td></tr>
  <tr><td>未绑定</td><td class="num">${f(fb.unbound)}</td><td>找不到产物——诚实记录，不隐藏</td></tr>
  <tr><td>候选冲突</td><td class="num">${f(fb.ambiguous)}</td><td>多个候选，需人工判定</td></tr>
  <tr><td>与产物不一致</td><td class="num">${f(fb.drift)}</td><td>本次为 0，门禁通过</td></tr>
  <tr><td>引用已定位（lg-XXX 等实体）</td><td class="num">${f(fb.refFound)}</td><td>声明引用的存证实体在扫描范围内找到</td></tr>
  <tr><td>已分类（非产物属性）</td><td class="num">${f(fb.dispositioned)}</td><td>叙事/进度/一次性测量，逐条署名</td></tr>
  <tr><td>哈希存证（不介入判定）</td><td class="num">${f(fb.sealed)}</td><td>TSA 盖戳文件，改一个字节即破坏存证</td></tr>
  <tr><td>标准编号（非度量）</td><td class="num">${f(fb.standardRefs)}</td><td>FIPS 203/205 之类，避免被当成比值</td></tr>
  <tr><td>显式豁免</td><td class="num">${f(fb.ignored)}</td><td>每条必须写明为什么不该核</td></tr>
</table>
<p><b>核验率按两个分母同时给出</b>：${fbPct}%（${f(fb.verified)}/${f(fb.codeArtifactClaims)}，只算应当有产物的）与 ${((fb.verified / fb.allJudgedClaims) * 100).toFixed(1)}%（${f(fb.verified)}/${f(fb.allJudgedClaims)}，含分类与拒绑）。只报一个数就是选择性地好看。</p>
<p class="muted">口径说明：<code>claimsTotal</code> 含被分类、被忽略与被拒绑的条目，所以它与 <code>codeArtifactClaims</code> 不等；两个百分比的分母不同，不可互相引用。本节即全仓口径，与 2026-10-26 那份 <code>docs/</code> 子集快照（314 条断言）不是同一分母，不构成趋势比较。</p>

<h2>五、门禁有没有牙：一次真实的红</h2>
<p>下面不是构造的演示，而是移除配置里全部 19 条豁免后，工具在同一仓库上给出的真实输出（退出码 1）：</p>
<div class="warn"><b>门禁 FAILED</b>：${f(driftRowsCount)} 条声明与产物不一致。四条是把 Node.js 基准的数字绑到了硬件基线（262µs），另外两条是绑定对象本身找错了（em-dash 计数、BKZ 成本）。</div>
<table>
  <thead><tr><th>#</th><th>位置</th><th>键</th><th class="num">文档值</th><th>绑定到的产物</th><th class="num">相似度</th></tr></thead>
  <tbody>
  ${driftRows}
  </tbody>
</table>
<p>这 ${f(driftRowsCount)} 条此前被豁免静默排除。<b>移除豁免并不会制造问题，它只是让问题可见</b>。恢复豁免后门禁重新变绿，但每一条豁免都必须写明：为什么不该核、指向哪里、何时应当删除。</p>
<p class="muted">口径：\u5171 ${f(exemptionTotal)} 条豁免中，${f(driftRowsCount)} 条在移除后表现为 drift；其余 ${f(exemptionTotal - driftRowsCount)} 条仍属"口径不同"或"非产物属性"，保留豁免。上表不是"19 条全有问题"。</p>
<div class="ok"><b>结论</b>：这个工具的价值不在于"报告很绿"，而在于它能证明自己会红，并且红得有据可查。</div>

<h2>六、这份报告不主张什么</h2>
<ul>
  <li>不判定数字背后的实现是否正确，也不构成安全评估或合规结论。</li>
  <li>"已验证"仅表示文档值与某个产物值一致；如果产物本身是伪造的，它同样一致。</li>
  <li>"未绑定"不代表有错，只代表账本上没有对应条目。</li>
  <li>扫描只读、本地运行；本报告不包含任何被扫描仓库的源代码。</li>
</ul>
<p class="muted">工具与规则均为开源实现，判定逻辑、豁免理由、门禁策略都在仓库内可复核。</p>
<footer>verifact 0.2.4 · 样例报告 · ${now} · 只读扫描</footer>
</body></html>`;

const outFile = path.join(outDir, 'verifact-sample-report.html');
fs.writeFileSync(outFile, cnQuotes(report1), 'utf8');
console.log('wrote ' + outFile + ' (' + fs.statSync(outFile).size + ' bytes)');
