#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// build-fibemate-intro.cjs
// Renders the project brief to A4 HTML.
// See README.md in this directory for inputs and usage.
const fs = require('fs');
const path = require('path');

const argOf = (name, fallback) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const dataDir = path.resolve(argOf('data-dir', path.join(__dirname, 'data')));
const outDir = path.resolve(argOf('out-dir', path.join(__dirname, 'out')));

const countsFile = path.join(dataDir, '_fb.json');
if (!fs.existsSync(countsFile)) {
  console.error('missing input: ' + countsFile);
  console.error('pass --data-dir <dir>; the snapshot is described in README.md');
  process.exit(2);
}
const fb = JSON.parse(fs.readFileSync(countsFile, 'utf8')).counts;
fs.mkdirSync(outDir, { recursive: true });
const f = (n) => Number(n).toLocaleString('en-US');

// 正文里的直引号统一成中文引号（只处理含中文的成对引号，属性值不受影响）
const cnQuotes = (s) =>
  s.replace(/"([^"<>]{1,60})"/g, (m, inner) => (/[\u4e00-\u9fff]/.test(inner) ? '\u201c' + inner + '\u201d' : m));

const css = `
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
* { box-sizing: border-box; }
body { font-family:"Microsoft YaHei","PingFang SC",sans-serif; color:#1b1f24; font-size:10.5pt; line-height:1.66; margin:0; }
h1 { font-size:23pt; margin:0 0 3mm; letter-spacing:-.3pt; }
h2 { font-size:13pt; margin:8mm 0 3mm; padding-bottom:2mm; border-bottom:1.1pt solid #d8dde3; }
h3 { font-size:10.8pt; margin:5mm 0 1.6mm; }
p,li { margin:0 0 2.2mm; }
small,.muted { color:#6b7684; font-size:8.6pt; }
.cover { padding-top:26mm; }
.kicker { font-size:8.8pt; letter-spacing:2.6pt; color:#6b7684; }
.rule { height:3pt; background:#1b1f24; width:34mm; margin:6mm 0; }
.sub { font-size:11.6pt; color:#3a4552; }
table { width:100%; border-collapse:collapse; margin:3mm 0; font-size:9.2pt; }
th,td { border-bottom:.6pt solid #dde2e8; padding:1.9mm 2.2mm; text-align:left; vertical-align:top; }
th { background:#f4f6f8; font-weight:600; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
pre { background:#f6f7f9; border-left:2.4pt solid #99a3ae; padding:2.6mm 3.6mm; font-size:8.2pt; font-family:Consolas,monospace; white-space:pre-wrap; word-break:break-all; }
.note { background:#f7f8fa; border-left:2.4pt solid #6b7684; padding:3mm 4mm; margin:3mm 0; }
.bad { background:#fff6f5; border-left:2.4pt solid #d0453a; padding:3mm 4mm; margin:3mm 0; }
.pb { page-break-before: always; }
`;

const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>${css}</style></head><body>

<div class="cover">
  <div class="kicker">FIBEMATE · 项目简介</div>
  <h1>让工程文档里的每个数字<br>都有据可查</h1>
  <div class="rule"></div>
  <p class="sub">一套可复现的后量子密码工程参考实现，以及围绕它的证据链工具。<br>目标不是"声称安全"，而是让"声称"可以被逐条复核。</p>
  <p class="muted" style="margin-top:14mm">版本：2026-10 快照　·　联系：research@fibemate.net　·　代码：github.com/Lennonhaha</p>
</div>

<h2>一、我们要解决的问题</h2>
<p>在密码工程与安全评审中，最常见的失效不是算法被攻破，而是<b>文档与实现之间没有任何可执行的对应关系</b>：文档写"10,000 次交叉验证通过"，实现里找不到那 10,000 次的输出；文档写"常数时间"，代码里没有任何时序检测记录。</p>
<p>审阅者因此只有两个选择：相信，或者不信。两者都不专业。我们做的是第三种：<b>把每个数字指回一个产物，把指不回去的明确标出来。</b></p>

<h2>二、三个可独立复核的交付物</h2>

<h3>1. 后量子密码参考实现（ML-KEM / ML-DSA 及衍生方案）</h3>
<p>JavaScript、C、WebAssembly、FPGA 四端实现与跨语言互操作验证；KAT/TVLA 测试向量入库；算法参数、序列化格式、边界条件有对应测试。定位是<b>互操作与教学用的参考实现</b>，不是经认证的密码模块。</p>

<h3>2. 数字溯源工具 verifact（本次样例报告的对象）</h3>
<p>只读扫描代码库文档，抽出带数字的断言，逐条绑定到仓库内产物，输出"一致 / 不一致 / 无产物 / 多候选"四态账本，并作为 CI 门禁运行。<b>它不判断谁对，只判断"能不能对上"和"对上了没有"。</b></p>

<h3>3. 形式化验证与时间戳存证</h3>
<p>关键协议不变量以 Isabelle 建模并给出机器可检的证明义务账本；发布物用 RFC 3161 时间戳（TSA）固定，任何人可用公开哈希复核。存证文件本身禁止被注释修改——工具对这类目录设有独立的"哈希存证"类别。</p>

<h2>三、当前状态：数字，含不好看的那些</h2>
<p class="muted">FIBEMATE 样本扫描快照 · 2026-10-26 14:16 · 范围：仓库 <code>docs/</code> 目录（32 个文档）。</p>
<table>
  <tr><th>项目</th><th>实测值</th><th>说明</th></tr>
  <tr><td>文档中的数字断言</td><td class="num">${f(fb.claimsTotal)}</td><td>含叙事、存证、豁免条目</td></tr>
  <tr><td>应当有产物的断言</td><td class="num">${f(fb.codeArtifactClaims)}</td><td>覆盖率的分母</td></tr>
  <tr><td>逐条绑定成功</td><td class="num">${f(fb.verified)}</td><td>${((fb.verified / fb.codeArtifactClaims) * 100).toFixed(1)}%（${f(fb.codeArtifactClaims)} 分母）</td></tr>
  <tr><td>暂无产物</td><td class="num">${f(fb.unbound)}</td><td><b>诚实缺口，不隐藏</b></td></tr>
  <tr><td>与产物不一致</td><td class="num">${f(fb.drift)}</td><td>CI 门禁当前通过</td></tr>
  <tr><td>显式豁免</td><td class="num">${f(fb.ignored)}</td><td>每条写明理由与失效条件</td></tr>
  <tr><td>形式化：证明义务</td><td class="num">6</td><td>已登记、未关闭，宽松构建下通过</td></tr>
</table>
<p class="muted">全仓口径（同日全量扫描：341 个文档、2,136 条应有产物的断言）：137 条已验证、1,768 条暂无产物、213 条多值候选、0 条漂移。上表是 <code>docs/</code> 样本快照，两者分母不同，百分比不可直接比较。</p>
<div class="bad"><b>必须说明的三件事</b>：① 未做侧信道加固，文档已按此修正声明；② 未通过任何第三方安全审计或密评认证；③ 形式化验证的"严格模式"目前会按设计失败——6 条证明义务尚未完成，我们不把它包装成"已验证"。</div>

<div class="pb"></div>
<h2>四、为什么这些数字值得相信</h2>
<p>不是因为我们说它们可信，而是因为每一条都有可复现的检查方式：</p>
<table>
  <tr><th>主张</th><th>复核方式</th></tr>
  <tr><td>文档数字与产物一致</td><td>运行 verifact，逐条给出文件、行号、产物路径</td></tr>
  <tr><td>形式化证明可复现</td><td>容器内 <code>isabelle build</code>；严格入口单独提供，失败即为失败</td></tr>
  <tr><td>发布物未被改动</td><td>RFC 3161 时间戳 + 公开哈希</td></tr>
  <tr><td>测试真实通过</td><td>测试脚本与 CI 日志公开；关键用例做了变异验证（改坏实现必须变红）</td></tr>
</table>
<div class="note"><b>一条我们自己踩过的教训</b>：工具曾把 <code>X25519 keygen 5.97ms</code> 与 <code>SM2 verify 50ms</code> 绑定成功（相似度 0.57），因为两者形状相近。这条被隐藏在一份"豁免清单"里很久。现在的规则是：<b>形状相似在密码学语义面前不算证据</b>，任何豁免都必须署名。</div>

<h2>五、可以怎么合作</h2>
<table>
  <tr><th>场景</th><th>交付形态</th></tr>
  <tr><td>存量系统文档审计</td><td>只读扫描 + 数字溯源报告（哪些数字有据、哪些无据、哪些冲突）</td></tr>
  <tr><td>PQC 迁移评估</td><td>CBOM（CycloneDX 标准）生成与差异分析</td></tr>
  <tr><td>交付物可复核性</td><td>把"文档—产物"对账接入 CI，交付时附可复核账本</td></tr>
  <tr><td>教学与实训</td><td>参考实现 + 验证容器 + 失败案例集（含本文提到的错绑案例）</td></tr>
</table>
<p>我们不做的事：不做安全认证代办，不出具"符合某标准"的结论，不宣称未经第三方验证的安全性质。<b>我们提供的是证据，结论应由评审方自己下。</b></p>

<h2>六、附件</h2>
<ul>
  <li>《文档数字溯源样例报告》（对 liboqs 与 FIBEMATE 两个真实仓库的只读扫描）</li>
  <li>工具与规则源码、门禁配置（开源，可自行复跑）</li>
</ul>
<p class="muted" style="margin-top:10mm">本文所有数字均来自 2026-10-26 的本地实测输出，可要求提供原始 JSON。</p>
</body></html>`;

const outFile = path.join(outDir, 'fibemate-intro.html');
fs.writeFileSync(outFile, cnQuotes(html), 'utf8');
console.log('wrote ' + outFile + ' (' + fs.statSync(outFile).size + ' bytes)');
