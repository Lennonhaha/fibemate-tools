// SPDX-License-Identifier: Apache-2.0
'use strict';

/**
 * xdiff 变异测试：把源码逐条改坏，测试必须变红。
 *
 * 纪律：判据自身也要被核对——每条变异先断言「原文命中且仅命中一次」，
 * 命中数不符就判 GATE 失败，而不是悄悄跳过（跳过 = 假绿）。
 *
 * 用法：node test/mutation.js
 * 退出码：0 全部变异被杀（红）；1 有存活变异或基线不绿；2 源码模式失配
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SKIP = new Set(['node_modules', '.git', '.xdiff']);
// 副本必须与原仓同深度：xdiff.json 里的实现路径是 ../../fibemate/... 这类相对路径，
// 放到 os.tmpdir() 会让所有实现加载失败，KAT 用例直接消失（假绿）。
const MUT_PARENT = path.dirname(ROOT);

const MUTANTS = [
  {
    id: 'M1',
    file: 'src/util.js',
    what: 'finalK 丢掉 H(ct)，退化成 SHA3-256(K̄)',
    from: 'return sha3_256(toBuf(kbar), sha3_256(toBuf(ct)));',
    to: 'return sha3_256(toBuf(kbar));',
  },
  {
    id: 'M2',
    file: 'src/util.js',
    what: 'flipBit 不再翻位（空操作）',
    from: 'b[byte] ^= 1 << (bitIdx % 8);',
    to: 'b[byte] ^= 0;',
  },
  {
    id: 'M3',
    file: 'src/rng.js',
    what: 'DRBG 计数器不递增，跨块重复',
    from: 'this.buf = drbgBlock(this.seed, this.counter++);',
    to: 'this.buf = drbgBlock(this.seed, 0);',
  },
  {
    id: 'M4',
    file: 'src/rng.js',
    what: 'DRBG 块哈希里忽略计数器字节',
    from: 'h.update(c);',
    to: 'h.update(Buffer.alloc(4));',
  },
  {
    id: 'M5',
    file: 'src/core/kat.js',
    what: 'parseRsp 不再校验字段长度',
    from: "cur[field + 'LenOk'] = buf.length === FIELD_LEN[field];",
    to: "cur[field + 'LenOk'] = true;",
  },
  {
    id: 'M6',
    file: 'src/core/kat.js',
    what: 'analyzeHygiene 不再统计全零 z 区',
    from: 'if (z.every((b) => b === 0)) zStats.allZero++;',
    to: 'zStats.allZero += 0;',
  },
  {
    id: 'M7',
    file: 'src/core/kat.js',
    what: 'provenance 候选把 missingDomainSep 换成标准式，检测能力消失',
    from: 'missingDomainSep: sha3_512(v.seed).slice(0, 32),',
    to: 'missingDomainSep: sha3_512(Buffer.concat([v.seed, kByte])).slice(0, 32),',
  },
  {
    id: 'M8',
    file: 'src/engine.js',
    what: 'provenance 异常永不报 error',
    from: "if (provenance !== 'standard' && provenance !== 'unknown') {",
    to: 'if (false) {',
  },
];

function copyTree(src, dest) {
  fs.cpSync(src, dest, {
    recursive: true,
    filter: (p) => !SKIP.has(path.basename(p)),
  });
}

function runSuite(dir) {
  const r = spawnSync(process.execPath, ['test/run.js'], { cwd: dir, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: ((r.stdout || '') + (r.stderr || '')).trim() };
}

function main() {
  const made = [];
  let failures = 0;

  try {
    // 0) 基线：未变异必须绿
    const baseDir = path.join(MUT_PARENT, '.xdiff-mut-baseline');
    fs.rmSync(baseDir, { recursive: true, force: true });
    fs.mkdirSync(baseDir);
    made.push(baseDir);
    copyTree(ROOT, baseDir);
    const base = runSuite(baseDir);
    if (base.code !== 0) {
      console.log('GATE FAIL: 基线未变异就不绿，变异测试没有意义');
      console.log(base.out.split('\n').slice(-6).join('\n'));
      process.exit(1);
    }
    console.log('baseline  GREEN (exit 0)');

    // 1) 逐条变异
    for (const m of MUTANTS) {
      const target = path.join(ROOT, m.file);
      const src = fs.readFileSync(target, 'utf8');
      const hits = src.split(m.from).length - 1;
      if (hits !== 1) {
        console.log(`GATE FAIL: ${m.id} 模式在 ${m.file} 命中 ${hits} 次（要求恰好 1 次）—— 源码已变，变异口径失效`);
        failures++;
        continue;
      }
      const dir = path.join(MUT_PARENT, '.xdiff-mut-' + m.id);
      fs.rmSync(dir, { recursive: true, force: true });
      fs.mkdirSync(dir);
      made.push(dir);
      copyTree(ROOT, dir);
      const mutated = src.replace(m.from, m.to);
      fs.writeFileSync(path.join(dir, m.file), mutated, 'utf8');
      const res = runSuite(dir);
      if (res.code === 0) {
        console.log(`SURVIVED  ${m.id}  ${m.what}  <-- 假绿，测试没抓到`);
        failures++;
      } else {
        console.log(`RED-OK    ${m.id}  ${m.what}  (exit ${res.code})`);
      }
    }
  } finally {
    for (const d of made) fs.rmSync(d, { recursive: true, force: true });
  }

  console.log('');
  if (failures) {
    console.log(`${MUTANTS.length - failures}/${MUTANTS.length} 变异被杀，${failures} 条未通过 —— GATE FAIL`);
    process.exit(1);
  }
  console.log(`${MUTANTS.length}/${MUTANTS.length} 变异全部被杀 —— GATE PASS`);
}

main();
