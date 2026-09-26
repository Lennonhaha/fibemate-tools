// SPDX-License-Identifier: Apache-2.0
'use strict';

const U = require('./util');
const { subSeed, Drbg } = require('./rng');
const { loadAll } = require('./impls/registry');
const { Pool } = require('./pool');

/**
 * 判定编排。
 *
 * 三条纪律：
 * 1. 长度、往返、互操作这些有客观答案的，不符就是 error。
 * 2. 共享密钥语义（K̄ 还是 K）不是缺陷，只归类，不判红。
 * 3. RNG 消耗序列不同导致的输出差异不算差异 —— 只有序列相同却输出不同，才是真差异。
 */

function newId(caseId, impls, extra) {
  return [caseId, impls.join('~'), extra || ''].filter(Boolean).join(':');
}

async function run(cfg, options) {
  const opts = options || {};
  const log = opts.log;
  const t0 = Date.now();

  const impls = await loadAll(cfg, log);
  const ready = impls.filter((i) => i.status === 'ready');
  const live = ready.map((i) => i.id);

  const report = {
    tool: 'xdiff',
    version: 1,
    generatedAt: null,
    algorithm: cfg.algorithm,
    durationMs: 0,
    configPath: cfg.__configPath || null,
    masterSeed: cfg.masterSeed,
    implementations: impls.map((i) => ({
      id: i.id, label: i.label, type: i.type, path: i.path, note: i.note,
      status: i.status, reason: i.reason || null, rngProfileKeygen: i.rngProfileKeygen || null
    })),
    cases: [],
    findings: [],
    counts: { error: 0, warn: 0, info: 0, checks: 0 },
    observations: {}
  };

  if (live.length < 2) {
    report.findings.push({
      id: 'matrix:insufficient',
      caseId: 'matrix',
      severity: 'error',
      impls: live,
      title: '可比对的实现少于 2 个，差分不成立',
      detail: { ready: live.length, unavailable: impls.filter((i) => i.status !== 'ready').map((i) => i.id + ':' + (i.reason || '')) }
    });
    report.counts.error++;
    report.counts.checks++;
    report.durationMs = Date.now() - t0;
    report.generatedAt = new Date().toISOString();
    return report;
  }

  const pool = new Pool(cfg);
  await pool.init(log);

  const C = cfg.cases || {};
  const sizes = cfg.sizes;
  const samples = (k, d) => (C[k] && typeof C[k].samples === 'number' ? C[k].samples : d);
  const on = (k) => !C[k] || C[k].enabled !== false;

  const push = (f) => {
    report.findings.push(f);
    if (f.severity === 'error') report.counts.error++;
    else if (f.severity === 'warn') report.counts.warn++;
    else report.counts.info++;
    report.counts.checks++;
  };
  const caseRec = (caseId, title, extra) => {
    const rec = Object.assign({ caseId, title }, extra || {});
    report.cases.push(rec);
    return rec;
  };

  try {
    // ---------- 1. 长度合规 ----------
    // 顺带产出互操作要用的密钥材料，避免重复 keygen
    const nSamples = Math.max(samples('roundtrip', 8), samples('crossInterop', 8), samples('determinism', 4), samples('entropy', 8));
    const keys = {};   // implId -> [{pk, sk, rng}]
    if (on('lengthCompliance') || on('roundtrip') || on('crossInterop')) {
      const tasks = [];
      for (const id of live) {
        for (let s = 0; s < nSamples; s++) {
          tasks.push({ op: 'keygen', implId: id, caseIndex: s, purpose: 'keygen' });
        }
      }
      const res = await pool.runAll(tasks);
      for (const r of res) {
        if (!r.ok) {
          push({
            id: newId('length', [r.task.implId], 'keygen-failed'),
            caseId: 'lengthCompliance', severity: 'error', impls: [r.task.implId],
            title: 'keygen 执行失败', detail: { error: r.error }
          });
          continue;
        }
        const id = r.task.implId;
        (keys[id] = keys[id] || [])[r.task.caseIndex] = { pk: r.r.result.pk, sk: r.r.result.sk, rng: r.r.rngProfile, ms: r.r.ms };
      }
    }

    if (on('lengthCompliance')) {
      const bad = [];
      for (const id of live) {
        const k0 = (keys[id] || [])[0];
        if (!k0) continue;
        const lens = { pk: k0.pk.length / 2, sk: k0.sk.length / 2 };
        if (lens.pk !== sizes.pk || lens.sk !== sizes.sk) bad.push({ id, lens, expect: { pk: sizes.pk, sk: sizes.sk } });
      }
      caseRec('lengthCompliance', '密钥长度符合 FIPS 203', { checked: live.length, bad });
      if (bad.length) {
        push({
          id: 'length:' + bad.map((b) => b.id).join(','),
          caseId: 'lengthCompliance', severity: 'error', impls: bad.map((b) => b.id),
          title: '密钥长度与 ' + cfg.algorithm + ' 规定不符',
          detail: { bad }
        });
      }
    }

    // ---------- 2. 自身往返 ----------
    const encOwn = {};  // implId -> index -> {ct, ss}
    if (on('roundtrip')) {
      const n = samples('roundtrip', 8);
      const tasks = [];
      for (const id of live) {
        for (let s = 0; s < n; s++) {
          const k = (keys[id] || [])[s];
          if (k) tasks.push({ op: 'encaps', implId: id, pk: k.pk, caseIndex: s, purpose: 'encaps' });
        }
      }
      const res = await pool.runAll(tasks);
      const decTasks = [];
      for (const r of res) {
        if (!r.ok) continue;
        const id = r.task.implId;
        (encOwn[id] = encOwn[id] || [])[r.task.caseIndex] = { ct: r.r.result.ct, ss: r.r.result.ss, ms: r.r.ms };
        const k = (keys[id] || [])[r.task.caseIndex];
        decTasks.push({ op: 'decaps', implId: id, sk: k.sk, ct: r.r.result.ct, caseIndex: r.task.caseIndex, purpose: 'decaps' });
      }
      const decs = await pool.runAll(decTasks);
      const fail = [];
      const ctLenBad = [];
      const ssLenBad = [];
      for (const d of decs) {
        if (!d.ok) { fail.push({ id: d.task.implId, index: d.task.caseIndex, error: d.error }); continue; }
        const id = d.task.implId;
        const own = (encOwn[id] || [])[d.task.caseIndex];
        if (!own) continue;
        if (own.ct.length / 2 !== sizes.ct) ctLenBad.push({ id, got: own.ct.length / 2 });
        if (own.ss.length / 2 !== sizes.ss) ssLenBad.push({ id, got: own.ss.length / 2 });
        if (d.r.result.ss !== own.ss) {
          fail.push({ id, index: d.task.caseIndex, ssEnc: U.shortHex(own.ss), ssDec: U.shortHex(d.r.result.ss) });
        }
      }
      const total = decs.length;
      caseRec('roundtrip', '自身封装/解封装往返一致', { samples: total, failed: fail.length });
      if (fail.length) {
        push({
          id: newId('roundtrip', [...new Set(fail.map((f) => f.id))]),
          caseId: 'roundtrip', severity: 'error', impls: [...new Set(fail.map((f) => f.id))],
          title: '往返解封装得到的共享密钥与封装时不同',
          detail: { failed: fail.length, of: total, sample: fail.slice(0, 3) }
        });
      }
      if (ctLenBad.length || ssLenBad.length) {
        push({
          id: newId('roundtrip', [...new Set([...ctLenBad, ...ssLenBad].map((x) => x.id))], 'len'),
          caseId: 'roundtrip', severity: 'error', impls: [...new Set([...ctLenBad, ...ssLenBad].map((x) => x.id))],
          title: '密文或共享密钥长度不符',
          detail: { expect: { ct: sizes.ct, ss: sizes.ss }, ctLenBad, ssLenBad }
        });
      }
    }

    // ---------- 3. 跨实现互操作 + 共享密钥语义归类 ----------
    const semanticsVotes = {};   // implId -> {kbar:n, k:n}
    const vote = (id, kind) => {
      semanticsVotes[id] = semanticsVotes[id] || { kbar: 0, k: 0 };
      semanticsVotes[id][kind]++;
    };
    if (on('crossInterop')) {
      const n = samples('crossInterop', 8);
      let pairIdx = 0;
      const encTasks = [];
      const meta = [];
      for (const A of live) {
        for (const B of live) {
          if (A === B) continue;
          const p = pairIdx++;
          for (let s = 0; s < n; s++) {
            const kA = (keys[A] || [])[s];
            if (!kA) continue;
            encTasks.push({ op: 'encaps', implId: B, pk: kA.pk, caseIndex: p * 100 + s, purpose: 'encaps' });
            meta.push({ A, B, s });
          }
        }
      }
      const encRes = await pool.runAll(encTasks);
      const decTasks = [];
      const ctx = [];
      encRes.forEach((r, i) => {
        if (!r.ok) return;
        const m = meta[i];
        const kA = (keys[m.A] || [])[m.s];
        decTasks.push({ op: 'decaps', implId: m.A, sk: kA.sk, ct: r.r.result.ct, caseIndex: m.s, purpose: 'decaps' });
        ctx.push({ A: m.A, B: m.B, s: m.s, ct: r.r.result.ct, ssB: r.r.result.ss });
      });
      const decRes = await pool.runAll(decTasks);

      const mismatch = [];
      const semanticDiff = [];
      const checked = [];
      decRes.forEach((d, i) => {
        if (!d.ok) { mismatch.push({ pair: ctx[i].A + '←' + ctx[i].B, error: d.error }); return; }
        const c = ctx[i];
        const ssA = d.r.result.ss;
        const ssB = c.ssB;
        const ct = U.fromHex(c.ct);
        if (ssA === ssB) {
          checked.push({ pair: c.A + '←' + c.B, mode: 'equal' });
          return;
        }
        // A 返回 K̄，B 返回最终 K
        if (U.finalK(U.fromHex(ssA), ct).toString('hex') === ssB) {
          semanticDiff.push({ pair: c.A + '←' + c.B, aSemantics: 'kbar', bSemantics: 'k' });
          vote(c.A, 'kbar'); vote(c.B, 'k');
          checked.push({ pair: c.A + '←' + c.B, mode: 'kbar-vs-k' });
          return;
        }
        // A 返回最终 K，B 返回 K̄
        if (U.finalK(U.fromHex(ssB), ct).toString('hex') === ssA) {
          semanticDiff.push({ pair: c.A + '←' + c.B, aSemantics: 'k', bSemantics: 'kbar' });
          vote(c.A, 'k'); vote(c.B, 'kbar');
          checked.push({ pair: c.A + '←' + c.B, mode: 'k-vs-kbar' });
          return;
        }
        mismatch.push({
          pair: c.A + '←' + c.B, index: c.s,
          ssDecA: U.shortHex(ssA), ssEncB: U.shortHex(ssB),
          finalKofA: U.shortHex(U.finalK(U.fromHex(ssA), ct)),
          finalKofB: U.shortHex(U.finalK(U.fromHex(ssB), ct))
        });
      });

      caseRec('crossInterop', '跨实现互操作（A 密钥 → B 封装 → A 解封）', {
        pairs: live.length * (live.length - 1), samplesPerPair: n, checked: checked.length,
        mismatch: mismatch.length, semanticDiff: semanticDiff.length
      });

      if (mismatch.length) {
        // 按 pair 聚合，方便判断是「某实现参与就失败」还是整体不兼容
        const byPair = {};
        for (const m of mismatch) byPair[m.pair] = (byPair[m.pair] || 0) + 1;
        const byPairOk = {};
        for (const c of checked) byPairOk[c.pair] = (byPairOk[c.pair] || 0) + 1;
        push({
          id: newId('crossInterop', [...new Set(mismatch.map((m) => m.pair))]),
          caseId: 'crossInterop', severity: 'error',
          impls: live,
          title: '跨实现互操作失败：解封装结果与对方的封装结果对不上（含两种共享密钥语义折算后仍不等）',
          detail: {
            failed: mismatch.length, of: checked.length + mismatch.length,
            failedByPair: byPair, okByPair: byPairOk, sample: mismatch.slice(0, 5)
          }
        });
      }
      if (semanticDiff.length) {
        push({
          id: newId('crossInterop', live, 'semantics'),
          caseId: 'crossInterop', severity: 'info',
          impls: live,
          title: '实现之间返回的共享密钥语义不同（一方给 K̄，另一方给 K=SHA3-256(K̄‖H(ct))）',
          detail: { note: '这不是缺陷，但对外接口必须写清返回哪一种', occurrences: semanticDiff.length, sample: semanticDiff.slice(0, 5) }
        });
      }
    }

    // 语义归类汇总
    const semantics = {};
    for (const id of live) {
      const v = semanticsVotes[id];
      if (!v || (v.kbar === 0 && v.k === 0)) semantics[id] = 'undetermined';
      else semantics[id] = v.kbar > v.k ? 'kbar' : (v.k > v.kbar ? 'k' : 'conflict');
    }
    report.observations.ssSemantics = semantics;

    // ---------- 4. 确定性（同一种子两次必须一致）----------
    if (on('determinism')) {
      const n = samples('determinism', 4);
      const tasks = [];
      for (const id of live) for (let s = 0; s < n; s++) {
        tasks.push({ op: 'keygen', implId: id, caseIndex: s, purpose: 'keygen' });
      }
      const res = await pool.runAll(tasks);
      const got = {};
      for (const r of res) {
        if (!r.ok) continue;
        const id = r.task.implId;
        (got[id] = got[id] || {})[r.task.caseIndex] = (got[id][r.task.caseIndex] || []).concat(r.r.result.pk);
      }
      const nondeterministic = [];
      for (const id of live) {
        const base = (keys[id] || [])[0];
        for (let s = 0; s < n; s++) {
          const cur = got[id] && got[id][s] && got[id][s][0];
          const ref = base ? base.pk : undefined;
          if (!cur) continue;
          // 同一 caseIndex 的 keygen 必须与第一轮完全一致
          const refSame = (keys[id] || [])[s];
          if (refSame && cur !== refSame.pk) {
            nondeterministic.push({ id, index: s, first: U.shortHex(refSame.pk), second: U.shortHex(cur) });
          }
        }
      }
      caseRec('determinism', '同一随机种子可复现（确定性注入）', { samples: n * live.length, failed: nondeterministic.length });
      if (nondeterministic.length) {
        push({
          id: newId('determinism', [...new Set(nondeterministic.map((x) => x.id))]),
          caseId: 'determinism', severity: 'error', impls: [...new Set(nondeterministic.map((x) => x.id))],
          title: '同一随机种子下两次 keygen 结果不同 —— 实现里存在未受控的随机源',
          detail: { failed: nondeterministic.length, sample: nondeterministic.slice(0, 3) }
        });
      }
    }

    // ---------- 5. 熵（不同种子必须产出不同密钥）----------
    if (on('entropy')) {
      const n = samples('entropy', 8);
      const dup = [];
      const lowEntropy = [];
      for (const id of live) {
        const seen = new Map();
        const list = (keys[id] || []).slice(0, n).filter(Boolean);
        for (const k of list) {
          if (seen.has(k.pk)) dup.push({ id, other: seen.get(k.pk) });
          seen.set(k.pk, k.pk);
        }
        if (seen.size !== list.length) dup.push({ id, note: '集合大小与样本数不符' });
        // 熵粗检：公钥不应出现长段重复字节
        for (const k of list) {
          const b = U.fromHex(k.pk);
          const first = b[0];
          let same = 1;
          for (let i = 1; i < b.length; i++) { if (b[i] === first) same++; else break; }
          if (same > 32) lowEntropy.push({ id, leadingSameBytes: same });
        }
      }
      caseRec('entropy', '不同种子产出不同密钥', { samples: n, duplicates: dup.length });
      if (dup.length) {
        push({
          id: newId('entropy', [...new Set(dup.map((d) => d.id))]),
          caseId: 'entropy', severity: 'error', impls: [...new Set(dup.map((d) => d.id))],
          title: '不同随机种子产生了相同的公钥',
          detail: { sample: dup.slice(0, 5) }
        });
      }
      if (lowEntropy.length) {
        push({
          id: newId('entropy', [...new Set(lowEntropy.map((d) => d.id))], 'low'),
          caseId: 'entropy', severity: 'warn', impls: [...new Set(lowEntropy.map((d) => d.id))],
          title: '公钥前部出现长段相同字节，随机源可疑',
          detail: { sample: lowEntropy.slice(0, 5) }
        });
      }
    }

    // ---------- 6. 失败性解密（隐式拒绝）----------
    if (on('implicitRejection')) {
      const n = samples('implicitRejection', 4);
      const tasks = [];
      const meta = [];
      for (const id of live) {
        const own = encOwn[id] || [];
        for (let s = 0; s < n; s++) {
          const e = own[s];
          const k = (keys[id] || [])[s];
          if (!e || !k) continue;
          for (const bit of [0, 7, 123]) {
            tasks.push({ op: 'flipdecaps', implId: id, sk: k.sk, ct: e.ct, bit, caseIndex: s, purpose: 'flip' });
            meta.push({ id, s, bit, origSs: e.ss });
          }
        }
      }
      const res = await pool.runAll(tasks);
      const threw = [];
      const lenBad = [];
      const notRejected = [];
      const notCtDependent = [];
      const perKey = {};   // id:s -> Set(ss)
      res.forEach((r, i) => {
        if (!r.ok) { threw.push({ id: meta[i].id, error: r.error }); return; }
        const m = meta[i];
        const out = r.r.result;
        if (out.threw) {
          threw.push({ id: m.id, bit: m.bit, message: out.threw });
          return;
        }
        if (!out.ss || out.ss.length / 2 !== sizes.ss) {
          lenBad.push({ id: m.id, bit: m.bit, got: out.ss ? out.ss.length / 2 : null });
          return;
        }
        if (out.ss === m.origSs) {
          notRejected.push({ id: m.id, bit: m.bit, index: m.s });
          return;
        }
        const key = m.id + ':' + m.s;
        (perKey[key] = perKey[key] || new Set()).add(out.ss);
      });
      for (const key of Object.keys(perKey)) {
        if (perKey[key].size < 2) notCtDependent.push({ group: key, distinct: perKey[key].size });
      }
      caseRec('implicitRejection', '篡改密文触发隐式拒绝且不抛异常', { tasks: res.length, threw: threw.length, notRejected: notRejected.length });
      if (threw.length) {
        push({
          id: newId('implicitRejection', [...new Set(threw.map((t) => t.id))], 'threw'),
          caseId: 'implicitRejection', severity: 'error', impls: [...new Set(threw.map((t) => t.id))],
          title: '解封装被篡改的密文时抛出异常 —— 与隐式拒绝要求不符，也会泄漏信息',
          detail: { count: threw.length, sample: threw.slice(0, 5) }
        });
      }
      if (lenBad.length) {
        push({
          id: newId('implicitRejection', [...new Set(lenBad.map((t) => t.id))], 'len'),
          caseId: 'implicitRejection', severity: 'error', impls: [...new Set(lenBad.map((t) => t.id))],
          title: '拒绝路径返回的共享密钥长度不是 ' + sizes.ss + ' 字节',
          detail: { sample: lenBad.slice(0, 5) }
        });
      }
      if (notRejected.length) {
        push({
          id: newId('implicitRejection', [...new Set(notRejected.map((t) => t.id))], 'noreject'),
          caseId: 'implicitRejection', severity: 'error', impls: [...new Set(notRejected.map((t) => t.id))],
          title: '密文被篡改后仍返回原共享密钥 —— 未触发隐式拒绝',
          detail: { count: notRejected.length, sample: notRejected.slice(0, 5) }
        });
      }
      if (notCtDependent.length) {
        push({
          id: newId('implicitRejection', live, 'ct-independent'),
          caseId: 'implicitRejection', severity: 'warn', impls: live,
          title: '不同位翻转得到相同的拒绝值，拒绝值可能未绑定密文',
          detail: { sample: notCtDependent.slice(0, 5) }
        });
      }
    }

    // ---------- 7. RNG 消耗指纹 ----------
    // 注意：DRBG 是连续流，[32,32] 与 [64] 抽到的是同一段字节，只有「总量」才决定能否对齐
    const profileSum = (p) => (Array.isArray(p) ? p.reduce((a, b) => a + b, 0) : null);
    if (on('rngProfile')) {
      const profiles = {};
      for (const id of live) {
        const k = (keys[id] || [])[0];
        profiles[id] = k ? k.rng : (impls.find((i) => i.id === id) || {}).rngProfileKeygen || null;
      }
      report.observations.rngProfile = profiles;
      report.observations.rngProfileBytes = Object.fromEntries(Object.entries(profiles).map(([k, v]) => [k, profileSum(v)]));
      const sums = new Set(Object.values(report.observations.rngProfileBytes));
      caseRec('rngProfile', '随机源消耗指纹', { profiles, bytes: report.observations.rngProfileBytes });
      push({
        id: 'rngProfile:' + live.join(','),
        caseId: 'rngProfile', severity: 'info', impls: live,
        title: 'keygen 随机消耗 ' + JSON.stringify(profiles) + '（字节总量 ' + JSON.stringify(report.observations.rngProfileBytes) + '）'
          + (sums.size === 1 ? '，总量一致，跨实现字节级比对成立' : '，总量不一致，字节级比对只对总量相同的实现成立'),
        detail: { profiles, bytes: report.observations.rngProfileBytes }
      });
    }

    // ---------- 7b. 同种子字节级对齐 ----------
    // 随机消耗总量相同的实现，在同一段随机流下必须产出同一把密钥。
    // 总量不同就没有可比性，跳过而不是判红。
    if (on('seedAlignment')) {
      const byBytes = new Map();
      for (const id of live) {
        const k = (keys[id] || [])[0];
        const sum = profileSum(k ? k.rng : null);
        if (sum == null) continue;
        if (!byBytes.has(sum)) byBytes.set(sum, []);
        byBytes.get(sum).push(id);
      }
      const groups = [];
      for (const [sum, ids] of byBytes.entries()) {
        if (ids.length < 2) { groups.push({ bytes: sum, ids, comparable: false }); continue; }
        const mis = [];
        const agree = [];
        for (let i = 0; i < ids.length; i++) {
          for (let j = i + 1; j < ids.length; j++) {
            const a = (keys[ids[i]] || [])[0];
            const b = (keys[ids[j]] || [])[0];
            if (!a || !b) continue;
            if (a.pk === b.pk && a.sk === b.sk) agree.push(ids[i] + '=' + ids[j]);
            else {
              let dpk = 0;
              const x = U.fromHex(a.pk); const y = U.fromHex(b.pk);
              for (let t = 0; t < Math.min(x.length, y.length); t++) if (x[t] !== y[t]) dpk++;
              mis.push({ pair: ids[i] + ' vs ' + ids[j], pkDiffBytes: dpk, of: x.length });
            }
          }
        }
        groups.push({ bytes: sum, ids, comparable: true, agree, mismatch: mis });
        if (mis.length) {
          push({
            id: newId('seedAlignment', ids),
            caseId: 'seedAlignment', severity: 'error', impls: ids,
            title: '同一随机种子下产出的密钥不同：随机消耗总量相同（' + sum + ' 字节），这些实现拿到了同一段随机流却算出不同的密钥',
            detail: { groups: [groups[groups.length - 1]], note: '两个实现互相印证为一致时，偏离的那个是偏离方' }
          });
        }
      }
      report.observations.seedAlignment = groups;
      caseRec('seedAlignment', '同种子字节级对齐', { groups });
    }

    // ---------- 7c. 密钥派生根因定位 ----------
    // 当 seedAlignment 判定某实现偏离时，进一步定位偏在哪一步。
    // 做法：借一个导出 Keccak 原语的实现当尺子，把 pk 尾部的 rho 与若干候选输入对号入座。
    // 没有实现导出原语时，这个用例整体跳过（不猜、不判）。
    if (on('keySchedule')) {
      const k = (cfg.params && typeof cfg.params.k === 'number') ? cfg.params.k : null;
      let ref = null;
      for (const r of impls) {
        if (r.status !== 'ready' || !r.impl || !r.impl.module) continue;
        if (typeof r.impl.module.sha3_512 === 'function') { ref = r; break; }
      }
      if (ref && k != null) {
        const G = ref.impl.module.sha3_512;
        const dFor = (caseIndex) => {
          const seed = subSeed(Buffer.from(String(cfg.masterSeed), 'utf8'), caseIndex, 'keygen');
          return new Drbg(seed, 'keygen#' + caseIndex)._next(32);
        };
        const kByte = Buffer.from([k]);
        const verdicts = {};
        for (const id of live) {
          const kk = (keys[id] || [])[0];
          if (!kk) continue;
          const rho = U.fromHex(kk.pk).slice(U.fromHex(kk.pk).length - 32);
          const d = dFor(0);
          const cands = {
            standard: U.toBuf(G(U.toBuf(Buffer.concat([d, kByte])))).slice(0, 32),   // G(d‖k)
            missingDomainSep: U.toBuf(G(U.toBuf(d))).slice(0, 32),                    // G(d)  漏拼 k
            reversedOrder: U.toBuf(G(U.toBuf(Buffer.concat([kByte, d])))).slice(0, 32) // G(k‖d)
          };
          let hit = 'unknown';
          for (const [name, v] of Object.entries(cands)) {
            if (Buffer.from(v).equals(rho)) { hit = name; break; }
          }
          verdicts[id] = hit;
        }
        report.observations.keySchedule = { reference: ref.id, k, verdicts };
        caseRec('keySchedule', '密钥派生根因定位（借参考原语比对 pk 尾部的 ρ）', { reference: ref.id, verdicts });
        const bad = Object.entries(verdicts).filter(([, v]) => v !== 'standard');
        for (const [id, v] of bad) {
          const desc = v === 'missingDomainSep'
            ? '密钥派生用了 G(d) 而非 G(d‖k)：漏拼了域分隔符 k（FIPS 203 要求 G(d‖k)，ML-KEM-768 的 k=' + k + '）'
            : v === 'reversedOrder'
              ? '密钥派生用了 G(k‖d)：域分隔符拼接顺序与 FIPS 203 相反'
              : 'ρ 与任何候选输入都对不上，G 函数（SHA3-512 实现本身）与参考不同';
          push({
            id: newId('keySchedule', [id]),
            caseId: 'keySchedule', severity: 'error', impls: [id],
            title: desc,
            detail: { reference: ref.id, verdict: v, k, rho: U.shortHex(U.fromHex((keys[id] || [])[0].pk).slice(U.fromHex((keys[id] || [])[0].pk).length - 32)) }
          });
        }
        if (!bad.length) {
          push({
            id: newId('keySchedule', live),
            caseId: 'keySchedule', severity: 'info', impls: live,
            title: '所有实现的 ρ 均等于 G(d‖' + k + ')，密钥派生第一步一致',
            detail: { reference: ref.id, verdicts }
          });
        }
      } else {
        caseRec('keySchedule', '密钥派生根因定位', { skipped: true, reason: ref ? '未配置 params.k' : '没有实现导出 Keccak 原语，无法取参考尺子' });
      }
    }

    // ---------- 7d. KAT 参考文件：provenance + 卫生 + 对拍 ----------
    // 三件事分开报：
    //   katProvenance  —— 这份参考文件自称 FIPS 203，它的 ek 到底是不是按 FIPS 203 派生的
    //   katFileHygiene —— 文件里有没有不可复现区域（z 越界读、尾部内存残留）
    //   kat            —— 每个实现与该文件的对拍结果
    // 纪律：文件自身未通过 provenance 时，「实现与文件不一致」不等于实现错；
    // 「实现与一份非标准文件逐字节一致」才是共享缺陷。
    if (on('kat')) {
      const katCfg = C.kat || {};
      const katCore = require('./core/kat');
      const fs = require('fs');
      const path = require('path');
      const rspAbs = katCfg.rsp
        ? (path.isAbsolute(katCfg.rsp) ? katCfg.rsp : path.resolve(cfg.__cwd || '.', katCfg.rsp))
        : null;
      if (!rspAbs || !fs.existsSync(rspAbs)) {
        caseRec('kat', 'KAT 参考向量对拍', { skipped: true, reason: rspAbs ? ('向量文件不存在: ' + rspAbs) : '未配置 cases.kat.rsp' });
      } else {
        const vectors = katCore.parseRsp(fs.readFileSync(rspAbs, 'utf8'));
        const structBad = katCore.checkStructure(vectors);
        const n = Math.min(typeof katCfg.vectors === 'number' ? katCfg.vectors : 16, vectors.length);
        const head = fs.readFileSync(rspAbs, 'utf8').split(/\r?\n/).slice(0, 8).join(' ');

        // --- provenance：文件自身的派生路径 ---
        const kNum = (cfg.params && typeof cfg.params.k === 'number') ? cfg.params.k : null;
        let provenance = 'unknown';
        const provTally = {};
        if (kNum != null) {
          const kByte = Buffer.from([kNum]);
          for (const v of vectors.slice(0, Math.min(8, vectors.length))) {
            if (!v.ek || !v.seed) continue;
            const rho = v.ek.slice(v.ek.length - 32);
            const cands = {
              standard: U.sha3_512(v.seed, kByte).slice(0, 32),
              missingDomainSep: U.sha3_512(v.seed).slice(0, 32),
              reversedOrder: U.sha3_512(kByte, v.seed).slice(0, 32)
            };
            let hit = 'unknown';
            for (const [name, val] of Object.entries(cands)) {
              if (val.equals(rho)) { hit = name; break; }
            }
            provTally[hit] = (provTally[hit] || 0) + 1;
          }
          provenance = Object.entries(provTally).sort((a, b) => b[1] - a[1])[0][0];
        }
        caseRec('katProvenance', 'KAT 文件自身派生路径（ek 尾部 ρ 对号）', { rsp: path.basename(rspAbs), k: kNum, tally: provTally, provenance });
        if (provenance !== 'standard' && provenance !== 'unknown') {
          push({
            id: newId('katProvenance', [provenance]),
            caseId: 'katProvenance', severity: 'error', impls: [],
            title: 'KAT 文件自称 FIPS 203，但其 ek 的 ρ 等于 G(d)——派生时漏拼域分隔符 k，这份文件不是 FIPS 203 向量',
            detail: { rsp: rspAbs, provenance, tally: provTally, headerSample: head.slice(0, 160), note: '用它当黄金参考会把标准实现误判为失败，把同缺陷实现误判为通过' }
          });
        }

        // --- hygiene：不可复现区域 ---
        if (on('katFileHygiene')) {
          const hy = katCore.analyzeHygiene(vectors);
          caseRec('katFileHygiene', 'KAT 文件卫生（dk 分区域）', hy);
          if (hy.compact.of > 0 && (hy.compact.dMatch !== hy.compact.of || hy.compact.ekMatch !== hy.compact.of || hy.compact.hMatch !== hy.compact.of)) {
            push({
              id: 'katFileHygiene:structure', caseId: 'katFileHygiene', severity: 'warn', impls: [],
              title: 'dk 的 compact 区域与 seed/ek/H(ek) 对不上（d ' + hy.compact.dMatch + '/' + hy.compact.of + '，ek ' + hy.compact.ekMatch + '/' + hy.compact.of + '，H ' + hy.compact.hMatch + '/' + hy.compact.of + '）',
              detail: hy
            });
          }
          if (hy.tail.nonZero > 0) {
            push({
              id: 'katFileHygiene:tail', caseId: 'katFileHygiene', severity: 'warn', impls: [],
              title: 'dk 尾部（1280 字节之后）在 ' + hy.tail.nonZero + '/' + hy.tail.total + ' 条记录里不是全零，其中 ' + hy.tail.asciiReadable + ' 条含 ASCII 可读串——参考文件带出生成进程的内存残留',
              detail: { tail: hy.tail, note: '信号不是判决：说明生成该文件的实现对 sk 只写了前 1280 字节，尾段是未初始化内存' }
            });
          }
          if (hy.z.asciiReadable > 0) {
            push({
              id: 'katFileHygiene:z', caseId: 'katFileHygiene', severity: 'warn', impls: [],
              title: 'dk 的 z 区（隐式拒绝随机源）在 ' + hy.z.asciiReadable + '/' + hy.z.total + ' 条记录里含 ASCII 可读串——z 不是从 seed 确定性派生的，疑似越界读',
              detail: { z: hy.z, note: '信号不是判决：z 不参与 ek 比对，但决定篡改密文时返回的拒绝值' }
            });
          }
        }

        // --- 对拍 ---
        const structErr = structBad.length;
        const zZero = Buffer.alloc(32);
        const perImpl = {};
        for (const rec of ready) {
          const impl = rec.impl;
          if (!impl || typeof impl.derandKeygen !== 'function' || typeof impl.derandEncaps !== 'function') {
            perImpl[rec.id] = { unsupported: true };
            continue;
          }
          const acc = { ekOk: 0, cOk: 0, kOk: 0, decOk: 0, failed: [] };
          for (let i = 0; i < n; i++) {
            const v = vectors[i];
            try {
              const kg = impl.derandKeygen(v.seed, zZero).result;
              const ekOk = kg.pk.equals(v.ek);
              if (ekOk) acc.ekOk++;
              const en = impl.derandEncaps(v.ek, v.m).result;
              const cOk = en.ct.equals(v.c);
              const kOk = en.ss.equals(v.k);
              if (cOk) acc.cOk++;
              if (kOk) acc.kOk++;
              if (impl.decaps(kg.sk, v.c).equals(v.k)) acc.decOk++;
              if (!(ekOk && cOk && kOk)) {
                acc.failed.push({ count: v.count, ekOk, cOk, kOk });
              }
            } catch (e) {
              acc.failed.push({ count: v.count, error: (e && e.message ? e.message : String(e)).slice(0, 120) });
            }
          }
          perImpl[rec.id] = acc;
        }
        caseRec('kat', 'KAT 参考向量对拍', { rsp: path.basename(rspAbs), vectors: n, structureBad: structErr, provenance, perImpl });
        if (structErr) {
          push({
            id: 'kat:structure', caseId: 'kat', severity: 'warn', impls: [],
            title: 'KAT 文件有 ' + structErr + ' 处字段缺失或长度不符',
            detail: { sample: structBad.slice(0, 5) }
          });
        }
        for (const [id, acc] of Object.entries(perImpl)) {
          if (acc.unsupported) continue;
          if (provenance === 'standard') {
            if (acc.ekOk < n || acc.cOk < n || acc.kOk < n) {
              push({
                id: newId('kat', [id]), caseId: 'kat', severity: 'error', impls: [id],
                title: '未通过 KAT 对拍（ek ' + acc.ekOk + '/' + n + '，c ' + acc.cOk + '/' + n + '，k ' + acc.kOk + '/' + n + '）',
                detail: { sample: acc.failed.slice(0, 3) }
              });
            }
          } else {
            if (acc.ekOk === n && acc.cOk === n && acc.kOk === n) {
              push({
                id: newId('kat', [id], 'shares-defect'), caseId: 'kat', severity: 'error', impls: [id],
                title: '与一份未通过 provenance 检查的参考文件逐字节一致——与该文件的派生缺陷同源',
                detail: { provenance, ekOk: acc.ekOk, of: n }
              });
            } else {
              push({
                id: newId('kat', [id], 'vs-nonstd-file'), caseId: 'kat', severity: 'info', impls: [id],
                title: '与该参考文件不一致（ek ' + acc.ekOk + '/' + n + '，c ' + acc.cOk + '/' + n + '，k ' + acc.kOk + '/' + n + '）；注意该文件自身未通过 provenance 检查，不一致不代表实现错误',
                detail: { provenance, acc: { ekOk: acc.ekOk, cOk: acc.cOk, kOk: acc.kOk, decOk: acc.decOk }, sample: acc.failed.slice(0, 3) }
              });
            }
          }
        }
      }
    }

    // ---------- 8. 耗时 ----------
    if (on('timing')) {
      const timings = {};
      for (const id of live) {
        const kg = (keys[id] || []).filter(Boolean).map((k) => k.ms);
        const en = (encOwn[id] || []).filter(Boolean).map((e) => e.ms);
        timings[id] = { keygen: stat(kg), encaps: stat(en) };
      }
      report.observations.timing = timings;
      caseRec('timing', '单次操作耗时（毫秒，本地实测）', { timings });
      push({
        id: 'timing:' + live.join(','),
        caseId: 'timing', severity: 'info', impls: live,
        title: '耗时观测：' + live.map((id) => id + ' keygen p50=' + (timings[id].keygen.p50 || '-') + 'ms').join('，'),
        detail: { timings }
      });
    }
  } finally {
    pool.shutdown();
  }

  report.durationMs = Date.now() - t0;
  report.generatedAt = new Date().toISOString();
  report.gate = report.counts.error > 0 ? 'fail' : (report.counts.warn > 0 ? 'warn' : 'pass');
  return report;
}

function stat(arr) {
  const a = (arr || []).slice().sort((x, y) => x - y);
  if (!a.length) return { n: 0, p50: null, p95: null, min: null, max: null };
  const at = (q) => Number(a[Math.min(a.length - 1, Math.floor(a.length * q))].toFixed(3));
  return { n: a.length, p50: at(0.5), p95: at(0.95), min: Number(a[0].toFixed(3)), max: Number(a[a.length - 1].toFixed(3)) };
}

module.exports = { run, stat };
