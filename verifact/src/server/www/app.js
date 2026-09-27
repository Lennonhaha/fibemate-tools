'use strict';
// SPDX-License-Identifier: Apache-2.0

(function () {
  var state = { report: null, filter: 'all', q: '', lintFilter: 'all', expanded: {} };

  var STATUS_TEXT = {
    verified: '已核验', drift: '漂移', ambiguous: '候选冲突', unbound: '未绑定',
    ignored: '已忽略', 'ref-found': '产出物存在', 'ref-missing': '产出物缺失'
  };

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function valText(v) {
    if (!v) return '-';
    if (v.type === 'ref') return v.raw;
    return v.raw;
  }

  function toast(msg, ms) {
    var t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.hidden = true; }, ms || 2600);
  }

  async function api(path, options) {
    var attempts = 0;
    for (;;) {
      attempts++;
      try {
        var res = await fetch(path, options);
        if (res.status === 409) { toast('上一次核验还在进行'); return null; }
        if (res.status >= 500 && attempts < 3) {
          await new Promise(function (r) { setTimeout(r, 400 * attempts); });
          continue;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return await res.json();
      } catch (e) {
        if (attempts >= 3) {
          toast('连不上本地服务（' + path + '）。确认 verifact serve 仍在运行。');
          return null;
        }
        await new Promise(function (r) { setTimeout(r, 400 * attempts); });
      }
    }
  }

  function renderCards(r) {
    var c = r.counts, l = r.lintCounts;
    var items = [
      { k: '声明总数', v: c.claims, cls: '' },
      { k: '已核验', v: c.verified, cls: 'ok' },
      { k: '漂移', v: c.drift, cls: c.drift ? 'bad' : 'ok' },
      { k: '候选冲突', v: c.ambiguous, cls: c.ambiguous ? 'warn' : '' },
      { k: '未绑定', v: c.unbound, cls: '' },
      { k: '引用缺失', v: c.refMissing, cls: c.refMissing ? 'warn' : '' },
      { k: '用语 high', v: l.high, cls: l.high ? 'bad' : 'ok' },
      { k: '耗时 ms', v: r.durationMs, cls: '' }
    ];
    $('cards').innerHTML = items.map(function (i) {
      return '<div class="card ' + i.cls + '"><div class="k">' + esc(i.k) + '</div><div class="v">' + esc(i.v) + '</div></div>';
    }).join('');
    $('meta').textContent = 'cache=' + r.meta.cache + ' · workers=' + r.meta.workers +
      ' · 产出物条目 ' + r.counts.artifacts + ' · 门禁 ' + r.gate.policy + ' ' + (r.gate.failed ? 'FAILED' : 'PASSED');
  }

  function rows(r) {
    var q = state.q.trim().toLowerCase();
    return r.claims.filter(function (c) {
      if (state.filter !== 'all' && c.status !== state.filter) return false;
      if (!q) return true;
      var hay = [c.file, c.module, c.key, c.sentence, valText(c.value)].join(' ').toLowerCase();
      return hay.indexOf(q) >= 0;
    });
  }

  function renderTable() {
    var r = state.report;
    var list = rows(r);
    var tb = $('tbody');
    $('empty').hidden = list.length > 0;

    tb.innerHTML = list.map(function (c) {
      var open = !!state.expanded[c.id];
      var main = '<tr class="dr" data-id="' + esc(c.id) + '">' +
        '<td><span class="chip ' + esc(c.status) + '">' + esc(STATUS_TEXT[c.status] || c.status) + '</span></td>' +
        '<td class="loc mono">' + esc(c.file) + ':' + c.line + '</td>' +
        '<td>' + esc(c.module || '-') + '</td>' +
        '<td class="mono">' + esc(c.key) + '</td>' +
        '<td class="mono">' + esc(valText(c.value)) + '</td>' +
        '<td class="mono">' + esc(c.best ? valText(c.best.value) : '-') + '</td>' +
        '<td class="mono">' + (c.score != null ? Number(c.score).toFixed(2) : '-') + '</td>' +
        '</tr>';
      if (!open) return main;
      var detail = '<tr class="detail"><td colspan="7">' +
        '<div><strong>原文</strong>：' + esc(c.sentence) + '</div>' +
        '<div><strong>判定依据</strong>：' + esc(c.note || '-') + '</div>' +
        '<div><strong>产出物</strong>：' + esc(c.best ? c.best.source + ' :: ' + c.best.path : '-') + '</div>' +
        (c.alternatives && c.alternatives.length
          ? '<div><strong>其他候选</strong>：' + c.alternatives.map(function (a) {
              return esc(a.source + ' :: ' + a.path + ' = ' + valText(a.value) + ' (' + Number(a.score).toFixed(2) + ')');
            }).join(' ｜ ') + '</div>'
          : '') +
        '<div><strong>id</strong>：' + esc(c.id) + '</div>' +
        '</td></tr>';
      return main + detail;
    }).join('');

    Array.prototype.forEach.call(tb.querySelectorAll('tr.dr'), function (tr) {
      tr.addEventListener('click', function () {
        var id = tr.getAttribute('data-id');
        state.expanded[id] = !state.expanded[id];
        renderTable();
      });
    });
  }

  function renderLint() {
    var l = state.report.lint.filter(function (f) {
      return state.lintFilter === 'all' || f.severity === state.lintFilter;
    }).slice(0, 200);
    $('lint').innerHTML = l.length ? l.map(function (f) {
      return '<div class="item"><div class="h">' +
        '<span class="chip ' + (f.severity === 'high' ? 'drift' : f.severity === 'medium' ? 'ambiguous' : 'unbound') + '">' +
        esc(f.severity) + '</span>' + esc(f.ruleId) + ' · ' + esc(f.file) + ':' + f.line +
        ' · 命中「' + esc(f.matched) + '」</div>' +
        '<div class="b">' + esc(f.sentence) + '</div>' +
        '<div class="hint">' + esc(f.hint) + '</div></div>';
    }).join('') : '<p class="note">无。</p>';
  }

  async function renderHistory() {
    var h = await api('/api/history?limit=20');
    var list = (h && h.runs) ? h.runs.slice().reverse() : [];
    $('history').innerHTML = list.length ? list.map(function (r) {
      var c = r.counts || {};
      return '<div class="item"><div class="h">' + esc(String(r.generatedAt).replace('T', ' ').slice(0, 19)) +
        ' · ' + r.durationMs + 'ms · ' + esc(r.cache) + '</div>' +
        '<div class="b">声明 ' + esc(c.claims) + ' · 已核验 ' + esc(c.verified) +
        ' · <span style="color:' + (c.drift ? 'var(--bad)' : 'inherit') + '">漂移 ' + esc(c.drift) + '</span>' +
        ' · 未绑定 ' + esc(c.unbound) + ' · 门禁 ' + esc(r.gate && r.gate.policy) + ' ' +
        (r.gate && r.gate.failed ? 'FAILED' : 'PASSED') + '</div></div>';
    }).join('') : '<p class="note">暂无历史。</p>';
  }

  function renderAll(r) {
    state.report = r;
    renderCards(r);
    renderTable();
    renderLint();
    renderHistory();
  }

  async function load() {
    var r = await api('/api/report');
    if (r) { if (r.pending) { toast('首次核验进行中，稍后刷新'); setTimeout(load, 2500); return; } renderAll(r); }
  }

  async function doVerify() {
    var btn = $('btn-verify');
    btn.disabled = true;
    btn.textContent = '核验中…';
    try {
      var r = await api('/api/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ noCache: $('chk-nocache').checked })
      });
      if (r) { renderAll(r); toast('核验完成：漂移 ' + r.counts.drift + ' 条'); }
    } finally {
      btn.disabled = false;
      btn.textContent = '重新核验';
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('btn-verify').addEventListener('click', doVerify);
    $('q').addEventListener('input', function (e) { state.q = e.target.value; renderTable(); });
    $('tabs').addEventListener('click', function (e) {
      var b = e.target.closest('button'); if (!b) return;
      state.filter = b.getAttribute('data-s');
      Array.prototype.forEach.call($('tabs').children, function (x) { x.classList.toggle('on', x === b); });
      renderTable();
    });
    $('lint-tabs').addEventListener('click', function (e) {
      var b = e.target.closest('button'); if (!b) return;
      state.lintFilter = b.getAttribute('data-x');
      Array.prototype.forEach.call($('lint-tabs').children, function (x) { x.classList.toggle('on', x === b); });
      renderLint();
    });
    load();
  });
})();
