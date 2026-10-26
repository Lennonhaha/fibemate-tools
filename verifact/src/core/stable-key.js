'use strict';
// SPDX-License-Identifier: Apache-2.0

const crypto = require('crypto');

/**
 * 内容寻址的声明身份（stableKey）。
 *
 * 为什么不用 `id` 当身份：`id` 含行号（`claims.js` 里 `<file>:L<line>:<kind>:<key>`）。
 * 在声明上方插入一行注释，整份文件的 id 全部改名，drift 历史会把纯排版改动读成
 * 大规模迁移（issue #96）。行号制至少是「诚实的错」—— 而一个错误的稳定键会让两条
 * 不同的声明共用同一个身份，所以这里的每条归一化规则都必须能说清理由。
 *
 * stableKey = <file>:<kind>:<key>:<sha256(payload) 前 12 位>
 * payload   = file \0 kind \0 key \0 value.raw \0 normalizeContext(sentence)
 *
 * 归一化只做三件事，且都是「同一份内容的不同排版」：
 *   1. CRLF -> LF（Windows 本地跑与 Actions Linux 跑必须得到同一个 hash）
 *   2. 剥掉 HTML 注释（否则在行尾加 disposition 注释就会改变身份）
 *   3. 连续空白压成一个空格并去首尾（缩进变化不该改变身份）
 *
 * 不做的事：不猜「文件 + kind + key 相同就算同一条」。同一文件里完全可能有两行
 * 一模一样的声明；那两条必须有两个身份，按出现顺序追加 `#2`、`#3`，并且报告要
 * 告诉作者「你自己写了两行一样的」。
 */

const HASH_LEN = 12;

function normalizeContext(sentence) {
  return String(sentence == null ? '' : sentence)
    .replace(/\r\n?/g, '\n')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function valueRaw(claim) {
  const v = claim && claim.value;
  if (!v || v.raw == null) return '';
  return String(v.raw);
}

function payload(claim) {
  const c = claim || {};
  return [
    String(c.file == null ? '' : c.file),
    String(c.kind == null ? '' : c.kind),
    String(c.key == null ? '' : c.key),
    valueRaw(c),
    normalizeContext(c.sentence)
  ].join('\u0000');
}

function hashClaim(claim) {
  return crypto.createHash('sha256').update(payload(claim), 'utf8').digest('hex').slice(0, HASH_LEN);
}

function baseKeyOf(claim) {
  const c = claim || {};
  return String(c.file) + ':' + String(c.kind) + ':' + String(c.key) + ':' + hashClaim(c);
}

/**
 * 给一批声明写 stableKey。必须按抽取顺序调用（顺序决定 `#n` 后缀）。
 *
 * 同一 baseKey 的第 1 条不带后缀，第 2 条起带 `#2`、`#3`…… 这样在无关行插入时，
 * 计数器既不会错位，也不会因为「后出现的覆盖前面的」把两条声明合并成一条。
 *
 * @returns {{duplicates: Array<{stableKey:string,file:string,ids:string[],count:number}>}}
 */
function assignStableKeys(claims) {
  const seen = new Map();
  const groups = new Map();
  for (const c of claims) {
    const base = baseKeyOf(c);
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    c.stableKeyIndex = n;
    c.stableKey = n === 1 ? base : base + '#' + n;
    if (!groups.has(base)) groups.set(base, []);
    groups.get(base).push(c);
  }
  const duplicates = [];
  for (const [stableKey, list] of groups) {
    if (list.length < 2) continue;
    for (const c of list) c.stableKeyGroupSize = list.length;
    duplicates.push({
      stableKey,
      file: list[0].file,
      ids: list.map((c) => c.id),
      count: list.length
    });
  }
  return { duplicates };
}

module.exports = { normalizeContext, hashClaim, baseKeyOf, assignStableKeys, HASH_LEN };
