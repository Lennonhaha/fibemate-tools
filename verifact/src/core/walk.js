'use strict';
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');

/** 极简 glob → 正则（支持 ** / * / ?），够用即可，避免引入外部依赖。 */
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      // "**/" 语义是「零层或多层目录」，必须能匹配根目录下的文件
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          re += '(?:(?:[^/]+/)*)?';
          i += 2;                       // i 落在 '/' 上，交给外层 i++ 消化
        } else {
          re += '.*';
          i += 1;                       // 跳过第二个 '*'
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('\\^$.|+()[]{}'.indexOf(c) >= 0) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

function compilePatterns(list) {
  return (list || []).map(globToRegExp);
}

function matchesAny(rel, compiled) {
  for (const re of compiled) if (re.test(rel)) return true;
  return false;
}

const DEFAULT_EXCLUDE = [
  '**/node_modules/**', '**/.git/**', '**/target/**', '**/.verifact/**',
  '**/coverage/**', '**/*.map', '**/*.min.js'
];

/**
 * 迭代式遍历目录（不用递归，避免深目录爆栈）。
 * @returns {Iterator<{full:string, rel:string, size:number}>}
 */
function* iterate(root, opts) {
  const exclude = compilePatterns(opts.exclude && opts.exclude.length ? opts.exclude : DEFAULT_EXCLUDE);
  const rootAbs = path.resolve(root);
  const stack = [rootAbs];
  let emitted = 0;

  while (stack.length) {
    const cur = stack.pop();
    let ents;
    try { ents = fs.readdirSync(cur, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of ents) {
      const full = path.join(cur, e.name);
      const rel = path.relative(rootAbs, full).split(path.sep).join('/');
      if (e.isDirectory()) {
        if (matchesAny(rel + '/', exclude)) continue;
        if (opts.maxDepth && rel.split('/').length > opts.maxDepth) continue;
        stack.push(full);
        continue;
      }
      if (!e.isFile()) continue;
      if (matchesAny(rel, exclude)) continue;
      // include 语义为 OR，由调用方通过 matchInclude 提供
      if (opts.matchInclude && !opts.matchInclude(rel)) continue;
      let size = 0;
      try { size = fs.statSync(full).size; } catch (_) { continue; }
      if (opts.maxFileBytes && size > opts.maxFileBytes) continue;
      if (opts.maxFiles && emitted >= opts.maxFiles) return;
      emitted++;
      yield { full, rel, size };
    }
  }
}

function listFiles(root, opts) {
  const out = [];
  for (const f of iterate(root, opts)) out.push(f);
  return out;
}

function readText(full, maxBytes) {
  const buf = fs.readFileSync(full);
  if (maxBytes && buf.length > maxBytes) throw new Error('file_too_large');
  return buf.toString('utf8');
}

module.exports = { globToRegExp, compilePatterns, matchesAny, iterate, listFiles, readText, DEFAULT_EXCLUDE };
