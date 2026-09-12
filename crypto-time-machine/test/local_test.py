#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto-time-machine 本地测试（真实仓库只读，不修改）。

验证目标：
1. collect_timeline 能在 FIBEMATE 真历史上追踪到 ml_kem768 的引入/变更事件。
2. 事件含真实 sha / date / author / files（不拿推测当事实）。
3. build_db 写入 SQLite 后 query_impact 能读出。
"""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ctime import core

REPO = r'D:\FIBEMATE\fibemate'
PATTERN = 'ml_kem768'  # 已知存在于 FIBEMATE（noble-ciphers 的 ml_kem768）


def main():
    checks = []
    # 1) 真实历史追踪
    rows = core.collect_timeline(REPO, PATTERN, mode='-S')
    checks.append(('timeline non-empty', len(rows) > 0))
    if rows:
        r0 = rows[0]
        checks.append(('has real sha (40 hex)', len(r0['sha']) == 40 and all(c in '0123456789abcdef' for c in r0['sha'])))
        checks.append(('has iso date', 'T' in r0['date']))
        checks.append(('has author', bool(r0['author'])))
        checks.append(('files is list', isinstance(r0['files'], list)))

    # 2) SQLite 写入 + 查询
    tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    tmp.close()
    try:
        n = core.build_db(REPO, PATTERN, tmp.name, mode='-S')
        checks.append(('db rows match', n == len(rows)))
        imp = core.query_impact(tmp.name)
        checks.append(('query returns list', isinstance(imp, list) and len(imp) == n))
        if imp:
            checks.append(('query item has files', 'files' in imp[0]))
    finally:
        os.unlink(tmp.name)

    # 3) 文件历史（用真实存在文件）
    fhist = core.collect_file_history(REPO, 'packages/pqc-kem/src/ml-kem-768.js')
    checks.append(('file history non-empty', len(fhist) > 0))

    # 4) 负向：不存在的符号应返回空（不误报）
    neg = core.collect_timeline(REPO, 'this_symbol_should_not_exist_xyz', mode='-S')
    checks.append(('nonexistent symbol -> empty', len(neg) == 0))

    ok = True
    for name, passed in checks:
        print(('PASS ' if passed else 'FAIL ') + name)
        if not passed:
            ok = False
    print('\n[result] ' + ('ALL PASS' if ok else 'SOME FAILED'))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
