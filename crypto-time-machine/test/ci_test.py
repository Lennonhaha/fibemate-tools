#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto-time-machine CI 专用测试（零外部依赖，不依赖任何真实仓库）。

设计目标：CI 环境无 FIBEMATE 仓，不能跑 local_test.py（它硬编码本机路径）。
本测试自建一个带 2 个 commit 的临时 git 仓：
  - commit 1: 引入 `def foo()`
  - commit 2: 引入 `def bar()`
这样 `git log -S bar` 能追踪到 bar 的引入（单 commit 仓 -S 会返回空，这是 git 语义）。

覆盖：
1. collect_timeline(-S) 正向：bar 被追踪到（commit 2 引入）。
2. collect_timeline(-S) 负向：不存在符号返回空（不误报）。
3. collect_file_history 正向：a.py 有 2 条历史。
4. build_db + query_impact 往返一致。

所有结论基于真实 git 命令输出，不凭记忆。
"""
import os
import sys
import tempfile
import subprocess
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ctime import core


def build_temp_repo():
    d = tempfile.mkdtemp(prefix='ctm-ci-')
    subprocess.run(['git', 'init', '-q'], cwd=d, check=True)
    subprocess.run(['git', '-c', 'user.email=ci@test', '-c', 'user.name=CI',
                   'config', 'commit.gpgsign', 'false'], cwd=d, check=True)
    # commit 1: 引入 foo
    with open(os.path.join(d, 'a.py'), 'w', encoding='utf-8') as f:
        f.write('def foo():\n    pass\n')
    subprocess.run(['git', 'add', '.'], cwd=d, check=True)
    subprocess.run(['git', '-c', 'user.email=ci@test', '-c', 'user.name=CI',
                   'commit', '-q', '-m', 'add foo'], cwd=d, check=True)
    # commit 2: 引入 bar
    with open(os.path.join(d, 'a.py'), 'a', encoding='utf-8') as f:
        f.write('\ndef bar():\n    pass\n')
    subprocess.run(['git', 'add', '.'], cwd=d, check=True)
    subprocess.run(['git', '-c', 'user.email=ci@test', '-c', 'user.name=CI',
                   'commit', '-q', '-m', 'add bar'], cwd=d, check=True)
    return d


def main():
    checks = []
    d = build_temp_repo()
    try:
        # 1) 正向：-S 追踪 bar（commit 2 引入）
        rows = core.collect_timeline(d, 'bar', mode='-S')
        checks.append(('timeline tracks bar', len(rows) > 0))
        if rows:
            r0 = rows[0]
            checks.append(('bar sha 40 hex', len(r0['sha']) == 40 and all(c in '0123456789abcdef' for c in r0['sha'])))
            checks.append(('bar has iso date', 'T' in r0['date']))
            checks.append(('bar files is list', isinstance(r0['files'], list)))

        # 2) 负向：不存在符号必须空
        neg = core.collect_timeline(d, 'this_symbol_should_not_exist_xyz', mode='-S')
        checks.append(('nonexistent -> empty', len(neg) == 0))

        # 3) 文件历史正向
        fh = core.collect_file_history(d, 'a.py')
        checks.append(('file history == 2 commits', len(fh) == 2))

        # 4) build_db + query_impact 往返
        tmpdb = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmpdb.close()
        try:
            n = core.build_db(d, 'bar', tmpdb.name, mode='-S')
            checks.append(('db rows match timeline', n == len(rows)))
            imp = core.query_impact(tmpdb.name)
            checks.append(('query returns list', isinstance(imp, list) and len(imp) == n))
            if imp:
                checks.append(('query item has files', 'files' in imp[0]))
        finally:
            os.unlink(tmpdb.name)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    ok = True
    for name, passed in checks:
        print(('PASS ' if passed else 'FAIL ') + name)
        if not passed:
            ok = False
    print('\n[result] ' + ('ALL PASS' if ok else 'SOME FAILED'))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
