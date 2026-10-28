#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crypto-time-machine 的命令行入口。

判定逻辑全在 core.py；这里只做参数解析、错误码映射和输出。
console script（crypto-time-machine）、"python -m ctime" 与
"python ctime/core.py" 三条路径共用本模块，行为一致。
"""
import argparse
import json
import os
import sys

from . import __version__
from .core import REPO, GitError, UnknownShaError, build_db, query_impact


def build_parser():
    p = argparse.ArgumentParser(
        prog='crypto-time-machine',
        description='crypto-time-machine — 用 git 真历史回答「某个 API 何时引入/变更/影响了哪些文件」。',
    )
    p.add_argument('--repo', default=REPO, help='待分析的 git 仓库（默认当前目录，可用 CTM_REPO 覆盖）')
    p.add_argument('--pattern', required=True, help='追踪的符号/字符串，如 ml_kem768')
    p.add_argument('--mode', default='-S', choices=['-S', '-G'], help='git log 匹配模式（-S 内容变化 / -G diff 命中）')
    p.add_argument('--db', default=None, help='SQLite 输出路径（默认 ./timeline.db）')
    p.add_argument('--since', default=None)
    p.add_argument('--until', default=None)
    p.add_argument('--query-after', default=None, help='仅分析某 sha 之后的影响')
    p.add_argument('--allow-empty', action='store_true',
                   help='允许用空结果覆盖已有时间轴（默认拒绝）')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    db = a.db or os.path.join(os.getcwd(), 'timeline.db')

    try:
        n = build_db(a.repo, a.pattern, db, mode=a.mode, allow_empty=a.allow_empty)
    except GitError as e:
        if 'not a git repository' in e.stderr.lower():
            sys.stderr.write('[time-machine] error: not a git repository: %s\n' % a.repo)
        else:
            sys.stderr.write('[time-machine] error: git failed: %s\n' % e.stderr.strip()[:300])
        return 2

    if n == -1:
        sys.stderr.write(
            "[time-machine] error: pattern %r matched nothing; existing timeline left "
            'untouched (pass --allow-empty to overwrite)\n' % a.pattern)
        return 2

    print(f"[time-machine] pattern={a.pattern} mode={a.mode} events={n} db={db}")

    if a.query_after:
        try:
            imp = query_impact(db, a.query_after)
        except UnknownShaError as e:
            sys.stderr.write('[time-machine] error: unknown sha in --query-after: %s\n' % e.sha)
            return 2
        print(json.dumps(imp, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
