#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto-time-machine — 密码依赖时间轴分析器（零外部依赖，仅标准库）

定位：把「某个密码学 API / 算法在哪个 commit 引入、何时变更、影响哪些文件」
变成可查询的时间轴。对应 FIBEMATE 纪律「不拿推测当事实」——用 git 真历史
而非记忆。

设计纪律：
- 只读 git 历史，不修改任何仓库。
- 所有结论基于 `git log -S/-G` 的真实匹配，不做语义猜测。
- 输出结构化 JSON，人工复核。
"""
import subprocess
import sqlite3
import json
import os
import re
import sys
from datetime import datetime, timezone

DEFAULT_REPO = '.'  # 默认分析当前目录；指定任意 git 仓用环境变量 CTM_REPO 覆盖
REPO = os.environ.get('CTM_REPO', DEFAULT_REPO)


class GitError(RuntimeError):
    """git exited non-zero. Carries stderr so the CLI can explain itself."""

    def __init__(self, args, stderr, returncode):
        self.args_list = args
        self.stderr = stderr or ''
        self.returncode = returncode
        super().__init__('git %s failed (exit %d): %s' % (' '.join(args), returncode, self.stderr.strip()[:300]))


class UnknownShaError(RuntimeError):
    """A sha the caller asked about is not in the timeline."""

    def __init__(self, sha):
        self.sha = sha
        super().__init__('unknown sha: %s' % sha)


def run_git(args, repo):
    # core.quotepath=false keeps non-ASCII paths as the author wrote them
    # instead of octal-escaped, double-quoted byte soup.
    cmd = ['git', '-c', 'core.quotepath=false', '-C', repo] + args
    # 只读分析工具应与宿主机 git 配置隔离：
    #   - GIT_CONFIG_NOSYSTEM=1  丢弃系统级配置（PortableGit 自带
    #     diff.astextplain.textconv=astextplain，而部分发行版缺 file.exe，
    #     遇到二进制 blob 会让 git log 直接报错——实测可复现）
    #   - GIT_CONFIG_GLOBAL=os.devnull  丢弃用户级配置（同理，防 global
    #     textconv / alias 干扰可复现输出）
    env = dict(os.environ)
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    env['GIT_CONFIG_GLOBAL'] = os.devnull
    r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', env=env)
    if r.returncode != 0:
        raise GitError(args, r.stderr, r.returncode)
    return r.stdout


def _unquote_path(line):
    """
    git quotes a path when it contains a quote, backslash or control character,
    even with core.quotepath=false. Undo that C-style quoting so callers get the
    path that exists on disk.
    """
    if len(line) >= 2 and line.startswith('"') and line.endswith('"'):
        body = line[1:-1]
        out = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == '\\' and i + 1 < len(body):
                nxt = body[i + 1]
                simple = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v',
                          '"': '"', '\\': '\\'}
                if nxt in simple:
                    out.append(simple[nxt])
                    i += 2
                    continue
                octal = body[i + 1:i + 4]
                if len(octal) == 3 and all(c in '01234567' for c in octal):
                    out.append(chr(int(octal, 8)))
                    i += 4
                    continue
            out.append(ch)
            i += 1
        return ''.join(out)
    return line


def parse_git_log(out):
    """
    解析 `git log --pretty=format:%H|%aI|%an|%s [--name-only]` 的原始输出为 rows。

    commit 头行 = 非空白缩进且能切成 4 段（sha|iso|author|subject）；
    其后缩进/独立行 = 该 commit 的受影响文件（仅 --name-only 时出现）。
    无文件行时 files 为空列表，语义统一。
    """
    rows = []
    current = None
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split('|', 3)
        if len(parts) >= 4 and not line.startswith(' '):
            # commit header line
            if current:
                rows.append(current)
            sha, iso, author, subject = parts
            current = {
                'sha': sha,
                'date': iso,
                'author': author,
                'subject': subject,
                'files': [],
            }
        else:
            # file name line (indented or just a path)
            if current is not None:
                current['files'].append(_unquote_path(line.strip()))
    if current:
        rows.append(current)
    return rows


def collect_timeline(repo, pattern, since=None, until=None, mode='-S'):
    """
    用 git log -S/-G 追踪某个符号/字符串的引入与变更历史。
    mode='-S' 追踪内容出现次数变化（增删）；mode='-G' 追踪差异行匹配。
    单次 git log --name-only 同时拿 commit 信息和受影响文件，避免 N+1 子进程。
    """
    if mode not in ('-S', '-G'):
        raise ValueError("mode must be -S or -G")
    # 用 --pretty + --name-only 一次拿到 commit 元数据和文件列表
    # Everything after '--' is a pathspec. A date flag placed there is silently
    # read as a filename: the filter stops filtering and can return zero rows.
    args = ['log', '--pretty=format:%H|%aI|%an|%s', '--name-only', mode + pattern]
    if since:
        args.append('--since=' + since)
    if until:
        args.append('--until=' + until)
    args.append('--')
    out = run_git(args, repo)
    return parse_git_log(out)


def collect_file_history(repo, filepath, since=None, until=None, follow=True):
    """某文件自身的提交历史（不是符号追踪）。follow=True 时加 --follow 追踪重命名。"""
    args = ['log', '--pretty=format:%H|%aI|%an|%s']
    if follow:
        args.append('--follow')
    # Same rule as collect_timeline: date flags are options, and options must
    # come before the path. Placed after '--' they become extra pathspecs, and
    # --follow then refuses to run ("requires exactly one pathspec").
    if since:
        args.append('--since=' + since)
    if until:
        args.append('--until=' + until)
    args += ['--', filepath]
    out = run_git(args, repo)
    return parse_git_log(out)


def build_db(repo, pattern, db_path, mode='-S', allow_empty=False):
    """
    把时间轴写入 SQLite，便于后续查询。

    Returns the number of events written, or -1 when the rebuild produced no
    matches while the table already held rows and --allow-empty was not given.
    In that case the existing rows are left untouched: "the pattern matched
    nothing" and "the timeline is empty" must not look the same.
    """
    rows = collect_timeline(repo, pattern, mode=mode)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS timeline (
        id INTEGER PRIMARY KEY, sha TEXT, date TEXT, author TEXT,
        subject TEXT, files TEXT)''')
    existing = c.execute('SELECT COUNT(*) FROM timeline').fetchone()[0]
    if not rows and existing and not allow_empty:
        conn.close()
        return -1
    c.execute('DELETE FROM timeline')
    for r in rows:
        c.execute('INSERT INTO timeline (sha, date, author, subject, files) VALUES (?,?,?,?,?)',
                  (r['sha'], r['date'], r['author'], r['subject'], json.dumps(r['files'])))
    conn.commit()
    conn.close()
    return len(rows)


def query_impact(db_path, after_sha=None):
    """影响分析：列出所有变更事件及受影响文件集合。"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    if after_sha:
        # 找到该 sha 的日期，返回其之后的所有变更
        row = c.execute('SELECT date FROM timeline WHERE sha=?', (after_sha,)).fetchone()
        if not row:
            conn.close()
            raise UnknownShaError(after_sha)
        c.execute('SELECT sha,date,author,subject,files FROM timeline WHERE date > ? ORDER BY date', (row[0],))
    else:
        c.execute('SELECT sha,date,author,subject,files FROM timeline ORDER BY date')
    out = []
    for sha, date, author, subject, files in c.fetchall():
        out.append({'sha': sha, 'date': date, 'author': author,
                    'subject': subject, 'files': json.loads(files)})
    conn.close()
    return out


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='crypto-time-machine')
    p.add_argument('--repo', default=REPO)
    p.add_argument('--pattern', required=True, help='追踪的符号/字符串，如 ml_kem768')
    p.add_argument('--mode', default='-S', choices=['-S', '-G'])
    p.add_argument('--db', default=None, help='SQLite 输出路径')
    p.add_argument('--since', default=None)
    p.add_argument('--until', default=None)
    p.add_argument('--query-after', default=None, help='仅分析某 sha 之后的影响')
    p.add_argument('--allow-empty', action='store_true',
                   help='允许用空结果覆盖已有时间轴（默认拒绝）')
    a = p.parse_args()
    db = a.db or (os.path.join(os.path.dirname(__file__), '..', 'timeline.db'))

    try:
        n = build_db(a.repo, a.pattern, db, mode=a.mode, allow_empty=a.allow_empty)
    except GitError as e:
        if 'not a git repository' in e.stderr.lower():
            sys.stderr.write('[time-machine] error: not a git repository: %s\n' % a.repo)
        else:
            sys.stderr.write('[time-machine] error: git failed: %s\n' % e.stderr.strip()[:300])
        sys.exit(2)

    if n == -1:
        sys.stderr.write(
            '[time-machine] error: pattern %r matched nothing; existing timeline left '
            'untouched (pass --allow-empty to overwrite)\n' % a.pattern)
        sys.exit(2)

    print(f"[time-machine] pattern={a.pattern} mode={a.mode} events={n} db={db}")

    if a.query_after:
        try:
            imp = query_impact(db, a.query_after)
        except UnknownShaError as e:
            sys.stderr.write('[time-machine] error: unknown sha in --query-after: %s\n' % e.sha)
            sys.exit(2)
        print(json.dumps(imp, indent=2, ensure_ascii=False))

