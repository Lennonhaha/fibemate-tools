#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Red contract tests for crypto-time-machine.

Every test states a guarantee the tool is supposed to offer. A failure here is
a line on the defect list, not a broken suite:

    python test/red_contract_test.py

The fixtures are real git repositories built in a temp directory, so the
tool is exercised against actual history rather than mocked output.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, 'ctime', 'core.py')

sys.path.insert(0, ROOT)
from ctime import core  # noqa: E402


def git(repo, *args, date=None):
    env = dict(os.environ)
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    env['GIT_CONFIG_GLOBAL'] = os.devnull
    if date:
        env['GIT_AUTHOR_DATE'] = date
        env['GIT_COMMITTER_DATE'] = date
    return subprocess.run(
        ['git', '-C', repo] + list(args),
        capture_output=True, text=True, env=env, check=True,
    ).stdout


def init_repo(path):
    os.makedirs(path, exist_ok=True)
    git(path, 'init', '-q', '-b', 'main')
    git(path, '-c', 'user.name=T', '-c', 'user.email=t@example.com', 'commit',
        '--allow-empty', '-q', '-m', 'root', date='2025-12-31T00:00:00Z')


def commit_file(repo, name, content, message, date):
    with open(os.path.join(repo, name), 'w', encoding='utf-8') as fh:
        fh.write(content)
    git(repo, 'add', name)
    git(repo, '-c', 'user.name=T', '-c', 'user.email=t@example.com', 'commit',
        '-q', '-m', message, date=date)
    return git(repo, 'rev-parse', 'HEAD').strip()


class ThreeCommitRepo:
    """c1 introduces the symbol, c2 adds a second occurrence, c3 removes both."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix='ctm-red-')
        self.repo = os.path.join(self.dir, 'repo')
        init_repo(self.repo)
        self.c1 = commit_file(self.repo, 'a.txt', 'kem = ml_kem768\n', 'feat: add ml_kem768',
                              '2026-01-01T00:00:00Z')
        self.c2 = commit_file(self.repo, 'a.txt', 'kem = ml_kem768\nbackup = ml_kem768\n',
                              'fix: keep ml_kem768 fallback', '2026-01-02T00:00:00Z')
        self.c3 = commit_file(self.repo, 'a.txt', 'kem = ml_kem1024\n',
                              'refactor: drop ml_kem768', '2026-01-03T00:00:00Z')
        self.db = os.path.join(self.dir, 'timeline.db')
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def run_cli(args):
    r = subprocess.run(
        [sys.executable, CORE] + args,
        capture_output=True, text=True, cwd=ROOT,
    )
    return r.returncode, (r.stdout or '') + (r.stderr or '')


class TimelineContract(unittest.TestCase):
    def test_three_commits_are_all_reported_in_order(self):
        with ThreeCommitRepo() as f:
            rows = core.collect_timeline(f.repo, 'ml_kem768')
            shas = [r['sha'] for r in rows]
            self.assertEqual(
                sorted(shas), sorted([f.c1, f.c2, f.c3]),
                'a three-commit history must yield three events, one per commit',
            )
            self.assertEqual(shas[0], f.c3, 'git log order is newest-first; the tool must preserve it')

    def test_since_filter_actually_filters(self):
        # Bug under test: since/until are appended after `--`, so git treats
        # them as pathspecs. The filter silently returns nothing instead of
        # returning the commits inside the window.
        with ThreeCommitRepo() as f:
            rows = core.collect_timeline(f.repo, 'ml_kem768', since='2026-01-02T12:00:00Z')
            self.assertEqual(
                [r['sha'] for r in rows], [f.c3],
                'since=2026-01-02T12:00 must return only the 2026-01-03 commit',
            )

    def test_until_filter_actually_filters(self):
        with ThreeCommitRepo() as f:
            rows = core.collect_timeline(f.repo, 'ml_kem768', until='2026-01-02T12:00:00Z')
            self.assertEqual(
                [r['sha'] for r in rows], [f.c2, f.c1],
                'until=2026-01-02T12:00 must return the two earlier commits, newest first',
            )

    def test_file_history_since_filter(self):
        with ThreeCommitRepo() as f:
            rows = core.collect_file_history(f.repo, 'a.txt', since='2026-01-02T12:00:00Z')
            self.assertEqual(
                [r['sha'] for r in rows], [f.c3],
                'file history must honour since as well',
            )


class CliContract(unittest.TestCase):
    def test_non_git_directory_exits_with_a_message_not_a_traceback(self):
        d = tempfile.mkdtemp(prefix='ctm-nogit-')
        try:
            code, out = run_cli(['--repo', d, '--pattern', 'ml_kem768',
                                 '--db', os.path.join(d, 'x.db')])
            self.assertNotEqual(code, 0, 'a non-git directory must not exit 0')
            self.assertEqual(code, 2, 'expected a dedicated exit code (2) for "not a git repository", got %s' % code)
            self.assertNotIn('Traceback', out, 'the CLI leaked a traceback instead of a structured error')
            self.assertIn('not a git repository', out.lower(), 'the message must say what is wrong')
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unknown_query_after_sha_is_an_error(self):
        with ThreeCommitRepo() as f:
            code, out = run_cli(['--repo', f.repo, '--pattern', 'ml_kem768',
                                 '--db', f.db, '--query-after', 'f' * 40])
            self.assertNotEqual(code, 0, 'an unknown --query-after sha must not be silently treated as "all"')
            self.assertIn('unknown', out.lower(), 'the error must name the unknown sha')

    def test_empty_result_does_not_wipe_the_existing_database(self):
        # A typo in --pattern must not destroy the timeline the operator
        # already has. Either refuse, or keep the old rows; silently writing
        # an empty table makes "no matches" indistinguishable from "lost data".
        with ThreeCommitRepo() as f:
            core.build_db(f.repo, 'ml_kem768', f.db)
            before = len(core.query_impact(f.db))
            core.build_db(f.repo, 'no_such_symbol_anywhere', f.db)
            after = len(core.query_impact(f.db))
            self.assertEqual(
                after, before,
                'rebuilding with a non-matching pattern wiped %d existing events' % before,
            )


class ParseContract(unittest.TestCase):
    def test_subject_containing_pipe_survives(self):
        with tempfile.TemporaryDirectory() as d:
            init_repo(d)
            commit_file(d, 'a.txt', 'ml_kem768\n', 'feat: a|b|c partition', '2026-02-01T00:00:00Z')
            rows = core.collect_timeline(d, 'ml_kem768')
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['subject'], 'feat: a|b|c partition')

    def test_file_path_containing_pipe_is_not_read_as_a_commit(self):
        # Windows forbids '|' in filenames, so exercise the parser directly with
        # the exact byte shape `git log --pretty=format:... --name-only` emits.
        raw = 'a' * 40 + '|2026-02-01T00:00:00Z|T|feat: odd path\nweird|name.txt\n'
        rows = core.parse_git_log(raw)
        self.assertEqual(len(rows), 1, 'a filename with pipes produced %d rows' % len(rows))
        self.assertEqual(rows[0]['files'], ['weird|name.txt'])

    def test_non_ascii_path_is_reported_as_written(self):
        # git quotes non-ASCII paths as octal escapes unless core.quotepath is
        # off, so the timeline would show \346\226\207\346\241\243.md instead of
        # the name the author actually used.
        with tempfile.TemporaryDirectory() as d:
            init_repo(d)
            commit_file(d, '\u4e2d\u6587.md', 'ml_kem768\n', 'feat: \u4e2d\u6587\u6587\u4ef6', '2026-02-01T00:00:00Z')
            rows = core.collect_timeline(d, 'ml_kem768')
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['files'], ['\u4e2d\u6587.md'],
                             'non-ASCII path came back as %r' % (rows[0]['files'],))


if __name__ == '__main__':
    unittest.main(verbosity=2)
