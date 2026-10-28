#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包契约测试：构建 → 检查内容 → 干净 venv 安装 → 跑真实 CLI。

判据（每条都能真的变红）：
1. sdist 与 wheel 都构建成功。
2. wheel 里有 ctime/cli.py 与 console script 元数据，能跑 --version / --help。
3. 包里不能有 timeline.db / *.db —— 那是本机分析产物，不是发布物。
4. wheel 不能带 test/（测试不属于运行期）。
5. 干净 venv 里安装后，用安装好的包对临时 git 仓跑一次，events 必须 > 0。
"""
import glob
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACT = []

sys.path.insert(0, ROOT)
from ctime import __version__ as EXPECTED_VERSION  # noqa: E402  (单源真相：pyproject 也读它)


def run(cmd, cwd=None, env=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print('FAIL command: %s' % ' '.join(cmd))
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        sys.exit(1)
    return r


def check(name, ok, detail=''):
    FACT.append((name, bool(ok), detail))
    print(('PASS ' if ok else 'FAIL ') + name + (('  [' + detail + ']') if detail and not ok else ''))


def main():
    work = tempfile.mkdtemp(prefix='ctm-pack-')
    dist = os.path.join(work, 'dist')
    try:
        run([sys.executable, '-m', 'build', '--outdir', dist], cwd=ROOT)
        wheels = glob.glob(os.path.join(dist, '*.whl'))
        sdists = glob.glob(os.path.join(dist, '*.tar.gz'))
        check('build produced a wheel', len(wheels) == 1, str(wheels))
        check('build produced an sdist', len(sdists) == 1, str(sdists))
        if not wheels or not sdists:
            return summarize()

        wheel, sdist = wheels[0], sdists[0]
        with zipfile.ZipFile(wheel) as z:
            names = z.namelist()
            eps = [n for n in names if n.endswith('entry_points.txt')]
            ep_body = z.read(eps[0]).decode('utf-8') if eps else ''
            has_db = [n for n in names if n.endswith('.db') or 'timeline.db' in n]
            has_test = [n for n in names if n.startswith('test/')]

        check('wheel has ctime/cli.py', 'ctime/cli.py' in names)
        check('wheel has ctime/__main__.py', 'ctime/__main__.py' in names)
        check('wheel declares the console script',
              'crypto-time-machine = ctime.cli:main' in ep_body, ep_body)
        check('wheel carries no database files', not has_db, str(has_db[:3]))
        check('wheel carries no test directory', not has_test, str(has_test[:3]))

        with tarfile.open(sdist) as t:
            sdist_names = t.getnames()
        check('sdist carries no database files',
              not [n for n in sdist_names if n.endswith('.db')],
              str([n for n in sdist_names if n.endswith('.db')][:3]))
        check('sdist carries README and LICENSE',
              any(n.endswith('/README.md') for n in sdist_names) and any(n.endswith('/LICENSE') for n in sdist_names))

        env_dir = os.path.join(work, 'venv')
        venv.EnvBuilder(with_pip=True, clear=True).create(env_dir)
        py = os.path.join(env_dir, 'Scripts' if os.name == 'nt' else 'bin', 'python')
        script = os.path.join(env_dir, 'Scripts' if os.name == 'nt' else 'bin',
                              'crypto-time-machine.exe' if os.name == 'nt' else 'crypto-time-machine')
        run([py, '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check',
             '--no-index', '--no-deps', wheel])

        check('console script installed', os.path.exists(script), script)
        ver = run([script, '--version']).stdout.strip()
        check('--version reports %s' % EXPECTED_VERSION, ver.endswith(EXPECTED_VERSION), ver)
        help_out = run([script, '--help']).stdout
        check('--help mentions --pattern', '--pattern' in help_out)

        repo = os.path.join(work, 'repo')
        os.makedirs(repo)
        gitenv = dict(os.environ)
        gitenv['GIT_CONFIG_NOSYSTEM'] = '1'
        gitenv['GIT_CONFIG_GLOBAL'] = os.devnull
        run(['git', 'init', '-q'], cwd=repo, env=gitenv)
        with open(os.path.join(repo, 'a.py'), 'w', encoding='utf-8') as f:
            f.write('def foo():\n    pass\n')
        run(['git', 'add', '.'], cwd=repo, env=gitenv)
        run(['git', '-c', 'user.email=ci@test', '-c', 'user.name=CI',
             'commit', '-q', '-m', 'add foo'], cwd=repo, env=gitenv)
        with open(os.path.join(repo, 'a.py'), 'a', encoding='utf-8') as f:
            f.write('\ndef bar():\n    return 42\n')
        run(['git', 'add', '.'], cwd=repo, env=gitenv)
        run(['git', '-c', 'user.email=ci@test', '-c', 'user.name=CI',
             'commit', '-q', '-m', 'add bar'], cwd=repo, env=gitenv)

        db = os.path.join(work, 't.db')
        out = run([script, '--repo', repo, '--pattern', 'bar', '--db', db]).stdout
        check('CLI run reports one event', 'events=1' in out, out.strip())
        check('CLI wrote the database', os.path.exists(db) and os.path.getsize(db) > 0)

        probe = run([py, '-c', 'import json,sys;from ctime.core import query_impact;'
                     'print(json.dumps(query_impact(sys.argv[1])))', db]).stdout
        check('installed package can query the timeline', '"bar"' in probe or 'files' in probe, probe[:200])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    return summarize()


def summarize():
    ok = all(f[1] for f in FACT)
    print('\n[result] ' + ('ALL PASS' if ok else 'SOME FAILED') + ' (%d checks)' % len(FACT))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
