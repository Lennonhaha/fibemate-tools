// SPDX-License-Identifier: Apache-2.0
//
// Red contract tests for crypto-time-ledger.
//
// Each test states a guarantee the tool is supposed to offer. Tests that fail
// today are the defect list, not a broken suite: run
//   node --experimental-strip-types --test test/red-contract.test.ts
// and read the failures as the work to do. Nothing here is mocked away —
// every CLI assertion spawns the real entry point against a real SQLite store.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

import { computeHash, type LedgerBlock } from '../src/core.ts';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', 'src', 'cli.ts');

function runCli(args: string[], cwd?: string) {
  const r = spawnSync(process.execPath, ['--experimental-strip-types', CLI, ...args], {
    encoding: 'utf8',
    cwd: cwd ?? here,
  });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'ctl-red-'));
}

function block(index: number, prev: string, tsrDigest = '', note = ''): LedgerBlock {
  const b: LedgerBlock = {
    schema_version: 1,
    index,
    ts: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
    state: {
      algorithms: [{ name: 'ML-KEM-768', version: `1.0.${index}`, lib: 'noble' }],
      git_commit: 'a'.repeat(40),
      note,
    },
    tsr_digest: tsrDigest,
    tsr_ref: tsrDigest ? `tsr/${tsrDigest.replace(/^sha256:/, '')}.tsr` : '',
    hash_prev: prev,
    hash_now: '',
  };
  b.hash_now = computeHash(b);
  return b;
}

function chain(n: number): LedgerBlock[] {
  const out: LedgerBlock[] = [];
  let prev = 'genesis';
  for (let i = 0; i < n; i++) {
    const b = block(i, prev);
    out.push(b);
    prev = b.hash_now;
  }
  return out;
}

function seedStore(dbPath: string, blocks: LedgerBlock[]): void {
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY, hash_prev TEXT NOT NULL, hash_now TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL, schema_version INTEGER NOT NULL, state_json TEXT NOT NULL,
    tsr_digest TEXT NOT NULL, tsr_ref TEXT NOT NULL, raw_json TEXT NOT NULL);`);
  for (const b of blocks) {
    db.prepare(
      `INSERT INTO blocks (idx, hash_prev, hash_now, ts, schema_version, state_json, tsr_digest, tsr_ref, raw_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(b.index, b.hash_prev, b.hash_now, b.ts, b.schema_version, JSON.stringify(b.state), b.tsr_digest, b.tsr_ref, JSON.stringify(b));
  }
  db.close();
}

function countRows(dbPath: string): number {
  if (!existsSync(dbPath)) return 0;
  const db = new DatabaseSync(dbPath);
  const row = db.prepare('SELECT COUNT(*) AS n FROM blocks').get() as unknown as { n: number };
  db.close();
  return row.n;
}

function rewriteRows(dbPath: string, mutate: (b: LedgerBlock) => LedgerBlock | null): void {
  const db = new DatabaseSync(dbPath);
  const rows = db.prepare('SELECT raw_json FROM blocks ORDER BY idx').all() as unknown as Array<{ raw_json: string }>;
  const kept: LedgerBlock[] = [];
  for (const r of rows) {
    const next = mutate(JSON.parse(r.raw_json) as LedgerBlock);
    if (next) kept.push(next);
  }
  db.exec('DELETE FROM blocks');
  db.close();
  seedStore(dbPath, kept);
}

/* ------------------------------------------------------------------ */
/* A. 篡改验签                                                         */
/* ------------------------------------------------------------------ */

test('A1 · genesis block with hash_prev != "genesis" must not verify', () => {
  // The store layer refuses this on append, so the only way it exists is a
  // rewritten database — exactly the case verify() exists to catch.
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  const b0 = block(0, 'attacker-supplied-predecessor');
  seedStore(db, [b0]);

  const r = runCli(['verify', '--store', db]);
  assert.notEqual(r.code, 0, `verify accepted a chain whose genesis block has hash_prev=${b0.hash_prev}\n${r.out}`);
});

test('A2 · an empty store must not report a successful verification', () => {
  const dir = tempDir();
  const db = join(dir, 'empty.db');
  const r = runCli(['verify', '--store', db]);
  assert.notEqual(r.code, 0, `verify exited ${r.code} on an empty store: "${r.out.trim()}"`);
});

test('A3 · a rejected block must not be written to the store', () => {
  // Block references a TSR digest but no --tsr is supplied, so `add` must
  // refuse. After the refusal the store has to look untouched: an append that
  // happens before validation is a half-write the operator cannot see.
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  const b0 = block(0, 'genesis', 'sha256:' + 'b'.repeat(64));
  const blockFile = join(dir, 'b0.json');
  writeFileSync(blockFile, JSON.stringify(b0), 'utf8');

  const r = runCli(['add', blockFile, '--store', db]);
  assert.notEqual(r.code, 0, 'add should have refused a block with an unverifiable TSR');
  assert.equal(countRows(db), 0, 'the refused block is still in the ledger');
});

test('A4 · editing a stored algorithm version breaks verify', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(2));
  rewriteRows(db, (b) => {
    if (b.index !== 1) return b;
    b.state.algorithms[0].version = '9.9.9';
    return b;
  });
  const r = runCli(['verify', '--store', db]);
  assert.notEqual(r.code, 0, 'a mutated algorithm version still verified');
});

test('A5 · editing a stored tsr_digest breaks verify', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(2));
  rewriteRows(db, (b) => {
    if (b.index !== 0) return b;
    b.tsr_digest = 'sha256:' + 'c'.repeat(64);
    return b;
  });
  const r = runCli(['verify', '--store', db]);
  assert.notEqual(r.code, 0, 'a mutated tsr_digest still verified');
});

test('A6 · deleting a middle block breaks verify', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(3));
  rewriteRows(db, (b) => (b.index === 1 ? null : b));
  const r = runCli(['verify', '--store', db]);
  assert.notEqual(r.code, 0, 'a chain with a removed block still verified');
});

/* ------------------------------------------------------------------ */
/* B. bundle 同步契约                                                  */
/* ------------------------------------------------------------------ */

test('B1 · `bundle export` produces a self-contained directory', () => {
  // 契约：一个 bundle 目录 = chain.json + tsr/ + pinned-certs.pem + manifest.json，
  // 其中 manifest 记录每个文件的 sha256。第三方拿到目录即可离线复验，
  // 不需要再访问本机 SQLite，也不需要知道原仓库路径。
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(2));
  const out = join(dir, 'bundle');

  const r = runCli(['bundle', 'export', '--store', db, '--out', out]);
  assert.equal(r.code, 0, `bundle export is not implemented: ${r.out.trim()}`);
  for (const f of ['chain.json', 'manifest.json']) {
    assert.ok(existsSync(join(out, f)), `bundle is missing ${f}`);
  }
  const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) as Record<string, unknown>;
  assert.ok(manifest.files && typeof manifest.files === 'object', 'manifest does not list file digests');
});

test('B2 · a bundle that lost a byte must be refused by `bundle verify`', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(2));
  const out = join(dir, 'bundle');
  const exported = runCli(['bundle', 'export', '--store', db, '--out', out]);
  assert.equal(exported.code, 0, `bundle export is not implemented: ${exported.out.trim()}`);

  const chainFile = join(out, 'chain.json');
  const original = readFileSync(chainFile, 'utf8');
  writeFileSync(chainFile, original.replace('1.0.1', '1.0.9'), 'utf8');

  const r = runCli(['bundle', 'verify', '--dir', out]);
  assert.notEqual(r.code, 0, 'a tampered bundle verified clean');
});

/* ------------------------------------------------------------------ */
/* C. 离线渲染                                                         */
/* ------------------------------------------------------------------ */

test('C1 · bundle ships a renderer that works with no network', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(2));
  const out = join(dir, 'bundle');
  const exported = runCli(['bundle', 'export', '--store', db, '--out', out]);
  assert.equal(exported.code, 0, `bundle export is not implemented: ${exported.out.trim()}`);

  const htmlPath = join(out, 'index.html');
  assert.ok(existsSync(htmlPath), 'bundle has no offline renderer (index.html)');

  const html = readFileSync(htmlPath, 'utf8');
  const external = html.match(/(?:src|href)\s*=\s*["'](https?:)?\/\//gi) || [];
  assert.deepEqual(external, [], `renderer loads ${external.length} external asset(s); it must work offline`);
  assert.ok(html.includes('ML-KEM-768'), 'renderer does not carry the chain data inline');
});

test('C2 · offline renderer shows the same block count as the CLI', () => {
  const dir = tempDir();
  const db = join(dir, 'ledger.db');
  seedStore(db, chain(3));
  const out = join(dir, 'bundle');
  const exported = runCli(['bundle', 'export', '--store', db, '--out', out]);
  assert.equal(exported.code, 0, `bundle export is not implemented: ${exported.out.trim()}`);

  const html = readFileSync(join(out, 'index.html'), 'utf8');
  assert.ok(/\b3\b/.test(html), 'renderer does not state the block count');
});
