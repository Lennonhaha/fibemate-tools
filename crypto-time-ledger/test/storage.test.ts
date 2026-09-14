import test from "node:test";
import assert from "node:assert/strict";
import { computeHash, type LedgerBlock } from "../src/core.ts";
import { SqliteLedgerStore, StorageError, ChainError } from "../src/storage.ts";

function makeBlock(index: number, hashPrev: string, over: Partial<LedgerBlock> = {}): LedgerBlock {
  const b: LedgerBlock = {
    schema_version: 1,
    index,
    ts: "2026-09-14T00:00:00Z",
    state: {
      algorithms: [{ name: "ML-KEM-768", version: "1.0", lib: "noble" }],
      git_commit: "abc123",
      note: "seed",
    },
    hash_prev: hashPrev,
    hash_now: "",
    tsr_digest: "",
    tsr_ref: "",
    ...over,
  };
  b.hash_now = computeHash(b);
  return b;
}

test("open + append genesis + getChain returns 1", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  await s.appendBlock(makeBlock(0, "genesis"));
  const chain = await s.getChain();
  assert.equal(chain.length, 1);
  assert.equal(chain[0].index, 0);
  await s.close();
});

test("appendBlock rejects bad hash_now", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  const b = makeBlock(0, "genesis");
  b.hash_now = "sha256:tampered";
  await assert.rejects(() => s.appendBlock(b), ChainError);
  await s.close();
});

test("chain links + continuity enforced", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  const b0 = makeBlock(0, "genesis");
  await s.appendBlock(b0);
  const b1 = makeBlock(1, b0.hash_now);
  await s.appendBlock(b1);
  // gap: index 3 without 2
  const b3 = makeBlock(3, b1.hash_now);
  await assert.rejects(() => s.appendBlock(b3), ChainError);
  // wrong hash_prev
  const b2bad = makeBlock(2, "wrongprev");
  await assert.rejects(() => s.appendBlock(b2bad), ChainError);
  // correct
  const b2 = makeBlock(2, b1.hash_now);
  await s.appendBlock(b2);
  const chain = await s.getChain();
  assert.equal(chain.length, 3);
  assert.equal(await s.count(), 3);
  const latest = await s.getLatest();
  assert.equal(latest?.index, 2);
  await s.close();
});

test("duplicate hash_now rejected", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  const b0 = makeBlock(0, "genesis");
  await s.appendBlock(b0);
  const dup = makeBlock(1, "genesis");
  dup.hash_now = b0.hash_now; // force UNIQUE collision on hash_now
  await assert.rejects(() => s.appendBlock(dup), ChainError);
  await s.close();
});

test("concurrent appendBlock same index serializes", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  await s.appendBlock(makeBlock(0, "genesis"));
  const prev = (await s.getLatest())!.hash_now;
  const b1 = makeBlock(1, prev);
  const b2 = makeBlock(1, prev);
  // Both target index 1. The synchronous transaction body (no await between read and
  // INSERT) means b1 fully commits before b2's check runs, so exactly one lands.
  const results = await Promise.allSettled([s.appendBlock(b1), s.appendBlock(b2)]);
  const rejected = results.filter((r) => r.status === "rejected").length;
  assert.equal(rejected, 1);
  assert.equal(await s.count(), 2);
  await s.close();
});

test("query filters + export json/csv", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  const b0 = makeBlock(0, "genesis", {
    state: { algorithms: [{ name: "ML-KEM-768", version: "1.0", lib: "noble" }], git_commit: "g0", note: "n0" },
  });
  await s.appendBlock(b0);
  const b1 = makeBlock(1, b0.hash_now, {
    state: { algorithms: [{ name: "ML-DSA-65", version: "2.0", lib: "noble" }], git_commit: "g1", note: "n1" },
  });
  await s.appendBlock(b1);

  const mlkem = await s.query((b) => b.state.algorithms.some((a) => a.name === "ML-KEM-768"));
  assert.equal(mlkem.length, 1);

  const json = await s.export("json");
  const parsed = JSON.parse(json) as LedgerBlock[];
  assert.equal(parsed.length, 2);

  const csv = await s.export("csv");
  const lines = csv.split("\n");
  assert.equal(lines[0], "index,ts,algorithm_name,algorithm_version,algorithm_lib,git_commit,note,hash_now,tsr_attached");
  // 2 blocks x 1 algorithm each = 2 data rows
  assert.equal(lines.length, 3);
  assert.ok(lines[2].includes("ML-DSA-65"));
  assert.ok(lines[1].includes("ML-KEM-768"));
  await s.close();
});

test("getBlockByIndex + empty store", async () => {
  const s = new SqliteLedgerStore();
  await s.open(":memory:");
  assert.equal(await s.getLatest(), null);
  assert.equal(await s.count(), 0);
  assert.equal(await s.getBlockByIndex(0), null);
  await s.close();
});

test("append before open throws StorageError", async () => {
  const s = new SqliteLedgerStore();
  await assert.rejects(() => s.appendBlock(makeBlock(0, "genesis")), StorageError);
});
