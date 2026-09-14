import { test } from "node:test";
import assert from "node:assert/strict";
import {
  computeHash,
  verifyChain,
  type LedgerBlock,
  type VerifyTSR,
} from "../src/core.ts";

function makeState() {
  return {
    algorithms: [{ name: "ML-KEM-768", version: "0.7.0", lib: "noble-pq" }],
    git_commit: "64092fb9ed9cfd7e419b8fac5fce9497232f49be",
    note: "test block",
  };
}

function makeBlock(index: number, hashPrev: string): LedgerBlock {
  const b: LedgerBlock = {
    schema_version: 1,
    index,
    ts: "2026-09-14T12:00:00Z",
    state: makeState(),
    tsr_digest: "sha256:abc",
    tsr_ref: "tsr/2026-09-14T12:00:00Z.tsr",
    hash_prev: hashPrev,
    hash_now: "placeholder",
  };
  b.hash_now = computeHash(b);
  return b;
}

const okTsr: VerifyTSR = () => true;

test("computeHash deterministic", () => {
  const a = makeBlock(0, "genesis");
  const b = makeBlock(0, "genesis");
  assert.equal(a.hash_now, b.hash_now);
});

test("verifyChain happy path (2 blocks)", () => {
  const b0 = makeBlock(0, "genesis");
  const b1 = makeBlock(1, b0.hash_now);
  const r = verifyChain([b0, b1], okTsr);
  assert.equal(r.ok, true);
});

test("verifyChain index gap", () => {
  const b0 = makeBlock(0, "genesis");
  const b1 = makeBlock(2, b0.hash_now); // index 2, expected 1
  const r = verifyChain([b0, b1], okTsr);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "index gap");
  assert.equal(r.failedAt, 2);
});

test("verifyChain hash_prev mismatch", () => {
  const b0 = makeBlock(0, "genesis");
  const b1 = makeBlock(1, "wrongprev");
  const r = verifyChain([b0, b1], okTsr);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "hash_prev mismatch");
});

test("verifyChain hash_now mismatch (tampered state)", () => {
  const b0 = makeBlock(0, "genesis");
  const b1 = makeBlock(1, b0.hash_now);
  b1.state.note = "tampered"; // 改 state 但 hash_now 未重算
  const r = verifyChain([b0, b1], okTsr);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "hash_now mismatch");
});

test("verifyChain TSR invalid", () => {
  const b0 = makeBlock(0, "genesis");
  const b1 = makeBlock(1, b0.hash_now);
  const failTsr: VerifyTSR = () => false;
  const r = verifyChain([b0, b1], failTsr);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "TSR invalid");
});

test("canonicalize excludes tsr_ref (move file keeps hash)", () => {
  const a = makeBlock(0, "genesis");
  const b = makeBlock(0, "genesis");
  b.tsr_ref = "tsr/MOVED.tsr"; // 改路径，不改内容锚
  assert.equal(computeHash(a), computeHash(b));
});

test("canonicalize binds tsr_digest (change content => hash changes)", () => {
  const a = makeBlock(0, "genesis");
  const b = makeBlock(0, "genesis");
  b.tsr_digest = "sha256:different";
  assert.notEqual(computeHash(a), computeHash(b));
});

test("state.note in hash (change note => hash changes)", () => {
  const a = makeBlock(0, "genesis");
  const b = makeBlock(0, "genesis");
  b.state.note = "different note";
  assert.notEqual(computeHash(a), computeHash(b));
});

test("U+2028 in note keeps hash stable across identical input", () => {
  const sep = String.fromCharCode(0x2028); // 真实 U+2028 字符（源码零字面，运行时 1 字符）
  const a = makeBlock(0, "genesis");
  a.state.note = "line1" + sep + "line2";
  const b = makeBlock(0, "genesis");
  b.state.note = "line1" + sep + "line2";
  assert.equal(computeHash(a), computeHash(b));
  assert.ok(computeHash(a).startsWith("sha256:"));
});

// #10 加强：证明转义真的发生（而非「两边同错仍相等」假绿）
// 若 RE_U2028 被误删：a 的 real U+2028 原样序列化（1 字符）≠ b 的 6 字符字面 → hash 不等 → 此测 FAIL
test("U+2028 is escaped to \\u2028 (not passed through raw)", () => {
  const sep = String.fromCharCode(0x2028); // 运行时 1 个真字符
  const a = makeBlock(0, "genesis");
  a.state.note = "x" + sep + "y"; // 含真 U+2028
  const b = makeBlock(0, "genesis");
  b.state.note = "x\u2028y"; // 6 字符字面（已转义形式）
  // 转义生效：a 真字符被转义成 \u2028（6 字符）→ 与 b 完全相同的序列化 → hash 相等
  assert.equal(computeHash(a), computeHash(b));
});

test("verifyChain empty chain returns ok", () => {
  const r = verifyChain([], okTsr);
  assert.equal(r.ok, true);
});

test("verifyChain single genesis block returns ok", () => {
  const b0 = makeBlock(0, "genesis");
  const r = verifyChain([b0], okTsr);
  assert.equal(r.ok, true);
});
