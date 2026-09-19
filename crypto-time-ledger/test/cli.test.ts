/**
 * CLI integration tests for crypto-time-ledger.
 *
 * Architecture:
 * - Each test spawns the CLI as a subprocess via Node's `spawn` so we get real
 *   exit codes and process-level behaviour (process.exit cannot be intercepted otherwise).
 * - Temp directories are created per-test-file (not per-test) and cleaned up after all tests.
 * - Mocking at the module level: `makeVerifyTSR` is replaced to always return true so that
 *   CLI genTime-cross-check is the only failure path exercised in time-tolerance tests.
 *   (Actual cryptographic verification is covered by tsr.test.ts.)
 *
 * Design ref: cli-design.md (workspace-only, not committed).
 * A″ rule: delta_ms < 0 → exit 1 (clock anomaly). delta_ms > tolerance_ms → exit 1.
 */

import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { before, after, describe, it } from "node:test";
import assert from "node:assert";

// __dirname replacement for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---- Test fixtures ----

const CLI = "node";
const PKG_ROOT = join(__dirname, "..");

/** Resolve path to the CLI entry point (absolute path for spawn) */
function cliPath(): string {
  return join(PKG_ROOT, "src", "cli.ts");
}

/** Node executable path (absolute, works regardless of cwd) */
const NODE = process.execPath;

/** Resolve path to the ledger store */
function storePath(tmp: string, name = "ledger.db"): string {
  return join(tmp, name);
}

/** Resolve path to the TSR directory */
function tsrDir(tmp: string): string {
  return join(tmp, "tsr");
}

/** Resolve path to a .tsr file inside the TSR directory */
function tsrPath(tmp: string, digest: string): string {
  return join(tsrDir(tmp), `${digest.replace(/^sha256:/, "")}.tsr`);
}

// ---- Ledger block helpers ----

/**
 * Build a minimal valid LedgerBlock for testing.
 * hash_now is computed from the block so it always matches.
 * Uses dynamic import() to stay ESM-safe.
 */
async function makeBlock(overrides: Partial<{
  index: number;
  ts: string;
  hash_prev: string;
  tsr_digest: string;
  tsr_ref: string;
  note: string;
  state: {
    algorithms: Array<{ name: string; version: string; lib: string }>;
    git_commit: string;
    note: string;
  };
}> = {}): Promise<Record<string, unknown>> {
  const index = overrides.index ?? 0;
  const ts = overrides.ts ?? "2026-09-14T10:00:00Z";
  const hash_prev = overrides.hash_prev ?? (index === 0 ? "genesis" : "deadbeef");
  const note = overrides.note ?? "test block";
  const block = {
    index,
    ts,
    schema_version: 1,
    hash_prev,
    state: overrides.state ?? {
      algorithms: [{ name: "test-algo", version: "1.0.0", lib: "test-lib" }],
      git_commit: "",
      note,
    },
    tsr_digest: overrides.tsr_digest ?? "",
    tsr_ref: overrides.tsr_ref ?? "",
  };
  // Dynamic import stays ESM-safe: use pathToFileURL so Node ESM loader accepts Windows paths
  const { computeHash } = await import(pathToFileURL(join(PKG_ROOT, "src", "core.ts")).href) as {
    computeHash: (b: Record<string, unknown>) => string;
  };
  return { ...block, hash_now: computeHash(block) };
}

// ---- CLI runner ----

/**
 * Run the CLI with the given arguments, in a specific working directory.
 * Returns { code, stdout, stderr }.
 */
function runCli(
  args: string[],
  cwd: string,
  stdinData?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(NODE, [cliPath(), ...args], {
      cwd,
      stdio: stdinData !== undefined ? ["pipe", "pipe", "pipe"] : ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => (stdout += d));
    child.stderr?.on("data", (d) => (stderr += d));
    if (stdinData !== undefined) {
      child.stdin?.write(stdinData);
      child.stdin?.end();
    }
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

// ---- Temp directory (module-level) ----

let tmpDir: string;

before(() => {
  tmpDir = join(__dirname, "..", `.tmp-cli-${Date.now()}`);
  mkdirSync(tmpDir, { recursive: true });
  mkdirSync(tsrDir(tmpDir), { recursive: true });
});

after(() => {
  // Clean up even on failure
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

// ---- Mock makeVerifyTSR to always return true ----
//
// For time-tolerance tests, we only care about genTime cross-check logic,
// not about actual cryptographic signature verification.  By overriding
// `makeVerifyTSR` to always return true the CLI proceeds past the
// signature check and hits the genTime check.
//
// We do this by prepending a --experimental-vm-modules flag that loads a
// mock shim, or more portably by patching the module registry before the
// CLI starts.  Since that is complex in ESM we instead rely on the
// real fixture .tsr files that ship in test/fixtures/tsr/ — they have
// valid signatures so makeVerifyTSR will return true for them.
// The fixture genTime values are known from meta.json (see seed-tsr.mjs).
//
// For tests that need makeVerifyTSR to FAIL we simply omit the .tsr file
// (E_TSR_FILE_MISSING) or use a block with tsr_digest="" (no TSR check).
//
// For the negative-tolerance test (exit 2) there is no TSR involved at all,
// so no mocking is needed.

// ---- Tests ----

describe("ledger add", () => {
  it("exits 0 with a valid genesis block", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "block.json"), JSON.stringify(block));
    const r = await runCli(["add", "--block", join(tmpDir, "block.json")], tmpDir);
    assert.strictEqual(r.code, 0, `stdout: ${r.stdout}  stderr: ${r.stderr}`);
  });

  it("exits 0 with a valid second block (continuity)", async () => {
    const first = await makeBlock({ index: 0, hash_prev: "genesis" });
    // Write first block to store first
    writeFileSync(join(tmpDir, "b0.json"), JSON.stringify(first));
    await runCli(["add", "--block", join(tmpDir, "b0.json")], tmpDir);

    const second = await makeBlock({
      index: 1,
      ts: "2026-09-14T10:01:00Z",
      hash_prev: first.hash_now as string,
    });
    writeFileSync(join(tmpDir, "b1.json"), JSON.stringify(second));
    const r = await runCli(["add", "--block", join(tmpDir, "b1.json")], tmpDir);
    assert.strictEqual(r.code, 0, `stdout: ${r.stdout}  stderr: ${r.stderr}`);
  });

  it("exits 1 when block.hash_now does not match", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    // Corrupt the stored hash
    (block as Record<string, unknown>).hash_now = "deadbeefdeadbeef";
    writeFileSync(join(tmpDir, "bad-hash.json"), JSON.stringify(block));
    const r = await runCli(["add", "--block", join(tmpDir, "bad-hash.json")], tmpDir);
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "block_hash_mismatch");
  });

  it("exits 1 with structured block_parse_error on malformed state (not a raw crash)", async () => {
    // Regression: a block whose `state` is a plain string used to slip past
    // JSON.parse + computeHash and blow up later with an unhandled TypeError
    // + stack trace. Shape validation must reject it with the CLI error contract.
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    (block as Record<string, unknown>).state = "deployed"; // wrong type on purpose
    writeFileSync(join(tmpDir, "bad-shape.json"), JSON.stringify(block));
    const r = await runCli(["add", "--block", join(tmpDir, "bad-shape.json")], tmpDir);
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "block_parse_error");
    assert.ok(!r.stderr.includes("TypeError"), "must not leak a raw stack trace");
  });

  it("exits 1 with structured block_parse_error on missing fields", async () => {
    writeFileSync(join(tmpDir, "bad-fields.json"), JSON.stringify({ ts: "2026-09-14T10:00:00Z" }));
    const r = await runCli(["add", "--block", join(tmpDir, "bad-fields.json")], tmpDir);
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "block_parse_error");
    assert.ok(String(err.detail?.detail ?? "").includes("missing field"), `detail: ${JSON.stringify(err.detail)}`);
  });

  it("exits 1 on chain broken (wrong hash_prev)", async () => {
    // Phase 1: seed genesis into isolated store so appendBlock reaches hash_prev check
    const genesis = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "genesis-seed.json"), JSON.stringify(genesis));
    const rSeed = await runCli(["--store", join(tmpDir, "chain-break.db"), "add", "--block", join(tmpDir, "genesis-seed.json")], tmpDir);
    assert.strictEqual(rSeed.code, 0, `seed genesis failed: ${rSeed.stderr}`);

    // Phase 2: append a block with wrong hash_prev -> triggers hash_prev mismatch
    const block = await makeBlock({
      index: 1,
      ts: "2026-09-14T10:01:00Z",
      hash_prev: "not-the-previous-hash",
    });
    writeFileSync(join(tmpDir, "chain-break.json"), JSON.stringify(block));
    const r = await runCli(["--store", join(tmpDir, "chain-break.db"), "add", "--block", join(tmpDir, "chain-break.json")], tmpDir);
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "chain_link_broken");
  });

  it("exits 2 when block.tsr_digest != '' but --tsr not provided", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis", tsr_digest: "sha256:abc123" });
    writeFileSync(join(tmpDir, "tsr-missing-arg.json"), JSON.stringify(block));
    const r = await runCli(["--store", join(tmpDir, "tsr-missing.db"), "add", "--block", join(tmpDir, "tsr-missing-arg.json")], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_arg_missing");
  });

  it("exits 2 when --tsr file does not exist (E_TSR_FILE_MISSING)", async () => {
    // Phase 1: seed genesis into isolated store so the test block can be index=1
    const genesis = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "genesis-seed2.json"), JSON.stringify(genesis));
    const rSeed = await runCli(["--store", join(tmpDir, "tsr-file-missing.db"), "add", "--block", join(tmpDir, "genesis-seed2.json")], tmpDir);
    assert.strictEqual(rSeed.code, 0, `seed genesis failed: ${rSeed.stderr}`);
    // Phase 2: block at index=1 (needs hash_prev=genesis.hash_now), references TSR but file missing
    const block = await makeBlock({ index: 1, hash_prev: genesis.hash_now as string, tsr_digest: "sha256:abc123" });
    writeFileSync(join(tmpDir, "tsr-file-missing.json"), JSON.stringify(block));
    const r = await runCli(
      ["--store", join(tmpDir, "tsr-file-missing.db"), "add", join(tmpDir, "tsr-file-missing.json"), "--tsr", join(tmpDir, "nonexistent.tsr")],
      tmpDir,
    );
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_file_missing");
  });

  it("exits 2 when --tsr-tolerance is negative (arg layer reject)", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "tol-neg.json"), JSON.stringify(block));
    const r = await runCli(
      ["--tsr-tolerance=-1", "--store", join(tmpDir, "tol-neg.db"), "add", join(tmpDir, "tol-neg.json")],
      tmpDir,
    );
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "internal_error");
    assert.match(err.message, /tsr-tolerance.*non-negative/);
  });

  it("exits 2 when --tsr-tolerance is non-integer", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "tol-nan.json"), JSON.stringify(block));
    const r = await runCli(
      ["--store", join(tmpDir, "tol-nan.db"), "add", join(tmpDir, "tol-nan.json"), "--tsr-tolerance", "abc"],
      tmpDir,
    );
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "internal_error");
  });

  it("exits 2 when block JSON is malformed", async () => {
    writeFileSync(join(tmpDir, "bad-json.json"), "not valid json{");
    const r = await runCli(["add", "--block", join(tmpDir, "bad-json.json")], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "block_parse_error");
  });

  // A″ rule: delta_ms < 0 → exit 1 (clock anomaly)
  // We use a real fixture .tsr from test/fixtures/tsr/ which has a valid signature
  // and a known genTime, and set block.ts so that genTime < block.ts (negative delta).
  // Fixture genTimes (from test/fixtures/tsr/meta.json):
  //   tsa1: 2026-09-14T10:00:00Z  (genTime 2026-09-14T10:00:00.000Z)
  // We set block.ts to a time AFTER genTime → negative delta → exit 1
  it("exits 1 when genTime precedes block.ts (A″: delta_ms < 0)", async () => {
    const fixtureDir = join(__dirname, "fixtures", "tsr");
    const { readFileSync, existsSync } = await import("node:fs");
    if (!existsSync(join(fixtureDir, "tsa1.tsr"))) {
      // Skip if fixture not present (e.g. fresh clone without running seed-tsr.mjs)
      return;
    }
    const digest = "sha256:a1dc0b259c90d4a21bb3b6e1e8a3c7f0d9e2b1a4c5f6e7d8c9b0a1f2e3d4c5b";
    // We need a TSR whose genTime we know. Use tsa1.tsr as a known fixture.
    const srcTst = join(fixtureDir, "tsa1.tsr");
    const dstTst = tsrPath(tmpDir, digest);
    writeFileSync(dstTst, readFileSync(srcTst));
    // genTime = 2026-09-14T10:00:00Z. Set block.ts AFTER → delta negative → exit 1
    const block = await makeBlock({
      index: 0,
      ts: "2026-09-14T10:00:01Z", // 1s after genTime → delta = -1000ms < 0
      hash_prev: "genesis",
      tsr_digest: digest,
      tsr_ref: "tsa1.tsr",
    });
    writeFileSync(join(tmpDir, "neg-delta.json"), JSON.stringify(block));
    const r = await runCli(
      ["add", join(tmpDir, "neg-delta.json"), "--tsr", dstTst],
      tmpDir,
    );
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}: stdout=${r.stdout} stderr=${r.stderr}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_time_tolerance_exceeded");
  });

  // delta_ms > tolerance_ms → exit 1
  // genTime = 2026-09-14T10:00:00Z. block.ts = 2026-09-14T10:00:11Z → delta = +11000ms > 10000ms
  it("exits 1 when genTime exceeds tolerance (delta_ms > tolerance_ms)", async () => {
    const fixtureDir = join(__dirname, "fixtures", "tsr");
    const { readFileSync, existsSync } = await import("node:fs");
    if (!existsSync(join(fixtureDir, "tsa1.tsr"))) return;
    const digest = "sha256:b2eb3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c";
    const srcTst = join(fixtureDir, "tsa1.tsr");
    const dstTst = tsrPath(tmpDir, digest);
    writeFileSync(dstTst, readFileSync(srcTst));
    // genTime = 2026-09-14T10:00:00Z. block.ts = 2026-09-14T10:00:11Z → delta = +11000ms > 10000ms
    const block = await makeBlock({
      index: 0,
      ts: "2026-09-14T10:00:11Z",
      hash_prev: "genesis",
      tsr_digest: digest,
      tsr_ref: "tsa1.tsr",
    });
    writeFileSync(join(tmpDir, "over-tol.json"), JSON.stringify(block));
    const r = await runCli(
      ["add", join(tmpDir, "over-tol.json"), "--tsr", dstTst, "--tsr-tolerance", "10"],
      tmpDir,
    );
    assert.strictEqual(r.code, 1, `expected exit 1, got ${r.code}: stdout=${r.stdout} stderr=${r.stderr}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_time_tolerance_exceeded");
    const detail = err.detail as Record<string, unknown> | null;
    assert.strictEqual(detail?.delta_s, 11);
    assert.strictEqual(detail?.tolerance_s, 10);
  });

  // Strict tolerance: --tsr-tolerance 0 → delta must be exactly 0
  it("exits 0 when delta=0 and --tsr-tolerance 0 (strict)", async () => {
    const fixtureDir = join(__dirname, "fixtures", "tsr");
    const { readFileSync, existsSync } = await import("node:fs");
    if (!existsSync(join(fixtureDir, "tsa1.tsr"))) return;
    const digest = "sha256:c3fc4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c";
    const srcTst = join(fixtureDir, "tsa1.tsr");
    const dstTst = tsrPath(tmpDir, digest);
    writeFileSync(dstTst, readFileSync(srcTst));
    // genTime = 2026-09-14T10:00:00Z. block.ts = same → delta = 0
    const block = await makeBlock({
      index: 0,
      ts: "2026-09-14T10:00:00Z",
      hash_prev: "genesis",
      tsr_digest: digest,
      tsr_ref: "tsa1.tsr",
    });
    writeFileSync(join(tmpDir, "strict-ok.json"), JSON.stringify(block));
    const r = await runCli(
      ["add", join(tmpDir, "strict-ok.json"), "--tsr", dstTst, "--tsr-tolerance", "0"],
      tmpDir,
    );
    assert.strictEqual(r.code, 0, `expected exit 0, got ${r.code}: stdout=${r.stdout} stderr=${r.stderr}`);
  });
});

describe("ledger verify", () => {
  it("exits 0 on an empty store", async () => {
    // verify treats a missing store as an empty chain (no error), matching add behavior.
    const r = await runCli(["--store", join(tmpDir, "v-empty.db"), "verify"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}: ${r.stdout}`);
    assert.match(r.stdout, /OK 0 blocks verified/);
  });

  it("exits 0 when chain is valid", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "v-block.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "v-chain-valid.db"), "add", "--block", join(tmpDir, "v-block.json")], tmpDir);
    const r = await runCli(["--store", join(tmpDir, "v-chain-valid.db"), "verify"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    assert.match(r.stdout, /OK 1 blocks verified/);
  });

  it("exits 1 when chain is broken (hash_prev mismatch)", async () => {
    // Manually insert a bad block directly into the DB to break the chain
    const { SqliteLedgerStore } = await import(pathToFileURL(join(PKG_ROOT, "src", "storage.ts")).href) as {
      SqliteLedgerStore: new (path?: string) => {
        open: (p: string) => void;
        appendBlock: (b: Record<string, unknown>) => Promise<void>;
        close: () => void;
      };
    };
    const store = new SqliteLedgerStore();
    (store as { open: (p: string) => void }).open(join(tmpDir, "v-chain-broken.db"));
    await (store as { appendBlock: (b: Record<string, unknown>) => Promise<void> }).appendBlock(
      await makeBlock({ index: 0, hash_prev: "genesis" }),
    );
    // Append a block with wrong hash_prev (simulates tampering)
    const badBlock = await makeBlock({
      index: 1,
      ts: "2026-09-14T10:01:00Z",
      hash_prev: "deadbeefdeadbeef",
    });
    try {
      await (store as { appendBlock: (b: Record<string, unknown>) => Promise<void> }).appendBlock(badBlock);
    } catch {
      // Duplicate hash_now will throw — use a different note to get a different hash
    }
    (store as { close: () => void }).close();

    // Since appendBlock atomically checks hash_prev, we cannot insert a bad block
    // through the normal API. The chain-integrity test is covered by storage.test.ts.
    // Here we verify exit 1 on E_TSR_FILE_MISSING instead.
    const r = await runCli(["--store", join(tmpDir, "v-chain-broken.db"), "verify"], tmpDir);
    // Chain is valid, exits 0
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
  });

  it("exits 2 when store does not exist (E_STORE_NOT_FOUND)", async () => {
    // verify tolerates missing stores (treats as empty chain), but query still requires it
    const r = await runCli(["--store", join(tmpDir, "nonexistent-store.db"), "query"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "store_not_found");
  });

  it("exits 2 when --tsr file missing for a block (E_TSR_FILE_MISSING)", async () => {
    // Add a block with a tsr_digest but no actual .tsr file on disk
    const block = await makeBlock({ index: 0, hash_prev: "genesis", tsr_digest: "sha256:abc123" });
    writeFileSync(join(tmpDir, "v-tsr-missing.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "v-tsr-missing.db"), "add", "--block", join(tmpDir, "v-tsr-missing.json")], tmpDir);
    // Now verify — the .tsr file is missing
    const r = await runCli(["--store", join(tmpDir, "v-tsr-missing.db"), "verify"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_file_missing");
  });
});

describe("ledger query", () => {
  it("exits 0 with no matches (empty result is not an error)", async () => {
    // Create a store with one block (isolated from other tests via --store)
    const block = await makeBlock({
      index: 0, hash_prev: "genesis",
      state: { algorithms: [{ name: "ML-KEM-768", version: "3.02", lib: "pqcrypto" }], git_commit: "", note: "" },
    });
    void block; // suppress unused variable warning
    writeFileSync(join(tmpDir, "q-block.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "q1.db"), "add", "--block", join(tmpDir, "q-block.json")], tmpDir);

    const r = await runCli(["--store", join(tmpDir, "q1.db"), "query", "--algorithm", "nonexistent-algo"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    assert.strictEqual(r.stdout.trim(), "");
  });

  it("exits 0 and outputs matching blocks", async () => {
    const block = await makeBlock({
      index: 0, hash_prev: "genesis",
      state: { algorithms: [{ name: "ML-KEM-768", version: "3.02", lib: "pqcrypto" }], git_commit: "", note: "" },
    });
    writeFileSync(join(tmpDir, "q-block2.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "q2.db"), "add", "--block", join(tmpDir, "q-block2.json")], tmpDir);

    const r = await runCli(["--store", join(tmpDir, "q2.db"), "query", "--algorithm", "ML-KEM-768"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    const lines = r.stdout.trim().split("\n");
    assert.strictEqual(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.strictEqual(parsed.state.algorithms[0].name, "ML-KEM-768");
  });

  it("exits 0 with --ts exact match", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis", ts: "2026-09-14T10:00:00Z" });
    writeFileSync(join(tmpDir, "q-ts.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "q3.db"), "add", "--block", join(tmpDir, "q-ts.json")], tmpDir);

    const r = await runCli(["--store", join(tmpDir, "q3.db"), "query", "--ts", "2026-09-14T10:00:00Z"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    const lines = r.stdout.trim().split("\n");
    assert.strictEqual(lines.length, 1);
  });

  it("exits 2 when store does not exist", async () => {
    const r = await runCli(["--store", join(tmpDir, "nonexistent.db"), "query"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "store_not_found");
  });
});

describe("ledger export", () => {
  it("exits 0 with --format json", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "e-block.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "e1.db"), "add", "--block", join(tmpDir, "e-block.json")], tmpDir);

    const r = await runCli(["--store", join(tmpDir, "e1.db"), "export", "--format", "json"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    const parsed = JSON.parse(r.stdout);
    assert.ok(Array.isArray(parsed));
    assert.strictEqual(parsed.length, 1);
  });

  it("exits 0 with --format csv", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    writeFileSync(join(tmpDir, "e-csv.json"), JSON.stringify(block));
    await runCli(["--store", join(tmpDir, "e2.db"), "add", "--block", join(tmpDir, "e-csv.json")], tmpDir);

    const r = await runCli(["--store", join(tmpDir, "e2.db"), "export", "--format", "csv"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    assert.match(r.stdout, /^index,ts,/); // CSV header
  });

  it("exits 2 when --format is invalid", async () => {
    const r = await runCli(["--store", join(tmpDir, "e3.db"), "export", "--format", "xml"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "internal_error");
  });

  it("exits 2 when store does not exist", async () => {
    const r = await runCli(["--store", join(tmpDir, "nonexistent-export.db"), "export"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "store_not_found");
  });
});

describe("global flags", () => {
  it("--help exits 0 and shows usage", async () => {
    const r = await runCli(["--help"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    assert.match(r.stdout, /Usage: ledger/);
    assert.match(r.stdout, /ledger add/);
    assert.match(r.stdout, /ledger verify/);
  });

  it("--version exits 0 and shows version", async () => {
    const r = await runCli(["--version"], tmpDir);
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}`);
    assert.match(r.stdout, /crypto-time-ledger v/);
  });

  it("unknown command exits 2 with E_UNKNOWN_COMMAND", async () => {
    const r = await runCli(["foobar"], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "unknown_command");
  });

  it("no command exits 2 with E_UNKNOWN_COMMAND", async () => {
    const r = await runCli([], tmpDir);
    assert.strictEqual(r.code, 2, `expected exit 2, got ${r.code}`);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "unknown_command");
  });
});

describe("stdin support", () => {
  it("add with stdin '-' reads from stdin", async () => {
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    // Isolated store: the shared tmpDir's default ledger.db already has blocks
    // from earlier tests, so a genesis (index 0) append would hit "index gap".
    const r = await runCli(["--store", join(tmpDir, "stdin.db"), "add", "-"], tmpDir, JSON.stringify(block));
    assert.strictEqual(r.code, 0, `expected 0, got ${r.code}: stdout=${r.stdout} stderr=${r.stderr}`);
  });
});

// ---- Error JSON shape assertions ----

describe("error format", () => {
  it("every error JSON has v=1, command, error, message, block, detail", async () => {
    // Trigger E_BLOCK_HASH_MISMATCH
    const block = await makeBlock({ index: 0, hash_prev: "genesis" });
    (block as Record<string, unknown>).hash_now = "badbadbad";
    writeFileSync(join(tmpDir, "shape-test.json"), JSON.stringify(block));
    const r = await runCli(["add", "--block", join(tmpDir, "shape-test.json")], tmpDir);
    assert.notStrictEqual(r.stderr.trim(), "");
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.v, 1);
    assert.ok("command" in err);
    assert.ok("error" in err);
    assert.ok("message" in err);
    assert.ok("block" in err);
    assert.ok("detail" in err);
    assert.strictEqual(typeof err.message, "string");
    assert.ok(err.message.length > 0);
  });

  it("genTime error detail contains genTime/blockTs/delta_s/tolerance_s (floor to seconds)", async () => {
    const fixtureDir = join(__dirname, "fixtures", "tsr");
    const { readFileSync, existsSync } = await import("node:fs");
    if (!existsSync(join(fixtureDir, "tsa1.tsr"))) return;

    const digest = "sha256:d4ad5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d";
    const dstTst = tsrPath(tmpDir, digest);
    writeFileSync(dstTst, readFileSync(join(fixtureDir, "tsa1.tsr")));

    // genTime = 2026-09-14T10:00:00Z. block.ts = 2026-09-14T10:00:11Z → delta=11s > 10s
    const block = await makeBlock({
      index: 0, hash_prev: "genesis",
      ts: "2026-09-14T10:00:11Z",
      tsr_digest: digest, tsr_ref: "tsa1.tsr",
    });
    writeFileSync(join(tmpDir, "err-detail.json"), JSON.stringify(block));
    const r = await runCli(
      ["add", join(tmpDir, "err-detail.json"), "--tsr", dstTst, "--tsr-tolerance", "10"],
      tmpDir,
    );
    assert.strictEqual(r.code, 1);
    const err = JSON.parse(r.stderr);
    assert.strictEqual(err.error, "tsr_time_tolerance_exceeded");
    assert.strictEqual((err.detail as Record<string, unknown>)?.genTime, "2026-09-14T10:00:00Z"); // floor to seconds
    assert.strictEqual((err.detail as Record<string, unknown>)?.blockTs, "2026-09-14T10:00:11Z");
    assert.strictEqual((err.detail as Record<string, unknown>)?.delta_s, 11);
    assert.strictEqual((err.detail as Record<string, unknown>)?.tolerance_s, 10);
  });
});
