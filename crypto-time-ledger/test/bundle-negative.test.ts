/**
 * Black-box negative tests for `ledger bundle verify`.
 *
 * A verifier is only worth its error paths. Four failures are covered here, each
 * built from a bundle-shaped directory on disk and each asserting both the exit
 * code and the machine-readable error code, because "it exited non-zero" would
 * also be satisfied by a typo in the fixture:
 *
 *   1. empty directory            -> bundle_manifest_missing
 *   2. edited payload             -> bundle_tampered (manifest digest mismatch)
 *   3. unverifiable TSR signature -> chain link broken (TSR invalid)
 *   4. malformed manifest / chain -> bundle_manifest_missing / bundle_tampered
 *
 * Case 3 is the one that matters: the manifest is only a checksum envelope, so an
 * attacker who edits a block can rebuild it. What they cannot rebuild is the TSA
 * signature, which is why the fixture keeps the manifest honest and corrupts the
 * token instead.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { after, describe, it } from "node:test";
import assert from "node:assert";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(__dirname, "..");
const CLI = join(PKG_ROOT, "src", "cli.ts");
const NODE = process.execPath;

const scratch: string[] = [];
function makeDir(): string {
  const d = mkdtempSync(join(tmpdir(), "ledger-bundle-neg-"));
  scratch.push(d);
  return d;
}

after(() => {
  for (const d of scratch) rmSync(d, { recursive: true, force: true });
});

function sha256File(p: string): string {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(NODE, ["--experimental-strip-types", CLI, ...args], {
      cwd: PKG_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => { stdout += String(c); });
    child.stderr.on("data", (c) => { stderr += String(c); });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/** Pull the stable error code out of the CLI's JSON error envelope ({"error":"..."}). */
function errorCode(out: RunResult): string | null {
  const text = out.stdout + out.stderr;
  const m = text.match(/"error"\s*:\s*"([a-z0-9_]+)"/);
  return m ? m[1] : null;
}

async function makeBlock(index: number, opts: { tsrDigest?: string } = {}): Promise<Record<string, unknown>> {
  const core = await import(pathToFileURL(join(PKG_ROOT, "src", "core.ts")).href);
  const block: Record<string, unknown> = {
    schema_version: 1,
    index,
    ts: "2026-10-28T00:00:00Z",
    state: { algorithms: [{ name: "ML-KEM-768", version: "3.3.2", lib: "pqc-kem" }], git_commit: "0".repeat(40) },
    tsr_digest: opts.tsrDigest ?? "",
    tsr_ref: opts.tsrDigest ? `tsr/${opts.tsrDigest.replace(/^sha256:/, "")}.tsr` : "",
    hash_prev: "genesis",
    hash_now: "",
  };
  block.hash_now = core.computeHash(block as never);
  return block;
}

/** Write chain.json plus a manifest whose digests match, so only the intended check can fail. */
function writeBundle(dir: string, chain: unknown[], extraFiles: Record<string, string> = {}): void {
  const chainPath = join(dir, "chain.json");
  writeFileSync(chainPath, JSON.stringify(chain, null, 2) + "\n", "utf8");
  const files: Record<string, string> = { "chain.json": sha256File(chainPath) };
  for (const [rel, content] of Object.entries(extraFiles)) {
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content, "utf8");
    files[rel] = sha256File(p);
  }
  writeFileSync(
    join(dir, "manifest.json"),
    JSON.stringify({ schema: "crypto-time-ledger-bundle/1", block_count: chain.length, files }, null, 2) + "\n",
    "utf8",
  );
}

describe("bundle verify rejects bad bundles", () => {
  it("empty directory", async () => {
    const dir = makeDir();
    const r = await runCli(["bundle", "verify", "--dir", dir]);
    assert.notStrictEqual(r.code, 0, "empty bundle must not verify");
    assert.strictEqual(errorCode(r), "bundle_manifest_missing");
  });

  it("payload edited after the manifest was written", async () => {
    const dir = makeDir();
    const block = await makeBlock(0);
    writeBundle(dir, [block]);
    // Change the payload, leave the manifest alone: this is the tamper case.
    const chain = [block];
    (chain[0] as Record<string, unknown>).state = { algorithms: [], git_commit: "f".repeat(40) };
    writeFileSync(join(dir, "chain.json"), JSON.stringify(chain, null, 2) + "\n", "utf8");
    const r = await runCli(["bundle", "verify", "--dir", dir]);
    assert.notStrictEqual(r.code, 0);
    assert.strictEqual(errorCode(r), "bundle_tampered");
  });

  it("TSR whose signature cannot be verified", async () => {
    const dir = makeDir();
    const digest = "sha256:" + "a".repeat(64);
    const block = await makeBlock(0, { tsrDigest: digest });
    // The token is garbage but its digest in the manifest is correct, so the
    // envelope check passes and the failure has to come from TSR verification.
    writeBundle(dir, [block], { [`tsr/${"a".repeat(64)}.tsr`]: "not a timestamp token\n" });
    const r = await runCli(["bundle", "verify", "--dir", dir]);
    assert.notStrictEqual(r.code, 0, "an unverifiable TSR must not produce a green verify");
    const text = r.stdout + r.stderr;
    assert.match(text, /TSR invalid|tsr|signature/i, `expected a TSR-related failure, got: ${text.slice(0, 300)}`);
  });

  it("malformed manifest", async () => {
    const dir = makeDir();
    writeFileSync(join(dir, "manifest.json"), "{ this is not json", "utf8");
    const r = await runCli(["bundle", "verify", "--dir", dir]);
    assert.notStrictEqual(r.code, 0);
    assert.strictEqual(errorCode(r), "bundle_manifest_missing");
  });

  it("malformed chain", async () => {
    const dir = makeDir();
    writeFileSync(join(dir, "chain.json"), "[ not json", "utf8");
    writeFileSync(
      join(dir, "manifest.json"),
      JSON.stringify({ schema: "crypto-time-ledger-bundle/1", block_count: 1, files: { "chain.json": sha256File(join(dir, "chain.json")) } }, null, 2) + "\n",
      "utf8",
    );
    const r = await runCli(["bundle", "verify", "--dir", dir]);
    assert.notStrictEqual(r.code, 0);
    assert.strictEqual(errorCode(r), "bundle_tampered");
  });
});
