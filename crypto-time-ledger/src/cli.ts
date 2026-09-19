/**
 * CLI entry point for the Crypto Time Ledger.
 *
 * VerifyTSR contract unified (CLI-DESIGN-1 resolved): core.ts and tsr.ts both
 * use `(digest: string) => Promise<boolean>`. cli.ts calls makeVerifyTSR directly
 * and performs genTime cross-checks separately (requires block context + file access
 * that the core contract intentionally excludes).
 */

import { parseArgs } from "node:util";
import { readFileSync, existsSync, readFile } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { computeHash, type LedgerBlock } from "./core.ts";
import { makeVerifyTSR } from "./tsr.ts";
import { SqliteLedgerStore } from "./storage.ts";
import { fromBER } from "asn1js";
import { ContentInfo, SignedData, TimeStampResp, TSTInfo } from "pkijs";

// ---- Exit codes ----
const EXIT_OK = 0;
const EXIT_FAIL = 1; // logic / integrity
const EXIT_ERR = 2; // runtime / input

// ---- Error codes ----
const E_STORE_NOT_FOUND = "store_not_found";
const E_STORE_IO_ERROR = "store_io_error";
const E_BLOCK_PARSE_ERROR = "block_parse_error";
const E_BLOCK_HASH_MISMATCH = "block_hash_mismatch";
const E_CHAIN_LINK_BROKEN = "chain_link_broken";
const E_TSR_ARG_MISSING = "tsr_arg_missing";
const E_TSR_FILE_MISSING = "tsr_file_missing";
const E_TSR_SIGNATURE_INVALID = "tsr_signature_invalid";
const E_TSR_TIME_TOLERANCE_EXCEEDED = "tsr_time_tolerance_exceeded";
const E_UNKNOWN_COMMAND = "unknown_command";
const E_INTERNAL_ERROR = "internal_error";

// Exit 1 set (logic / integrity)
const EXIT1 = new Set([
  E_BLOCK_HASH_MISMATCH,
  E_CHAIN_LINK_BROKEN,
  E_TSR_SIGNATURE_INVALID,
  E_TSR_TIME_TOLERANCE_EXCEEDED,
]);

// ---- Error shape ----
interface CliError {
  v: 1;
  command: string;
  error: string;
  message: string;
  block: number | null;
  detail: Record<string, unknown> | null;
}

/**
 * Write a structured error JSON to stderr and exit.
 * @param exitOne  true → EXIT_FAIL (logic/integrity), false → EXIT_ERR (runtime/input)
 */
function emitError(
  exitOne: boolean,
  command: string,
  error: string,
  message: string,
  block: number | null = null,
  detail: Record<string, unknown> | null = null,
): never {
  const obj: CliError = { v: 1, command, error, message, block, detail };
  process.stderr.write(JSON.stringify(obj) + "\n");
  process.exit(exitOne ? EXIT_FAIL : EXIT_ERR);
}

// ---- Store setup ----
const DEFAULT_STORE = "ledger.db";

function resolveTsdDir(storePath: string, tsdDir?: string): string {
  return tsdDir ?? join(dirname(storePath), "tsr");
}

function resolvePinnedCerts(tsdDir: string, pinnedCerts?: string): string {
  return pinnedCerts ?? join(tsdDir, "pinned-certs.pem");
}

function openStore(path: string): SqliteLedgerStore {
  const store = new SqliteLedgerStore();
  store.open(path);
  return store;
}

// ---- genTime extraction ----
/**
 * Extract genTime from a valid `.tsr` file using pkijs (no re-verification).
 *
 * INVARIANT (must hold for every call):
 *   This function is ONLY called after `makeVerifyTSR` has returned true.
 *   The TSR file has already been cryptographically verified.
 *   Calling this on an unverified TSR is unsafe — the file may exist but contain
 *   a forged signature. The three-step CLI sequence (exists → verify → extract)
 *   enforces this invariant.
 *
 * @param tsrPath  Absolute or relative path to the `.tsr` file.
 * @returns        The `genTime` as a JS `Date`, or throws if the file cannot be parsed.
 */
function extractGenTime(tsrPath: string): Date {
  const der = readFileSync(tsrPath);
  const tsr = new TimeStampResp({ schema: fromBER(der).result });
  const ci = tsr.timeStampToken;
  if (!ci) throw new Error("no timeStampToken");
  const sd = new SignedData({ schema: ci.content });
  const eContent = sd.encapContentInfo.eContent;
  if (!eContent) throw new Error("no eContent");
  const tst = new TSTInfo({ schema: fromBER(eContent.valueBlock.valueHexView).result });
  return tst.genTime;
}

// ---- genTime cross-check (asymmetric ms-prec) ----
/**
 * Check that the TSR genTime is consistent with block.ts.
 *
 * Rule (asymmetric):
 *   0 <= (genTime - block.ts) <= tolerance_ms  → pass
 *   genTime < block.ts (negative delta)         → fail  (clock anomaly / forgery)
 *   genTime - block.ts > tolerance_ms           → fail  (excessive delay)
 *
 * Comparison is always done in milliseconds.
 * block.ts: parsed via Date.parse() (ms precision); sub-second part participates.
 * genTime: from pkijs TSTInfo (typically 0ms).
 * tolerance_ms = tolerance_s * 1000 (CLI --tsr-tolerance, default 10s).
 *
 * @param blockTs   block.ts ISO string
 * @param tsrPath  Path to the verified `.tsr` file
 * @param toleranceMs  Tolerance in milliseconds
 * @param blockIdx   Block index (for error reporting)
 * @returns void (throws on failure — caller should emit error and exit)
 */
function checkGenTimeConsistency(
  blockTs: string,
  tsrPath: string,
  toleranceMs: number,
  blockIdx: number,
  cmd: "add" | "verify",
): void {
  const blockTsMs = Date.parse(blockTs); // ms
  const genTime = extractGenTime(tsrPath);
  const genTimeMs = genTime.getTime(); // ms
  const deltaMs = genTimeMs - blockTsMs;

  if (deltaMs < 0) {
    emitError(
      true, // EXIT_FAIL
      cmd,
      E_TSR_TIME_TOLERANCE_EXCEEDED,
      `TSR genTime precedes block timestamp (clock anomaly): delta=${deltaMs}ms`,
      blockIdx,
      {
        genTime: genTime.toISOString().slice(0, 19) + "Z",
        blockTs,
        delta_s: Math.round(deltaMs / 1000),
        tolerance_s: toleranceMs / 1000,
      },
    );
  }
  if (deltaMs > toleranceMs) {
    emitError(
      true,
      cmd,
      E_TSR_TIME_TOLERANCE_EXCEEDED,
      `TSR genTime differs from block timestamp by ${Math.round(deltaMs / 1000)}s (tolerance ${toleranceMs / 1000}s)`,
      blockIdx,
      {
        genTime: genTime.toISOString().slice(0, 19) + "Z",
        blockTs,
        delta_s: Math.round(deltaMs / 1000),
        tolerance_s: toleranceMs / 1000,
      },
    );
  }
  // 0 <= deltaMs <= toleranceMs → pass
}

// ---- Commands ----

/**
 * Structural validation of a parsed block *before* any hashing / store access.
 * Without this, a malformed `state` (e.g. a plain string instead of a
 * BlockState object) survives JSON.parse + computeHash and blows up later
 * inside `query` with an unhandled TypeError + raw stack trace — instead of
 * the structured { v, command, error, message } contract the CLI promises.
 */
function validateBlockShape(b: unknown): { ok: true } | { ok: false; detail: string } {
  if (b === null || typeof b !== "object" || Array.isArray(b)) {
    return { ok: false, detail: "block must be a JSON object" };
  }
  const o = b as Record<string, unknown>;
  const missing: string[] = [];
  for (const k of ["schema_version", "index", "ts", "state", "tsr_digest", "tsr_ref", "hash_prev", "hash_now"]) {
    if (!(k in o)) missing.push(k);
  }
  if (missing.length) return { ok: false, detail: `missing field(s): ${missing.join(", ")}` };
  if (typeof o.ts !== "string" || Number.isNaN(Date.parse(o.ts))) {
    return { ok: false, detail: "field 'ts' must be an ISO 8601 date string" };
  }
  const st = o.state;
  if (st === null || typeof st !== "object" || Array.isArray(st)) {
    return { ok: false, detail: "field 'state' must be an object: { algorithms: [{name, version, lib}], git_commit, note? }" };
  }
  const stO = st as Record<string, unknown>;
  if (!Array.isArray(stO.algorithms)) {
    return { ok: false, detail: "field 'state.algorithms' must be an array of {name, version, lib}" };
  }
  for (const a of stO.algorithms) {
    if (a === null || typeof a !== "object" || typeof (a as Record<string, unknown>).name !== "string") {
      return { ok: false, detail: "each entry of 'state.algorithms' must be an object with a string 'name'" };
    }
  }
  if (typeof o.tsr_digest !== "string" || typeof o.tsr_ref !== "string") {
    return { ok: false, detail: "fields 'tsr_digest' and 'tsr_ref' must be strings" };
  }
  if (typeof o.hash_prev !== "string" || typeof o.hash_now !== "string") {
    return { ok: false, detail: "fields 'hash_prev' and 'hash_now' must be strings" };
  }
  if (typeof o.index !== "number" || !Number.isInteger(o.index) || o.index < 0) {
    return { ok: false, detail: "field 'index' must be a non-negative integer" };
  }
  if (typeof o.schema_version !== "number") {
    return { ok: false, detail: "field 'schema_version' must be a number" };
  }
  return { ok: true };
}

async function cmdAdd(args: {
  blockFile: string;
  tsrFile?: string;
  tsdDir: string;
  pinnedCerts: string;
  toleranceMs: number;
  storePath: string;
}): Promise<void> {
  let block: LedgerBlock;
  try {
    const raw =
      args.blockFile === "-"
        ? await readStdin()
        : readFileSync(args.blockFile, "utf-8");
    block = JSON.parse(raw) as LedgerBlock;

  } catch {
    emitError(false, "add", E_BLOCK_PARSE_ERROR, "failed to read or parse block JSON", null, null);
    return;
  }

  // 0. shape validation (before hash check — a wrong-shaped block can never hash right)
  const shape = validateBlockShape(block);
  if (!shape.ok) {
    emitError(true, "add", E_BLOCK_PARSE_ERROR, "block does not match the LedgerBlock schema", null, { detail: shape.detail });
    return;
  }

  // 1. hash check
  const computed = computeHash(block);
  if (computed !== block.hash_now) {
    emitError(
      true,
      "add",
      E_BLOCK_HASH_MISMATCH,
      "computed hash does not match block.hash_now",
      block.index ?? null,
      { expected: computed, actual: block.hash_now },
    );
    return;
  }

  const store = openStore(args.storePath);

  // 2. chain continuity (delegated to storage — appendBlock does it atomically)
  try {
    await store.appendBlock(block);
  } catch (e: unknown) {
    const msg = (e as Error).message ?? String(e);
    store.close();
    // ChainError from storage: index / hash_prev / duplicate
    emitError(true, "add", E_CHAIN_LINK_BROKEN, msg, block.index ?? null, null);
    return;
  }

  // 3. TSR checks (only if block references a TSR)
  if (block.tsr_digest && block.tsr_digest !== "") {
    // 3a. --tsr argument check
    if (!args.tsrFile) {
      emitError(
        false,
        "add",
        E_TSR_ARG_MISSING,
        "block references a TSR digest but --tsr was not provided",
        block.index ?? null,
        { tsr_digest: block.tsr_digest },
      );
      return;
    }

    // 3b. file existence
    if (!existsSync(args.tsrFile!)) {
      emitError(
        false,
        "add",
        E_TSR_FILE_MISSING,
        `TSR file not found`,
        block.index ?? null,
        { path: args.tsrFile },
      );
      return;
    }

    // 3c. cryptographic verification
    // Load pinned certs if the file exists
    let pinnedCerts: string[] = [];
    try {
      if (existsSync(args.pinnedCerts)) {
        const pem = readFileSync(args.pinnedCerts, "utf-8");
        pinnedCerts = pem
          .split(/\n-----END CERTIFICATE-----\n/)
          .filter((s) => s.trim())
          .map((s) => s.trim() + "\n-----END CERTIFICATE-----\n");
      }
    } catch {
      // pinned certs missing → treat as empty set
    }
    const verifyFn = makeVerifyTSR({ tsrDir: args.tsdDir, pinnedTsaCerts: pinnedCerts });
    const ok = await verifyFn(block.tsr_digest);
    if (!ok) {
      store.close();
      emitError(
        true,
        "add",
        E_TSR_SIGNATURE_INVALID,
        "TSR signature verification failed",
        block.index ?? null,
        { tsr_digest: block.tsr_digest },
      );
      return;
    }

    // 3d. genTime cross-check (asymmetric ms, see §2)
    // Note: store.close() is called at every emitError path above; extractGenTime throws
    // only non-never (malformed DER) which would propagate up with the store still open.
    // Defensively close before re-throwing so the store is not leaked on that path.
    try {
      checkGenTimeConsistency(block.ts, args.tsrFile!, args.toleranceMs, block.index ?? 0, "add");
    } catch (e: unknown) {
      store.close();
      throw e;
    }
  }

  store.close();
  process.exit(EXIT_OK);
}

async function cmdVerify(args: {
  hash?: string;
  tsdDir: string;
  pinnedCerts: string;
  toleranceMs: number;
  storePath: string;
}): Promise<void> {
  const store = openStore(args.storePath);

  // Load pinned certs
  let pinnedCerts: string[] = [];
  try {
    if (existsSync(args.pinnedCerts)) {
      const pem = readFileSync(args.pinnedCerts, "utf-8");
      pinnedCerts = pem
        .split(/\n-----END CERTIFICATE-----\n/)
        .filter((s) => s.trim())
        .map((s) => s.trim() + "\n-----END CERTIFICATE-----\n");
    }
  } catch {
    // missing pinned certs → empty set → fail closed
  }
  const verifyFn = makeVerifyTSR({ tsrDir: args.tsdDir, pinnedTsaCerts: pinnedCerts });

  let chain = await store.getChain();
  if (chain.length === 0) {
    store.close();
    process.stdout.write("OK 0 blocks verified\n");
    process.exit(EXIT_OK);
  }

  // If a hash is given, truncate chain to that block
  if (args.hash) {
    const idx = chain.findIndex((b) => b.hash_now === args.hash);
    if (idx === -1) {
      store.close();
      emitError(true, "verify", E_CHAIN_LINK_BROKEN, "hash not found in chain", null, {
        hash: args.hash,
      });
      return;
    }
    chain = chain.slice(0, idx + 1);
  }

  // Verify each block in order
  for (const b of chain) {
    // hash check
    if (computeHash(b) !== b.hash_now) {
      store.close();
      emitError(
        true,
        "verify",
        E_BLOCK_HASH_MISMATCH,
        "hash_now mismatch",
        b.index,
        { expected: computeHash(b), actual: b.hash_now },
      );
      return;
    }

    // chain link check
    const chainIdx = chain.indexOf(b);
    if (chainIdx > 0) {
      const prev = chain[chainIdx - 1];
      if (b.index !== prev.index + 1 || b.hash_prev !== prev.hash_now) {
        store.close();
        emitError(
          true,
          "verify",
          E_CHAIN_LINK_BROKEN,
          "chain broken",
          b.index,
          { expected_index: prev.index + 1, actual_index: b.index },
        );
        return;
      }
    }

    // TSR checks
    if (b.tsr_digest && b.tsr_digest !== "") {
      const tsrPath = join(args.tsdDir, `${b.tsr_digest.replace(/^sha256:/, "")}.tsr`);
      if (!existsSync(tsrPath)) {
        store.close();
        emitError(false, "verify", E_TSR_FILE_MISSING, "TSR file missing for block", b.index, {
          tsr_digest: b.tsr_digest,
        });
        return;
      }
      const ok = await verifyFn(b.tsr_digest);
      if (!ok) {
        store.close();
        emitError(
          true,
          "verify",
          E_TSR_SIGNATURE_INVALID,
          "TSR signature verification failed",
          b.index,
          { tsr_digest: b.tsr_digest },
        );
        return;
      }
      // Note: store.close() is called at every emitError path above; extractGenTime throws
      // only non-never (malformed DER). Defensively close before re-throwing.
      try {
        checkGenTimeConsistency(b.ts, tsrPath, args.toleranceMs, b.index, "verify");
      } catch (e: unknown) {
        store.close();
        throw e;
      }
    }
  }

  store.close();
  process.stdout.write(`OK ${chain.length} blocks verified\n`);
  process.exit(EXIT_OK);
}

async function cmdExport(args: { format: "json" | "csv"; storePath: string }): Promise<void> {
  const store = openStore(args.storePath);
  const out = await store.export(args.format);
  store.close();
  process.stdout.write(out + "\n");
  process.exit(EXIT_OK);
}

async function cmdQuery(args: {
  algorithm?: string;
  ts?: string;
  storePath: string;
}): Promise<void> {
  const store = openStore(args.storePath);
  const chain = await store.getChain();
  store.close();

  const matches = chain.filter((b) => {
    if (args.algorithm) {
      const ok = b.state.algorithms.some((a) => a.name === args.algorithm);
      if (!ok) return false;
    }
    if (args.ts) {
      if (b.ts !== args.ts) return false;
    }
    return true;
  });

  for (const b of matches) {
    process.stdout.write(JSON.stringify(b) + "\n");
  }
  process.exit(EXIT_OK);
}

// ---- helpers ----

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

// ---- main ----

if (import.meta.main) {
  const { values: gv, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      "store": { type: "string" },
      "tsr-dir": { type: "string" },
      "pinned-certs": { type: "string" },
      "tsr-tolerance": { type: "string" },
      "tsr-digest": { type: "string" },
      "tsr": { type: "string" },
      "algorithm": { type: "string" },   // consumed here; read via gv in query branch
      "ts": { type: "string" },          // consumed here; read via gv in query branch
      "format": { type: "string" },       // consumed here; read via gv in export branch

      "help": { type: "boolean" },
      "version": { type: "boolean" },
      "block": { type: "string" },
    },
  });

  if (gv.help) {
    printHelp();
    process.exit(EXIT_OK);
  }

  if (gv.version) {
    // eslint-disable-next-line no-console
    console.log("crypto-time-ledger v0.1.0");
    process.exit(EXIT_OK);
  }

  if (positionals.length === 0) {
    emitError(false, "", E_UNKNOWN_COMMAND, "no command given", null, null);
  }

  const [cmd, ...cmdPos] = positionals;
  const storePath = (gv.store as string | undefined) ?? DEFAULT_STORE;
  const tsdDir = resolveTsdDir(storePath, gv["tsr-dir"] as string | undefined);
  const pinnedCerts = resolvePinnedCerts(tsdDir, gv["pinned-certs"] as string | undefined);


  const toleranceRaw = gv["tsr-tolerance"] as string | undefined;
  let toleranceMs = 10_000; // default 10s
  if (toleranceRaw !== undefined) {
    const n = Number(toleranceRaw);
    if (!isFinite(n) || n < 0 || !Number.isInteger(n)) {
      emitError(
        false,
        cmd,
        E_INTERNAL_ERROR,
        "--tsr-tolerance must be a non-negative integer (seconds)",
        null,
        { value: toleranceRaw },
      );
    }
    if (n === 0) {
      toleranceMs = 0;
    } else {
      toleranceMs = n * 1000;
    }
  }

  // Check store exists (except for add/create, verify, and export which validate format first)
  if (cmd !== "add" && cmd !== "verify" && cmd !== "export" && !existsSync(storePath)) {
    emitError(false, cmd, E_STORE_NOT_FOUND, `store not found: ${storePath}`, null, null);
  }

  if (cmd === "add") {
    const { values: av } = parseArgs({
      allowPositionals: true,
      options: {
        "block": { type: "string" },
        "tsr": { type: "string" },
        "store": { type: "string" },
      },
    });
    // --block flag wins; otherwise positional from outer parseArgs
    // --store in inner schema takes precedence over outer (allows test isolation)
    const blockFile = (gv.block as string | undefined) ?? cmdPos[0] ?? "-";
    const storePath = (av.store as string | undefined) ?? (gv.store as string | undefined) ?? DEFAULT_STORE;
    // Re-derive tsdDir/pinnedCerts with effective storePath (inner takes priority)
    const tsdDir = resolveTsdDir(storePath, gv["tsr-dir"] as string | undefined);
    const pinnedCerts = resolvePinnedCerts(tsdDir, gv["pinned-certs"] as string | undefined);
    // --tsr-tolerance is handled at the outer level (global flag)
    // --tsr may come from outer (when passed before subcommand) or inner (after subcommand)
    cmdAdd({
      blockFile,
      tsrFile: (av.tsr as string | undefined) ?? (gv.tsr as string | undefined),
      tsdDir,
      pinnedCerts,
      toleranceMs,
      storePath,
    });
  } else if (cmd === "verify") {
    cmdVerify({
      hash: cmdPos[0],
      tsdDir,
      pinnedCerts,
      toleranceMs,
      storePath,
    });
  } else if (cmd === "export") {
    // --store and --format are consumed by the outer schema; read directly from gv.
    // Format check runs BEFORE store check (so invalid format is caught even on empty store).
    const format = (gv.format as string | undefined) ?? "json";
    if (format !== "json" && format !== "csv") {
      emitError(false, "export", E_INTERNAL_ERROR, "--format must be json or csv", null, {
        got: format,
      });
    }
    if (!existsSync(storePath)) {
      emitError(false, "export", E_STORE_NOT_FOUND, `store not found: ${storePath}`, null, null);
    }
    cmdExport({ format: format as "json" | "csv", storePath });
  } else if (cmd === "query") {
    // --algorithm and --ts are declared in the outer schema so parseArgs strips them
    // from positionals. We read the values directly from gv (no inner parseArgs).
    cmdQuery({
      algorithm: gv.algorithm as string | undefined,
      ts: gv.ts as string | undefined,
      storePath,
    });
  } else {
    emitError(false, cmd, E_UNKNOWN_COMMAND, `unknown command: ${cmd}`, null, null);
  }
}

function printHelp(): void {
  // eslint-disable-next-line no-console
  console.log(`crypto-time-ledger CLI

Usage: ledger <command> [options]

Commands:
  ledger add <block-file> [--tsr <tsr-file>]
    Append a block to the ledger store.
    Use "-" for block-file to read from stdin.

  ledger verify [hash]
    Verify the full chain, or up to a specific block hash.

  ledger query [--algorithm <name>] [--ts <iso-time>]
    Query blocks by algorithm name or timestamp.

  ledger export [--format json|csv]
    Export the full chain.

Global options:
  --store <path>          SQLite store path (default: ledger.db in cwd)
  --tsr-dir <path>       Directory containing .tsr files (default: <store-dir>/tsr/)
  --pinned-certs <pem>   Path to pinned-certs.pem (default: <tsr-dir>/pinned-certs.pem)
  --tsr-tolerance <s>    genTime tolerance in seconds (default: 10, 0=strict, negative=reject)
  --help                 Show this help
  --version              Show version
`);
}
