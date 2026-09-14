import { DatabaseSync } from "node:sqlite";
import { computeHash, type LedgerBlock } from "./core.ts";

export class StorageError extends Error {}
export class ChainError extends Error {}

export interface LedgerStore {
  open(path: string): Promise<void>;
  close(): Promise<void>;
  appendBlock(b: LedgerBlock): Promise<void>;
  getChain(): Promise<LedgerBlock[]>;
  getBlockByIndex(i: number): Promise<LedgerBlock | null>;
  getLatest(): Promise<LedgerBlock | null>;
  count(): Promise<number>;
  query(pred: (b: LedgerBlock) => boolean): Promise<LedgerBlock[]>;
  export(format: "json" | "csv"): Promise<string>;
}

const GENESIS = "genesis";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS blocks (
  idx INTEGER PRIMARY KEY,
  hash_prev TEXT NOT NULL,
  hash_now TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  state_json TEXT NOT NULL,
  tsr_digest TEXT NOT NULL,
  tsr_ref TEXT NOT NULL,
  raw_json TEXT NOT NULL
);`;

interface Row {
  raw_json: string;
}

// CSV field escaping: wrap + double internal quotes only when the value contains
// comma / quote / newline. Algorithm names or notes may contain commas in the wild.
function csvField(v: string): string {
  if (/[",\n]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
  return v;
}

export class SqliteLedgerStore implements LedgerStore {
  private db: DatabaseSync | null = null;

  async open(path: string): Promise<void> {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
  }

  private getDb(): DatabaseSync {
    if (!this.db) throw new StorageError("store not open");
    return this.db;
  }

  async close(): Promise<void> {
    this.getDb().close();
    this.db = null;
  }

  async appendBlock(b: LedgerBlock): Promise<void> {
    const db = this.getDb();
    const recomputed = computeHash(b);
    if (recomputed !== b.hash_now) {
      throw new ChainError(`hash_now mismatch: expected ${recomputed}, got ${b.hash_now}`);
    }
    // Atomic write. appendBlock reads `latest` INLINE via a synchronous db.prepare().get()
    // (NOT via the async getLatest()), so there is NO await between the read and the INSERT
    // in this single-threaded JS context. BEGIN IMMEDIATE additionally takes the write lock
    // up front so a second connection / process appending concurrently serializes behind it.
    db.exec("BEGIN IMMEDIATE");
    try {
      const row = db.prepare(`SELECT raw_json FROM blocks ORDER BY idx DESC LIMIT 1`).get() as unknown as
        | Row
        | undefined;
      const latest = row ? (JSON.parse(row.raw_json) as LedgerBlock) : null;
      if (latest === null) {
        if (b.index !== 0 || b.hash_prev !== GENESIS) {
          throw new ChainError(`genesis block must have index=0 and hash_prev="${GENESIS}"`);
        }
      } else {
        if (b.index !== latest.index + 1) {
          throw new ChainError(`index gap: expected ${latest.index + 1}, got ${b.index}`);
        }
        if (b.hash_prev !== latest.hash_now) {
          throw new ChainError(`hash_prev mismatch: expected ${latest.hash_now}, got ${b.hash_prev}`);
        }
      }
      const raw = JSON.stringify(b);
      const stateJson = JSON.stringify(b.state);
      db.prepare(
        `INSERT INTO blocks (idx, hash_prev, hash_now, ts, schema_version, state_json, tsr_digest, tsr_ref, raw_json) ` +
          `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        b.index,
        b.hash_prev,
        b.hash_now,
        b.ts,
        b.schema_version,
        stateJson,
        b.tsr_digest ?? "",
        b.tsr_ref ?? "",
        raw,
      );
      db.exec("COMMIT");
    } catch (e: unknown) {
      db.exec("ROLLBACK");
      if (e instanceof ChainError) throw e;
      const code = (e as { code?: string })?.code ?? "";
      if (code === "SQLITE_CONSTRAINT_UNIQUE" || code.includes("CONSTRAINT")) {
        throw new ChainError(`duplicate hash_now ${b.hash_now}`);
      }
      throw e;
    }
  }

  async getChain(): Promise<LedgerBlock[]> {
    const rows = this.getDb().prepare(`SELECT raw_json FROM blocks ORDER BY idx ASC`).all() as unknown as Row[];
    return rows.map((r) => JSON.parse(r.raw_json) as LedgerBlock);
  }

  async getBlockByIndex(i: number): Promise<LedgerBlock | null> {
    const row = this.getDb().prepare(`SELECT raw_json FROM blocks WHERE idx = ?`).get(i) as unknown as Row | undefined;
    return row ? (JSON.parse(row.raw_json) as LedgerBlock) : null;
  }

  async getLatest(): Promise<LedgerBlock | null> {
    const row = this.getDb().prepare(`SELECT raw_json FROM blocks ORDER BY idx DESC LIMIT 1`).get() as unknown as
      | Row
      | undefined;
    return row ? (JSON.parse(row.raw_json) as LedgerBlock) : null;
  }

  async count(): Promise<number> {
    const row = this.getDb().prepare(`SELECT COUNT(*) AS n FROM blocks`).get() as unknown as { n: number };
    return row.n;
  }

  async query(pred: (b: LedgerBlock) => boolean): Promise<LedgerBlock[]> {
    return (await this.getChain()).filter(pred);
  }

  async export(format: "json" | "csv"): Promise<string> {
    const chain = await this.getChain();
    if (format === "json") {
      return JSON.stringify(chain, null, 2);
    }
    const header = "index,ts,algorithm_name,algorithm_version,algorithm_lib,git_commit,note,hash_now,tsr_attached";
    const lines = [header];
    for (const b of chain) {
      // tsr_attached here = "TSR attached" flag (tsr_digest non-empty).
      // Full verifyTSR crypto-check is applied in cli verify/query once tsr.ts lands.
      const tsrAttached = b.tsr_digest !== "";
      for (const alg of b.state.algorithms) {
        const git = b.state.git_commit ?? "";
        const note = b.state.note ?? "";
        lines.push(
          [
            csvField(String(b.index)),
            csvField(b.ts),
            csvField(alg.name),
            csvField(alg.version),
            csvField(alg.lib ?? ""),
            csvField(git),
            csvField(note),
            csvField(b.hash_now),
            tsrAttached ? "true" : "false",
          ].join(","),
        );
      }
    }
    return lines.join("\n");
  }
}
