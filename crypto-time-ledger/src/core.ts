// crypto-time-ledger/src/core.ts
//
// 实现 §2.1 block schema + §2.2 verifyChain + §2.3 canonicalize
// 依赖：Node 内置 crypto（运行时纯 Node/JS，无 ts-node，符合 §4.1 决策 3a）
//
// 重要：原生 JSON.stringify 第二参数是 replacer、第三参数是 space、且不排序键。
// 故 canonicalize 自实现 RFC 8785 风格递归键排序 + 紧凑 + UTF-8（见 §2.3 伪代码注释）。

import { createHash } from "node:crypto";

export interface BlockState {
  algorithms: Array<{ name: string; version: string; lib: string }>;
  git_commit: string;
  note?: string;
}

export interface LedgerBlock {
  schema_version: number;
  index: number;
  ts: string; // ISO 8601 UTC，须与 tsr_ref 的 TSR 时间一致
  state: BlockState;
  tsr_digest: string; // sha256:<hex>
  tsr_ref: string; // 指向 tsr/<id>.tsr 的路径（不进 hash）
  hash_prev: string; // "genesis" 或上一块 hash_now
  hash_now: string; // sha256:<hex>
}

// RFC 8785 要求转义的字符（原生 JSON.stringify 不处理，会造成跨实现 hash 不一致）
const RE_U2028 = new RegExp(String.fromCharCode(0x2028), "g");
const RE_U2029 = new RegExp(String.fromCharCode(0x2029), "g");

// ---- §2.3 canonicalize ----

// RFC 8785 风格：递归键排序 + 紧凑 + UTF-8（无 BOM）
// 输入含 schema_version（hash 绑定格式版本，见 §2.3 规则 #5 排除项之外）
function canonicalize(block: LedgerBlock): Buffer {
  const obj = {
    schema_version: block.schema_version,
    index: block.index,
    ts: block.ts,
    state: block.state, // 整体进 hash（含 note），§2.3 规则补述
    tsr_digest: block.tsr_digest,
    hash_prev: block.hash_prev,
    // 排除 hash_now（自引用）、排除 tsr_ref（定位符，由 tsr_digest 锚定）
  };
  const json = stableStringify(obj);
  return Buffer.from(json, "utf-8");
}

// 自实现递归键排序（原生 JSON.stringify 不排序键）
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string") {
      // RFC 8785：U+2028 / U+2029 必须转义为 \u2028 / \u2029（原生 JSON.stringify 不转义）
      return JSON.stringify(value)
        .replace(RE_U2028, "\\u2028")
        .replace(RE_U2029, "\\u2029");
    }
    return JSON.stringify(value); // number / boolean / null：原生即可
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(rec[k]));
  return "{" + parts.join(",") + "}";
}

export function computeHash(block: LedgerBlock): string {
  const buf = canonicalize(block);
  const hex = createHash("sha256").update(buf).digest("hex");
  return "sha256:" + hex;
}

// ---- §2.2 verifyChain ----

// verifyTSR 由调用方注入：读 tsr_ref 文件 → 验签（TSA 证书链）→ 对上 block.ts
// 返回 false ⇒ 该链块判无效（不做降级，§4.2 拍板 #3）
export type VerifyTSR = (tsrRef: string, ts: string, tsrDigest: string) => boolean;

export interface VerifyResult {
  ok: boolean;
  failedAt?: number;
  reason?: string;
}

export function verifyChain(blocks: LedgerBlock[], verifyTSR: VerifyTSR): VerifyResult {
  let prevHash = "genesis";
  let expectedIndex = 0;
  for (const b of blocks) {
    if (b.index !== expectedIndex) {
      return { ok: false, failedAt: b.index, reason: "index gap" };
    }
    if (b.hash_prev !== prevHash) {
      return { ok: false, failedAt: b.index, reason: "hash_prev mismatch" };
    }
    const computed = computeHash(b);
    if (b.hash_now !== computed) {
      return { ok: false, failedAt: b.index, reason: "hash_now mismatch" };
    }
    if (!verifyTSR(b.tsr_ref, b.ts, b.tsr_digest)) {
      return { ok: false, failedAt: b.index, reason: "TSR invalid" };
    }
    prevHash = b.hash_now;
    expectedIndex++;
  }
  return { ok: true };
}
