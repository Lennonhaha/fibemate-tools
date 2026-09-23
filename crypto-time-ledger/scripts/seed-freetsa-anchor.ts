// seed-freetsa-anchor.ts — append a REAL externally-anchored block (index 3) to
// the ledger, timestamped by FreeTSA (freetsa.org). Does NOT overwrite the 3 demo
// blocks — it appends, preserving history. The signing key is held by an independent
// third party (freetsa.org), breaking the self-signing loop.
//
// Run: node --experimental-strip-types scripts/seed-freetsa-anchor.ts
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { computeHash } from "../src/core.ts";
import { fromBER } from "asn1js";
import { SignedData, TimeStampResp, TSTInfo } from "pkijs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repo = join(__dirname, "..");
const fx = join(repo, "test", "fixtures", "tsr");
const chainPath = join(repo, "..", "data", "time-ledger", "chain.json");
const metaPath = join(fx, "meta.json");
const pinnedPath = join(fx, "pinned-certs.pem");
const reqCfg = join(__dirname, "openssl-minimal.cnf");

// ---- 1. real anchor payload (this is what the timestamp actually anchors) ----
const payload = [
  "FIBEMATE crypto-time-ledger — first externally anchored block.",
  "Timestamped by FreeTSA (freetsa.org, RFC 3161).",
  "Proves the self-signing loop is broken: the signing key is held by an independent third party.",
  "git_commit=0c4f3c3",
].join("\n");
const digest = createHash("sha256").update(payload, "utf8").digest("hex");
console.log("payload digest:", digest);

// ---- 2. openssl TSQ (messageImprint = digest) ----
const opensslPath =
  execFileSync("where.exe openssl", { shell: true }).toString().trim().split(/\r?\n/)[0] || "openssl";
function run(args: string[], encoding: BufferEncoding = "buffer") {
  return execFileSync(opensslPath, args, {
    encoding,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, OPENSSL_CONF: reqCfg },
  });
}
const tmpq = join(fx, `anchor-${digest}.tsq`);
run(["ts", "-query", "-sha256", "-digest", digest, "-cert", "-out", tmpq]);
const tsq = readFileSync(tmpq);

// ---- 3. POST to FreeTSA /tsr ----
const resp = await fetch("https://freetsa.org/tsr", {
  method: "POST",
  headers: { "Content-Type": "application/timestamp-query" },
  body: tsq,
});
if (!resp.ok) throw new Error(`FreeTSA HTTP ${resp.status}`);
const tsrBuf = Buffer.from(await resp.arrayBuffer());
const tsrFile = join(fx, `${digest}.tsr`);
writeFileSync(tsrFile, tsrBuf);
console.log("TSR written:", `${digest}.tsr`, tsrBuf.length, "bytes");

// ---- 4. extract genTime from the real TSR ----
const tsr = new TimeStampResp({ schema: fromBER(tsrBuf).result });
const ci = tsr.timeStampToken;
if (!ci) throw new Error("no timeStampToken");
const sd = new SignedData({ schema: ci.content });
const eContent = sd.encapContentInfo.eContent;
if (!eContent) throw new Error("no eContent");
const tst = new TSTInfo({ schema: fromBER(eContent.valueBlock.valueHexView).result });
const genTime = tst.genTime;
console.log("FreeTSA genTime:", genTime.toISOString());

// ---- 5. build the new block ----
const chain = JSON.parse(readFileSync(chainPath, "utf8"));
const prev = chain[chain.length - 1];
const block: any = {
  schema_version: 1,
  index: prev.index + 1,
  ts: genTime.toISOString(),
  state: {
    algorithms: [{ name: "ML-KEM-768", version: "1.0", lib: "noble" }],
    git_commit: "0c4f3c3",
    note: "external anchor via FreeTSA (freetsa.org) — non-self-signed timestamp",
  },
  tsr_digest: "sha256:" + digest,
  tsr_ref: digest + ".tsr",
  hash_prev: prev.hash_now,
  hash_now: "",
};
block.hash_now = computeHash(block);
console.log("new block index:", block.index, "hash_now:", block.hash_now);

// ---- 6. append block + update meta.json + append FreeTSA cert to pinned ----
chain.push(block);
writeFileSync(chainPath, JSON.stringify(chain, null, 2) + "\n");

const meta = JSON.parse(readFileSync(metaPath, "utf8"));
if (!meta.digests.includes(digest)) meta.digests.push(digest);
writeFileSync(metaPath, JSON.stringify(meta, null, 2) + "\n");

const crt = await (await fetch("https://freetsa.org/files/tsa.crt")).text();
const pinned = readFileSync(pinnedPath, "utf8");
if (!pinned.includes("Free TSA")) {
  writeFileSync(pinnedPath, pinned + crt);
  console.log("pinned-certs.pem: appended FreeTSA tsa.crt");
} else {
  console.log("pinned-certs.pem: FreeTSA cert already present");
}

// ---- 7. verify the new block's TSR locally (pin = all certs incl. FreeTSA) ----
const { makeVerifyTSR } = await import("../src/tsr.ts");
const pinnedCerts = readFileSync(pinnedPath, "utf8")
  .split("-----END CERTIFICATE-----")
  .filter((s) => s.includes("BEGIN CERTIFICATE"))
  .map((s) => `${s}-----END CERTIFICATE-----`);
const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinnedCerts });
const ok = await v("sha256:" + digest);
console.log("local verify of new block TSR:", ok);

// cleanup temp tsq
unlinkSync(tmpq);

if (!ok) {
  console.error("FAIL: new block TSR did not verify");
  process.exit(1);
}
console.log("DONE — appended real FreeTSA-anchored block", block.index);
