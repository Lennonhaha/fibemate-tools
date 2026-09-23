// smoke-e2e-fetch.mjs — simulate the PUBLIC read-only endpoint in a browser-like
// runtime: fetch chain.json + .tsr + pinned-certs.pem from raw.githubusercontent.com,
// then verify each TSR cryptographically LOCALLY via the bundled browser port.
// This is exactly what a third-party browser does: no trust in the FIBEMATE server.
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const RAW = "https://raw.githubusercontent.com/Lennonhaha/fibemate-tools/main";

// Load the browser IIFE bundle in THIS realm (single realm = real browser semantics).
const bundle = readFileSync(join(root, "dist", "crypto-time-ledger-verify.iife.min.js"), "utf8");
vm.runInThisContext(bundle);
const verifyTsrBytes = globalThis.CryptoTimeLedgerVerify.verifyTsrBytes;

const chain = await (await fetch(`${RAW}/data/time-ledger/chain.json`, { cache: "no-store" })).json();
const pinnedPem = await (await fetch(`${RAW}/crypto-time-ledger/test/fixtures/tsr/pinned-certs.pem`, { cache: "no-store" })).text();

let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: got=${got} want=${want}`);
}

console.log(`chain blocks: ${chain.length}`);
for (const b of chain) {
  const hex = b.tsr_digest.replace(/^sha256:/, "");
  const der = new Uint8Array(await (await fetch(`${RAW}/crypto-time-ledger/test/fixtures/tsr/${hex}.tsr`, { cache: "no-store" })).arrayBuffer());
  const ok = await verifyTsrBytes(der, b.tsr_digest, pinnedPem);
  check(`block #${b.index} (${b.state.algorithms[0].name}) TSR verify`, ok, true);
}

// Negative: tampered digest must FAIL (imprint mismatch).
const tampered = chain[0].tsr_digest.replace(/^sha256:/, "").replace(/^./, (c) => (c === "a" ? "b" : "a"));
const der0 = new Uint8Array(await (await fetch(`${RAW}/crypto-time-ledger/test/fixtures/tsr/${chain[0].tsr_digest.slice(7)}.tsr`, { cache: "no-store" })).arrayBuffer());
check("tampered digest -> false (imprint mismatch)", await verifyTsrBytes(der0, "sha256:" + tampered, pinnedPem), false);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
