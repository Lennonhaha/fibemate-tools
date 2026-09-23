// smoke-browser-bundle.mjs — verify the IIFE bundle works in a WebCrypto environment.
// Loads dist/crypto-time-ledger-verify.iife.js, evals it (IIFE with globalName),
// then runs verifyTsrBytes against the real test fixtures.
// Run: node smoke-browser-bundle.mjs
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

// 1. load bundle source
const bundle = readFileSync(join(root, "dist", "crypto-time-ledger-verify.iife.js"), "utf8");

// 2. eval in the SAME realm (runInThisContext). A separate vm.createContext realm
//    would trigger a cross-realm ArrayBuffer instanceof mismatch inside asn1js — an
//    artifact of the test harness, not of the bundle (real browsers are single-realm).
vm.runInThisContext(bundle);

const verifyTsrBytes = globalThis.CryptoTimeLedgerVerify?.verifyTsrBytes;
if (typeof verifyTsrBytes !== "function") {
  throw new Error("bundle did not expose CryptoTimeLedgerVerify.verifyTsrBytes");
}

const fx = join(root, "test", "fixtures", "tsr");
const meta = JSON.parse(readFileSync(join(fx, "meta.json"), "utf8"));
const [d1, d2, d3, d4] = meta.digests;
const pinnedPem = readFileSync(join(fx, "pinned-certs.pem"), "utf8");

function readTsr(digest) {
  return new Uint8Array(readFileSync(join(fx, `${digest}.tsr`)));
}

let pass = 0;
let fail = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (ok) pass++;
  else fail++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: got=${actual} want=${expected}`);
}

// 3. run assertions
check("pinned TSA 1 -> true", await verifyTsrBytes(readTsr(d1), d1, pinnedPem), true);
check("pinned TSA 2 -> true", await verifyTsrBytes(readTsr(d2), d2, pinnedPem), true);
check("pinned TSA 3 -> true", await verifyTsrBytes(readTsr(d3), d3, pinnedPem), true);
check("UNPINNED TSA 4 -> false", await verifyTsrBytes(readTsr(d4), d4, pinnedPem), false);
check("empty pinned set -> false (fail closed)", await verifyTsrBytes(readTsr(d1), d1, ""), false);
check("wrong digest -> false (imprint mismatch)", await verifyTsrBytes(readTsr(d1), "0".repeat(64), pinnedPem), false);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
