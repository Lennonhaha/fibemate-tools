// smoke-freetsa-verify.mjs — verify a REAL FreeTSA-issued TSR using the browser
// bundle, pinning FreeTSA's self-signed tsa.crt. This proves the self-issue loop
// is breakable: the signing key is held by an external third party (freetsa.org).
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const tmp = os.tmpdir();

const bundle = readFileSync(join(root, "dist", "crypto-time-ledger-verify.iife.min.js"), "utf8");
vm.runInThisContext(bundle);
const verifyTsrBytes = globalThis.CryptoTimeLedgerVerify.verifyTsrBytes;

const tsr = new Uint8Array(readFileSync(join(tmp, "freetsa-test.tsr")));
const pinnedPem = readFileSync(join(tmp, "freetsa-tsa.crt"), "utf8");

// digest = sha256 of the test data that was timestamped
const data = readFileSync(join(tmp, "freetsa-test.txt"));
const digest = "sha256:" + createHash("sha256").update(data).digest("hex");
console.log("test data digest:", digest);

const ok = await verifyTsrBytes(tsr, digest, pinnedPem);
console.log("FreeTSA TSR verify (pinned tsa.crt):", ok);

// Negative: wrong pinned cert must fail (fail-closed) — pin ONLY the project's
// Test TSA certs (which do NOT include the FreeTSA signer). NOTE: pinned-certs.pem
// now also carries the FreeTSA cert (added for block #3), so we must strip it
// here to exercise a genuinely-wrong pin set. Filter by parsed subject (PEM body
// is base64, so plain-text substring matching won't work).
import { X509Certificate } from "node:crypto";
const allPem = readFileSync(join(root, "test", "fixtures", "tsr", "pinned-certs.pem"), "utf8");
const onlyTestPem = allPem
  .split("-----END CERTIFICATE-----")
  .filter((s) => s.includes("BEGIN CERTIFICATE"))
  .map((s) => s.split("-----BEGIN CERTIFICATE-----")[1].trim())
  .map((c) => "-----BEGIN CERTIFICATE-----\n" + c + "\n-----END CERTIFICATE-----")
  .filter((pem) => {
    const x = new X509Certificate(pem);
    return !/freetsa/i.test(x.subject);
  })
  .join("\n");
console.log("onlyTestPem cert count:", onlyTestPem ? onlyTestPem.split("BEGIN CERTIFICATE").length - 1 : 0);
const okWrong = await verifyTsrBytes(tsr, digest, onlyTestPem);
console.log("FreeTSA TSR vs Test-TSA pin (should be false):", okWrong);

console.log("\nRESULT:", ok === true && okWrong === false ? "PASS — self-issue loop breakable" : "FAIL");
process.exit(ok === true && okWrong === false ? 0 : 1);
