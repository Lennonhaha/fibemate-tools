// bundle-browser.cjs — build a single-file browser bundle of the TSR verification path.
// Bundles pkijs + asn1js (and their deps) into ONE file so the browser gets a single
// shared asn1js instance (avoids the classic "dual asn1js instance" schema-mismatch trap).
// Output: a global `window.CryptoTimeLedgerVerify` exposing verifyTsrFile(bytes, pinnedPemCerts).
// Run: node scripts/bundle-browser.cjs
"use strict";
const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

const root = path.join(__dirname, "..");
const entry = path.join(root, "src", "browser-entry.ts");
const out = path.join(root, "dist", "crypto-time-ledger-verify.iife.js");

async function main() {
  fs.mkdirSync(path.dirname(out), { recursive: true });
  await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    format: "iife",
    globalName: "CryptoTimeLedgerVerify",
    platform: "browser",
    target: ["es2022"],
    outfile: out,
    sourcemap: false,
    minify: false,
    logLevel: "info",
  });
  const bytes = fs.statSync(out).size;
  console.log(`built ${out} (${bytes} bytes)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
