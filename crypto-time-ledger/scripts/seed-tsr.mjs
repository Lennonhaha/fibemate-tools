// Generates real (self-signed, but structurally valid RFC3161) TSR fixtures for unit tests.
// 3 pinned TSAs (tsa1..3) + 1 unpinned (tsa4). Each timestamps a distinct digest so the
// .tsr filename (<sha256hex>.tsr) is unique and resolvable from the block's tsr_digest.
// Run: node scripts/seed-tsr.mjs   (requires openssl on PATH)
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const reqCfg = join(__dirname, "openssl-minimal.cnf");
const outDir = join(__dirname, "..", "test", "fixtures", "tsr");
mkdirSync(outDir, { recursive: true });

function opensslPath() {
  try {
    const p = execFileSync("where.exe openssl", { shell: true }).toString().trim().split(/\r?\n/)[0];
    if (p) return p;
  } catch {}
  return "openssl";
}
const OSSL = opensslPath();

function run(args, encoding = "buffer") {
  return execFileSync(OSSL, args, {
    encoding,
    maxBuffer: 1024 * 1024 * 16,
    env: { ...process.env, OPENSSL_CONF: reqCfg },
  });
}

// ts -reply needs a TSA config section (signer_cert / serial / policy). Build one per TSA.
function writeTsaCfg(n) {
  const tsaCfg = join(outDir, `tsa${n}.cnf`);
  const d = outDir.replace(/\\/g, "/");
  const pemPath = join(outDir, `tsa${n}.pem`).replace(/\\/g, "/");
  const content = [
    "[tsa]",
    "default_tsa = tsa_config",
    "",
    "[tsa_config]",
    `dir = ${d}`,
    `serial = ${join(outDir, "tsaserial").replace(/\\/g, "/")}`,
    "crypto_device = builtin",
    `signer_cert = ${pemPath}`,
    "default_policy = 1.2.3.4.1",
    "other_policies = 1.2.3.4.2",
    "signer_digest = sha256",
    "digests = sha256",
    "ess_cert_id_alg = sha256",
    "accuracy = secs:1",
    "clock_precision_digits = 0",
    "ordering = yes",
    "tsa_name = yes",
    "ess_cert_id_chain = no",
    "",
  ].join("\n");
  writeFileSync(tsaCfg, content);
  return tsaCfg;
}

function makeTsa(n) {
  const key = join(outDir, `tsa${n}.key`);
  const pem = join(outDir, `tsa${n}.pem`);
  run(["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", pem,
    "-days", "3650", "-subj", `/CN=Test TSA ${n}`, "-addext", "extendedKeyUsage=critical,timeStamping", "-nodes"]);
  const digest = createHash("sha256").update(`fibemate-time-ledger-fixture-${n}`).digest("hex");
  const q = join(outDir, `q${n}.tsq`);
  run(["ts", "-query", "-sha256", "-digest", digest, "-cert", "-out", q]);
  const tsr = join(outDir, `${digest}.tsr`);
  const tsaCfg = writeTsaCfg(n);
  run(["ts", "-reply", "-queryfile", q, "-signer", pem, "-inkey", key, "-out", tsr, "-config", tsaCfg]);
  return { digest, tsr };
}

// serial counter file required by ts -reply
writeFileSync(join(outDir, "tsaserial"), "01");

const tsas = [];
for (let i = 1; i <= 4; i++) tsas.push(makeTsa(i));

// pinned-certs.pem: tsa1..3 only (tsa4 intentionally excluded for the unpinned test)
const pinnedPem = [1, 2, 3].map((i) => readFileSync(join(outDir, `tsa${i}.pem`), "utf8")).join("");
writeFileSync(join(outDir, "pinned-certs.pem"), pinnedPem);

const meta = {
  digests: tsas.map((t) => t.digest),
};
writeFileSync(join(outDir, "meta.json"), JSON.stringify(meta, null, 2));

console.log(`wrote ${tsas.length} tsr fixtures + pinned-certs.pem to ${outDir}`);
