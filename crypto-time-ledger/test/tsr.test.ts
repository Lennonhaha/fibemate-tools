import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, unlinkSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeVerifyTSR } from "../src/tsr.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = join(__dirname, "fixtures", "tsr");
const meta = JSON.parse(readFileSync(join(fx, "meta.json"), "utf8")) as { digests: string[] };
const pinnedPem = readFileSync(join(fx, "pinned-certs.pem"), "utf8");
const pinned = pinnedPem
  .split("-----END CERTIFICATE-----")
  .filter((s) => s.includes("BEGIN CERTIFICATE"))
  .map((s) => `${s}-----END CERTIFICATE-----`);

// digests[0..2] = pinned TSAs 1..3 ; digests[3] = unpinned TSA 4
const [d1, d2, d3, d4] = meta.digests;

test("valid token from pinned TSA 1 -> true", async () => {
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  assert.equal(await v(`sha256:${d1}`), true);
});

test("valid token from pinned TSA 2 -> true", async () => {
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  assert.equal(await v(`sha256:${d2}`), true);
});

test("valid token from pinned TSA 3 -> true", async () => {
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  assert.equal(await v(`sha256:${d3}`), true);
});

test("token from UNPINNED TSA 4 -> false", async () => {
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  assert.equal(await v(`sha256:${d4}`), false);
});

test("empty pinned set -> fail-closed false (v1 requires trust anchor)", async () => {
  const v = makeVerifyTSR({ tsrDir: fx });
  assert.equal(await v(`sha256:${d1}`), false);
});

test("missing .tsr file -> false (no throw)", async () => {
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  assert.equal(await v("sha256:" + "0".repeat(64)), false);
});

test("corrupt .tsr file -> false (no throw)", async () => {
  const bad = "a".repeat(64);
  const path = join(fx, `${bad}.tsr`);
  writeFileSync(path, Buffer.from("this is not a DER-encoded CMS token"));
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  try {
    assert.equal(await v(`sha256:${bad}`), false);
  } finally {
    if (existsSync(path)) unlinkSync(path);
  }
});

test("imprint mismatch: file exists but timestamps a different digest -> false", async () => {
  // copy d1's real token under a wrong digest name: file exists, parses, but imprint != name
  const wrong = "b".repeat(64);
  const src = join(fx, `${d1}.tsr`);
  const dst = join(fx, `${wrong}.tsr`);
  writeFileSync(dst, readFileSync(src));
  const v = makeVerifyTSR({ tsrDir: fx, pinnedTsaCerts: pinned });
  try {
    assert.equal(await v(`sha256:${wrong}`), false);
  } finally {
    if (existsSync(dst)) unlinkSync(dst);
  }
});
