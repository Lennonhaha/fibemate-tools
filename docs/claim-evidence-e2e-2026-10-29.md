# Claim–evidence binding: end-to-end experiment, 2026-10-29

Status: **experiment, not a normative result.** This records what one real
claim→manifest→TSR run proved, what it did not, and which open questions in
`claim-evidence-binding-spec.md` it answers.

Related: `scripts/claim-evidence/` (the runnable experiment), `docs/claim-evidence-binding-spec.md`
(the skeleton it tests), `interop-matrix/` (the artifact), `fibemate/docs/tsa/2026-10-28-interop-matrix/`
(the evidence package).

---

## 1. Why this experiment

The spec's §2 assumed a chain: **digest list seals the artifacts, token seals the list**.
Until now that was a belief written in Markdown, not something a machine could execute.
A claim checker that only compares numbers (`verifact`) and a digest tool that only
compares hashes would each look green while the other's failure mode went unnoticed.

The experiment runs both against the same artifact, then tampers with it in two ways
that are invisible to one verifier each.

## 2. Setup

| Piece | Value |
|---|---|
| Claim | mock Markdown: `checks: 62, cells: 12, failed: 0`, plus `TSR lg-116` |
| Artifact | `interop-matrix/out/matrix.json`, 23,784 B, sha256 `477266705a03b33324fabf4850af330ca40744feccf0f0b685a83a143e2391d7` |
| Digest list | `SHA256SUMS`, 1,392 B, sha256 `11e98d8cf850d504cae404f532f28d588f018ca119a178b8c4d846d896a68c4e`, 14 entries |
| Token | `lg-116-interop-matrix-SHA256SUMS.tsr`, FreeTSA, serial `0x09823CA3`, `Oct 28 11:58:04 2026 GMT`, sha256 `7e3477b0…` |
| CA | `docs/tsa/2026-09-06-vwz-rank2/freetsa-root-ca.pem` |
| Openssl | 3.2.3 (Git for Windows build; `OPENSSL_CONF` required) |

`verifact` was configured with `docs.roots = ['.']`, `artifacts.roots = ['rep']` (a mirror
of the artifact tree at the paths the manifest uses), `presenceRoots = ['evidence']`,
cache disabled, `failOn = drift`.

## 3. Results

| # | Tampering | `verifact verify` | `verify-evidence` |
|---|---|---|---|
| S0 | none | exit 0 — claims 4, verified 3, ref-found 1, drift 0 | `verified`, exit 0 |
| S1 | `summary.checks` 62 → 61 | exit 1 — `drift` on `checks` | `drift`, exit 1 (1/14 files) |
| S2 | `ends.P.name`: `…-kem` → `…-kemX` | **exit 0 — still green** | `drift`, exit 1 |
| S3 | S2 + `SHA256SUMS` line recomputed | exit 0 | `drift`, exit 1 — files match, **imprint fails** |
| S4 | CA omitted | — | `unverifiable`, exit 3 |

All 11 expectations met (`node scripts/claim-evidence/run-e2e.cjs`).

### The two rows that matter

**S2 — value comparison is blind to bytes.** Changing the end's `name` field changes
no number, so every claim still matches. `verifact` is not wrong; it was never asked
about bytes. Any claim-bound report that stops at "the numbers agree" inherits this
blind spot.

**S3 — a digest list alone is not enough.** Recomputing the manifest line makes
link 1 (files ↔ manifest) pass again. Only link 2 catches it: the token's imprint is
over the *old* manifest, so the verdict is `drift`. This is the whole reason the TSR
exists rather than a bare `sha256sum -c`.

**S4 — absence of evidence is not evidence.** With the chain missing, the verifier
returns `unverifiable` and exit 3. Without this case, "no CA" would surface as a
warning somewhere and a green run would be read as a pass.

## 4. What this answers in the spec

- **§2 (binding mechanism), tested and narrowed.** Digest from committed bytes, digest
  list, token over the list: the chain is executable today. Two additions the run
  forced:
  - the manifest's paths must be repo-relative (the first run failed with 14 `missing`
    because the sandbox root was too deep — good fail-closed behaviour, but it means
    the manifest format must state its own base);
  - the token check needs the CA *and* the request nonce compared against the token
    nonce, otherwise a token for a different request with the same imprint would pass.
- **§3 (verdicts), one new state confirmed as necessary.** `unverifiable` must be
  distinct from `unbound`. `unbound` means "the artifact says nothing about this";
  `unverifiable` means "the evidence package is incomplete". Conflating them lets a
  missing CA read as "nothing to compare", which is a false green.
- **§1 (claim format), still open, and now with a concrete example of why.** The mock
  claim only worked because its keys (`checks`, `cells`, `failed`) happened to collide
  with JSON paths. A claim about *bytes* ("matrix.json is the file this TSR seals")
  cannot be expressed in the heuristic syntax at all; it had to live in a separate
  flag-driven tool. That is evidence for an explicit claim syntax with a `scope` and
  an `evidence` pointer, not for extending the heuristics.

## 5. What it does not prove

- That the interop matrix is correct. The token proves *when* these bytes existed, not
  that they were produced by an honest run. (Same boundary as the TSR READMEs.)
- That `verifact` is a security control. It is a drift detector over numbers.
- That the manifest is complete. Nothing checks that every artifact the claim depends
  on appears in the list; a short manifest verifies fine.

## 6. Reproduce

```bash
# fibemate-tools checkout, fibemate checkout beside it
node scripts/claim-evidence/run-e2e.cjs --fibemate ../fibemate
```

The script copies artifacts and evidence into a scratch directory; neither checkout is
modified. It is not in CI: it needs both repositories and network-free `openssl`, and a
cross-repo fixture would eventually drift from the evidence it claims to seal.
