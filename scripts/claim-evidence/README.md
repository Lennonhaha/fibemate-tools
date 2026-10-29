# claim-evidence end-to-end experiment

A mock claim, a real evidence package, two verifiers, one deliberately tampered byte.

This is the experiment that `docs/claim-evidence-binding-spec.md` asks for in its
"Next steps" §2: run a claim→manifest→TSR chain against a real artifact pair and see
which of the spec's open questions the example actually forces.

## The two questions

| Verifier | Question | Blind spot |
|---|---|---|
| `verifact verify` | do the **numbers** in the claim match the numbers in the artifact? | a changed byte that changes no number |
| `scripts/claim-evidence/verify-evidence.cjs` | are these the **exact bytes** the timestamp token seals? | whether the artifact is *correct* |

Both are needed. `verifact` alone cannot see byte-level tampering; a digest list alone
cannot see a rewritten digest list. The token is what closes the second hole.

## Run it

```bash
# from a fibemate-tools checkout, with the fibemate repository next to it
node scripts/claim-evidence/run-e2e.cjs --fibemate ../fibemate

# or point at both explicitly; --keep leaves the scenario workspaces for inspection
node scripts/claim-evidence/run-e2e.cjs --tools . --fibemate /path/to/fibemate --keep
```

Requires `openssl` (3.x) on PATH. On Windows the script sets `OPENSSL_CONF` from the
usual install locations if it is not already set.

Exit: `0` all expectations met, `1` an expectation failed, `3` a required input is missing.

## Scenarios and expected results

| # | Scenario | verifact | verify-evidence |
|---|---|---|---|
| S0 | untouched package | exit 0, 3 verified | `verified`, exit 0 |
| S1 | `summary.checks` 62 → 61 | `drift`, exit 1 | `drift`, exit 1 |
| S2 | one byte in `ends.P.name`, no number touched | **exit 0, still green** | `drift`, exit 1 |
| S3 | S2 + manifest digest line rewritten to match | exit 0 | `drift`, exit 1 (imprint mismatch) |
| S4 | no CA supplied | — | `unverifiable`, exit 3 |

S2 is the finding, not a defect report: value comparison has no notion of bytes.
S3 is why the digest list needs a token: link 1 (files vs manifest) passes, link 2
(token vs manifest) fails.

## Evidence used

`lg-116`, FreeTSA, serial `0x09823CA3`, `Oct 28 11:58:04 2026 GMT`, sealing
`SHA256SUMS` (1,392 B, sha256 `11e98d8c…`) which lists 14 files:

- `interop-matrix/out/matrix.json` (23,784 B, sha256 `47726670…`)
- `interop-matrix/out/matrix.md`
- `interop-matrix/out/logs/{NN,NP,PN,PP}-S{1,2,3}.log`

Artifacts live in this repository; the digest list and the token live in
`fibemate/docs/tsa/2026-10-28-interop-matrix/`. The experiment copies both into a
scratch directory and never writes to either checkout.

## What a `verified` here does not mean

The chain proves **what was published, and when**. It does not prove that the matrix
is correct, that the cells were executed honestly, or that ML-KEM-768 is secure. A
timestamp over a wrong answer is a timestamp over a wrong answer. Read it as
"these bytes existed at this time", not as "this is true".

## Exit codes of `verify-evidence.cjs`

| Code | Meaning |
|---|---|
| 0 | `verified`: every file matches the manifest and the token seals that manifest |
| 1 | `drift`: a file, the manifest, or the token link does not match |
| 2 | usage error (bad flags) |
| 3 | `unverifiable`: an input is missing, unparsable, or the chain could not be checked |

There is no path that reports `verified` without checking both links.
