# interop-matrix

ML-KEM-768 interoperability matrix, two ends, four cells, three seeds. It answers one
question with evidence: **do two independent ML-KEM-768 implementations agree, and can each
one use the other's ciphertexts?**

- **P** = `fibemate-pqc-kem` (pure JS, in the `fibemate` repository)
- **N** = `@noble/post-quantum` (independent JS oracle, pinned version)

Design, rules and the reasoning behind each rule: `fibemate/docs/design/interop-matrix-spec.md`
(sections 3–5, and section 11 for why the WASM end is not in the first release).

## Run it

```bash
node interop-matrix/run.cjs \
  --pqc-kem  ../fibemate/packages/pqc-kem \
  --noble    ../fibemate/node_modules/@noble/post-quantum \
  [--fibemate-repo ../fibemate] [--out interop-matrix/out]
```

Exit codes: `0` PASS, `1` FAIL, `2` setup error, `3` INVALID (a baseline cell broke, so the
harness cannot judge anything), `4` stale seed table.

`--fibemate-repo` is only used to record the commit in `matrix.json`; when omitted it is
inferred as the parent of `packages/pqc-kem`.

## What it measures

Four cells: `keygen by A -> encap by B -> decap by A`, for A,B in {P,N}. The two diagonal
cells are **baselines** (harness sanity), the two off-diagonal cells are the interop claim.
A failing baseline reports **INVALID**, never "3/4 passing".

Both ends run in **Mode D**: the caller supplies `d`, `z` and `m`, so the strong claim is
available and is what the run reports —

- `pk` and `sk` byte-identical across ends for the same seed;
- `ct` byte-identical for the same `(pk, m)`;
- `ss` identical, and each end decapsulates the other's ciphertext to the sender's secret.

`ss =P` in `matrix.md` means "the secret is byte-equal to end P's". A cell can match on
ciphertext bytes and still differ on the secret — that is exactly what a Kyber-round-3 end
does (same sizes, same ciphertext, extra KDF on the secret). The column exists so that
difference cannot hide behind a green `MATCH`.

## Seeds

`SHAKE256("fibemate-interop-matrix/2026-10/seed-i", 64)` for `i = 1,2,3`, split
`d = seed[0:32]`, `z = seed[32:64]`; message randomness uses a separate label
`.../msg-i`. The table of expected hex is in `run.cjs`; the run recomputes each seed and
**aborts with exit 4** if the table no longer matches, because a stale table is a silent lie
about which entropy was measured.

## Controls (none of them optional)

1. **Implicit rejection.** Flip one byte of `ct`; FIPS 203 §7.3 requires a deterministic
   pseudo-random secret, not an exception and not the original secret. Both ends must return
   the same wrong-but-stable secret.
2. **Wrong key.** Decapsulating with a key from a different seed must not return the sender's
   secret.
3. **Uniqueness.** Three seeds must produce three distinct `pk` and three distinct `ss`.

## Self-test: proving the harness can fail

```bash
node interop-matrix/selftest.cjs --pqc-kem ../fibemate/packages/pqc-kem --noble ../fibemate/node_modules/@noble/post-quantum
```

It runs the matrix four times and requires each outcome:

| run | mutation | expected |
|---|---|---|
| baseline | none | `PASS`, exit 0 |
| `n-kyber-kdf` | end N computes `ss = SHA3-256(K̄ ‖ SHA3-256(ct))` (Kyber round 3), self-consistent | `FAIL`, exit 1 — caught in PN/NP/NN, baselines still round-trip |
| `n-encap-ss` | end N returns a corrupted sender secret | `INVALID`, exit 3 — NN no longer round-trips |
| `p-decap-ss` | end P returns a corrupted decapsulation | `INVALID`, exit 3 |

The Kyber mutation is not academic: it is the shape of the WASM end this repository used to
call "ML-KEM-768" (issue Lennonhaha/fibemate#377). If this harness ever loses the ability to
turn that shape red, the self-test fails.

## Output

- `out/matrix.json` — run metadata (commit, versions, source `sha256`, mode, per-cell checks
  and verbatim errors), verdict, summary
- `out/matrix.md` — the same as tables; `=P`/`!=P` for byte equality, no digests
- `out/logs/<cell>-<seed>.log` — raw hex per cell, for anyone who wants to diff by hand

Artifacts under `out/` are the committed evidence for the run; they are reproduced by CI on
every change to this directory.

## What this is not

Not a security claim and not a KAT. It measures agreement between two implementations on
fixed entropy. It says nothing about side channels, timing, memory safety, or whether either
implementation is correct against the FIPS 203 test vectors — other suites cover that.
