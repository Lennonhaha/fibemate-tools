# 2026-11-16 audit snapshot

Why this is in the repo: the audit was first run from a working copy outside the repo
(`D:\FIBEMATE\release-audit\`). Keeping only the tools in git would have left the
evidence — the 18 records and the generated table — on one machine, which is the
same failure mode as an audit with no artifacts.

`audit.md` is the generated table. `results/*.json` are the raw `verify-one.cjs`
records, one line each, kept byte-for-byte as produced so the numbers in the table
can be recomputed instead of trusted.

Scope: `latest` for 6 packages (7 including `fibemate-pqc-kem`), plus every
`cbom-tools` version on the registry (13). Totals: **18 records, PASS 6 / FAIL 12,
A 3 / B 6 / C 7 / D 2**.

Reading the failures:

- **C (7)** — published before OIDC provenance existed. Historical; not repairable.
- **D (2)** — `cbom-tools@0.1.1` and `@0.2.1` were published with no tag and no
  Release. Historical; not repairable, and not deprecated (no auth path without
  introducing a long-lived token for a purely advisory flag).
- **B + FAIL (3)** — `cbom-tools@0.2.6`, `verifact@0.2.4`,
  `crypto-hallucination-detector@0.1.2`: built from `main` after the tag. Evidence is
  complete and the package directory is byte-identical to the tag, but provenance
  records a branch, so the release does not prove it came from the tag. Fixed going
  forward by publishing from tags; the historical records stay red on purpose.

Re-run:

```bash
node ../../verify-one.cjs cbom-tools 0.2.9 --git-dir <repo> --pkg-dir cbom-tools
node ../../summarize.cjs --dir results --out audit.md
```
