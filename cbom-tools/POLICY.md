# Detection Provenance Policy

## Rule

> Merge only when the evidence establishes compatible algorithm identity
> and parameter-set specificity for the records being combined. Preserve
> both detection origins in the emitted BOM. Otherwise keep the records
> separate. Zero occurrences alone is not a reason to merge.

## Detection origins

- **`manifest-analysis`** — inferred from a dependency name. This is
  *dependency-derived capability*, not confirmed use. For multi-parameter
  or multi-family packages, emit **family-level** inference.
- **`source-code-analysis`** — matched from source text. This is
  *source-pattern evidence*, not proof of execution or actual crypto use.

## Merge criteria

Records merge only when **both** hold:

1. The same algorithm identity (exact name — no cross-name inference).
2. **Compatible granularity**: either both records are family-level,
   or both records are specific to the same parameter set.

A family-level record never merges with a parameter-set-specific record
of the same family, even if the family matches. Specific and generic
records stay separate unless additional evidence justifies consolidation.

This is a **suggested generator policy**, not a normative CycloneDX rule.

### Coverage limitation

The current `@noble/hashes` mapping emits only `Keccak` at family level.
This is **partial coverage** of the package's supported algorithms, not
an exhaustive inventory. Other families (SHA-2, SHA-3, Blake, RIPEMD,
...) are not inferred in this iteration. Absence of a family in the
emitted BOM does not imply the package lacks it.

## Algorithm hierarchy

| Parameter set | Family |
|---------------|--------|
| ML-DSA-44 | ML-DSA |
| ML-DSA-65 | ML-DSA |
| ML-DSA-87 | ML-DSA |
| ML-KEM-512 | ML-KEM |
| ML-KEM-768 | ML-KEM |
| ML-KEM-1024 | ML-KEM |
| Keccak-224 | Keccak |
| Keccak-256 | Keccak |
| Keccak-384 | Keccak |
| Keccak-512 | Keccak |
| SLH-DSA | (family only) |

## CycloneDX 1.6 / 1.7 mapping

The mapping below is identical in 1.6 and 1.7; only `specVersion` differs.

- `manifest-analysis` → `methods[]: { technique: "manifest-analysis", confidence, value: <pkg> }`
- `source-code-analysis` → `methods[]: { technique: "source-code-analysis", confidence, value: <matched text> }`
- merged → one identity, two methods, all occurrences retained
- separate → one component per record, one method each

`confidence` describes the evidence, not the name's specificity: `0.9` when the
algorithm was seen in source, `0.7` when it is only a declared dependency, and the
identity's value is the maximum over its methods. A family-level name (`ML-KEM`) and a
parameterised one (`ML-KEM-768`) both score `0.9` when found in source; which of the
two it is, is carried by `component.name` and `cryptoProperties`. See
`docs/adr-0001-confidence-model.md`.

## Reproducible output

`metadata.timestamp` is the current time by default. Set `SOURCE_DATE_EPOCH` (seconds
since the epoch) to pin it — that is what makes the committed sample
`cbom-cyclonedx.json` byte-for-byte reproducible:

```bash
node scripts/gen-sample-cbom.cjs        # regenerates from fixtures/sample-project/
node scripts/check-sample-cbom.cjs      # exits 1 if the committed bytes drifted
```

CI runs the second command; a checked-in BOM that nobody regenerates goes stale
silently, which is what happened to this sample between 0.2.1 and 0.3.0.

This is a **conservative generator policy** — not a CycloneDX mandate.