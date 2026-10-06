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

## CycloneDX 1.6 mapping

- `manifest-analysis` → `methods[]: { technique: "manifest-analysis", confidence, value: <pkg> }`
- `source-code-analysis` → `methods[]: { technique: "source-code-analysis", confidence, value: <matched text> }`
- merged → one identity, two methods, all occurrences retained
- separate → one component per record, one method each

This is a **conservative generator policy** — not a CycloneDX mandate.