# ADR-0001 — Source confidence: decouple it from `params`

- **Status:** accepted, implemented in 0.3.0 (2026-11-16)
- **Scope:** `cbom-tools/cbom-scan.cjs` (`mergeEvidence`), scoring use of
  `algorithm-hierarchy.cjs`'s `params`, and every BOM the tool emits
- **Related:** 0.2.9 dictionary gate (`test/legacy-recall.test.cjs`), CHANGELOG 0.2.9
  "single-value algorithms keep a 0.7 source confidence"

## 1. The code this ADR replaces

```js
const h = HIERARCHY[name];
const conf = (h && h.params !== null) ? 0.9 : 0.7;
```

`identity.confidence` was the maximum over the component's methods
(`cbom-scan.cjs`, `mergeEvidence`), with a defensive `0.5` when there were none.
`manifest-analysis` was flat `0.7`. So a dependency-only component and a source hit on
a family-level name concluded the same number, from evidence of different strength.

## 2. What `0.7` used to mean: three things at once

1. **"The dictionary had no entry for this name."** The original intent —
   `test/legacy-recall.test.cjs` still spelled it out: a rule-emitted name with no
   hierarchy entry "ships with a 0.7 source confidence instead of 0.9".
2. **"The entry is family-level or single-value"** (`params: null`) — which describes
   `ML-KEM` exactly as well as `MD5`.
3. **"Seen only in a manifest."** Unrelated to 1 and 2, numerically identical.

Meaning 1 died with the 0.2.9 gate, which asserts every name any rule can emit resolves
to both a metadata entry and a hierarchy entry. What remained was meaning 2 — a
statement about **name specificity** — standing in for **evidence strength**, which is
what `evidence.identity[].confidence` is defined to mean.

## 3. The problem

**In the cases that mattered most, the number said the opposite of the truth.**

The tool's own published example was wrong in exactly this way. `docs/cbom-tools-tutorial.md`
§4 presented "the real content" of a component as `ECDH` with
`"confidence": 0.7` on a `source-code-analysis` method — an algorithm found in source,
scored like a dependency that merely appears in `package.json`. A reader comparing
`ML-KEM 0.7` against `ML-KEM-768 0.9` concludes the family-level finding is weaker
evidence. The 0.2.9 note in the CHANGELOG then had to explain that this is "the current
model, not a regression", which is the tell: the number needed a paragraph.

Measured on the corpus in this repository:

| corpus | components | at 0.7 | at 0.9 |
|---|---|---|---|
| `fixtures/legacy/` | 19 | **14** | 5 — exactly the names carrying a parameter suffix |
| `fixtures/sample-project/` (added by this change) | 23 | 1 (manifest-only `Keccak`) | 22 |
| dictionary | 97 entries | 50 have `params: null` | 47 carry a value |

Half the dictionary is `params: null`, and that half includes the flagship post-quantum
names (`ML-KEM`, `ML-DSA`, `SLH-DSA`) plus every single-value algorithm (`MD5`, `3DES`,
`Ed448`, `X448`, `Poly1305`). The value was not measuring evidence; it was measuring
whether a name happened to have a parameter set.

**Consumers.** In this repository, nothing reads the field: `cbom-csv.cjs`,
`cbom-diff.js` and `cli.cjs` contain zero occurrences of `confidence`, so no gate, filter
or diff depends on it. What does depend on it is everything outside: BOM viewers, the
tutorial, and any human reading the JSON. One invariant is asserted in tests
(`test/provenance.test.cjs`): identity confidence equals the max of its methods. Any
option must keep that.

**A constraint that rules out the cheap fix.** `params` is not only a scoring input:
`deduplicateOccurrences()` uses `params !== null` to mean "this match is *specific*, so
its span may absorb a covered generic match". The field carries two jobs — specificity
for absorption, and the scoring proxy.

## 4. Options

### A. Keep it, document the meaning — rejected

State in README, CHANGELOG and report headers that `0.7` means "no parameter family,
not weak evidence".

It documents a semantically wrong value instead of fixing it. In CycloneDX, `confidence`
is a claim about identity certainty, so a reader's prior that `0.7 < 0.9` is *correct*
for that field; the documentation has to fight the field's own definition, in every
downstream viewer that never reads our README. It also leaves a manifest-only hit and a
source hit indistinguishable.

### B. Non-null sentinel (`params: 'single'`) — rejected

Give single-value algorithms a parameter marker so they reach 0.9.

1. **It is false data.** `MD5`, `3DES`, `Ed448` have no parameter set; `'single'` is not
   a parameter value, and putting it beside `'224'`, `'GCM'`, `'prime'` destroys the
   meaning of the field.
2. **It changes absorption.** Every such name enters `specificSpans`, so a generic match
   on the same span may now be absorbed by something that is not more specific. Not
   visible for `MD5` (no generic sibling), but `Ed25519`/`X25519` live in the `EdDSA`/
   `XDH` families, where "specific vs family" is exactly the distinction at stake.
3. **It fixes a number by lying in the field that encodes a different fact**, so the next
   consumer of `params` inherits the lie.

Not "discouraged" — excluded. The only reason it looks cheap is that it is wrong in one
place instead of three.

### C. Score by evidence, not by `params` — accepted

```js
const CONFIDENCE = Object.freeze({
  'source-code-analysis': 0.9,  // a token in code: the algorithm is used here
  'manifest-analysis':    0.7,  // a declared dependency: capability, usage unproven
});
// identity.confidence = max(method confidences)   [unchanged]
// 0.5 defensive fallback for a component with no methods   [unchanged, unreachable today]
```

**Technique names are the schema's, not ours.** Both `test/fixtures/bom-1.6.schema.json`
and `bom-1.7.schema.json` enumerate them at
`#/definitions/componentIdentityEvidence/properties/methods/items/properties/technique`
as `["source-code-analysis", "binary-analysis", "manifest-analysis", "ast-fingerprint",
"hash-comparison", "instrumentation", "dynamic-analysis", …]`. A test asserts that every
key in `CONFIDENCE` is in that enum, so a table-driven mismatch cannot ship.

`params` leaves the scoring path and keeps its structural job. Specificity stays where
it already is: `component.name` (`ML-KEM` vs `ML-KEM-768`) and
`cryptoProperties.algorithmProperties`.

## 5. Implementation (0.3.0)

1. **`cbom-scan.cjs`** — the ternary is gone in both places; both method confidences come
   from `CONFIDENCE`; `identity.confidence = max(methods)` untouched.
2. **`test/confidence-model.test.cjs`** — seven assertions: enum membership; manifest-only
   → 0.7; source hit on `params: null` (`ML-KEM`) → 0.9; merge → 0.9 with both methods;
   identity == max(methods); a static check that no regex of the old form exists in the
   source; and the mutation guard below.
3. **The mutation guard is the point.** It rewrites `HIERARCHY['ML-KEM'].params` to
   `'768'`, `'1024'`, `'arbitrary'` and back to `null`, and asserts the confidence never
   moves. Verified falsifiable: reintroducing the old ternary turns four assertions red
   (3, 4, 6 and 7) and restoring it returns 7/7.
4. **The sample BOM is now reproducible, and CI says so.** `cbom-cyclonedx.json` was
   produced from a demo project that no longer exists and had been frozen at 0.2.1 while
   the model changed under it — a checked-in artifact describing behaviour the code no
   longer had. It is now generated from `fixtures/sample-project/` with
   `SOURCE_DATE_EPOCH` pinned (`scripts/gen-sample-cbom.cjs`), and
   `scripts/check-sample-cbom.cjs` fails CI when the committed bytes differ from a fresh
   scan, listing the components that moved. Chosen over "delete the sample" because
   `cbom-diff`'s default self-diff smoke test and `scripts/cbom-official-crosscheck.cjs`
   both consume it; chosen over "keep and regenerate by hand" because that is exactly the
   arrangement that produced a stale file nobody noticed.
5. **Docs** — tutorial example `ECDH` 0.7 → 0.9 plus a row explaining what the number
   means; `POLICY.md` gains the same two sentences; CHANGELOG 0.3.0 records it under
   "Changed (output)".

## 6. Consequences

- Components previously at 0.7 because their name had no parameter family now report 0.9
  when seen in source; manifest-only components stay 0.7. No schema change, no API
  change, no CLI change.
- `cbom-diff` does not compare confidence, so diffs do not churn.
- A pre-1.0 minor with a "Changed" note is sufficient; this is not a breaking schema
  change.
- The scale remains two-valued. That is deliberate.

## 7. What this ADR does not do

- No weighted score. A fine-grained number would look like a measurement and would not be
  one; two values that mean something beat five that do not.
- No `fibemate:nameSpecificity` property. The axis is real, but nothing consumes it, and
  adding it now would re-encode `params` in a second place. Revisit when a consumer asks.
- No change to the absorption logic, whose `params` semantics stay exactly as they are.
