# Cross-version fidelity fixtures

Two minimal CBOMs that observe the *same three facts* about a cryptographic asset,
expressed once per spec generation. They exist so that BOM-fidelity tools can check
whether information survives schema validation and tool round-trips.

| File | Schema | How "algorithm family" is carried |
|---|---|---|
| `cbom-fidelity-1.6.2.json` | CycloneDX 1.6 (`bom-1.6.schema.json`, tag `1.6.2`) | `component.name` only — 1.6 has no `algorithmFamily` field |
| `cbom-fidelity-1.7.2.json` | CycloneDX 1.7 (`bom-1.7.schema.json`, tag `1.7.2`) | `algorithmProperties.algorithmFamily`, constrained by `cryptography-defs.schema.json` |

Each file carries three `cryptographic-asset` components:

1. `crypto:alg:family-only` — a family-level observation with no parameter set.
2. `crypto:alg:explicit-zero` — `nistQuantumSecurityLevel: 0` on an algorithm that
   really does meet none of the NIST categories (`MD5`), i.e. *evaluated, and none of
   the categories are met*.
3. `crypto:alg:omitted-namespaced` — `nistQuantumSecurityLevel` deliberately **omitted**,
   with the producer's own assessment status preserved out of band in a namespaced
   property `fibemate:nistQuantumSecurityLevel = "notEvaluated"`.

## Why the distinction matters

`nistQuantumSecurityLevel` is an integer in `[0, 6]`. `0` means "none of the categories
are met", which is not the same statement as "this algorithm was never evaluated".
Omitting the field asserts no category at all — and, on its own, says nothing about
whether an assessment happened: producers omit it for different reasons ("not assessed
this round", "assessed, but NIST categories are the wrong scale", "level unknown").
A consumer that fills missing values with defaults will therefore collapse "no
assertion" into "evaluated as zero" and silently promote it to `0`.

Assessment status is a separate question from a NIST category claim. Where a producer
needs to record it, it currently has to live outside the standard field — here, as a
namespaced property.

## Notes on the two documents

- They are **independent test cases**, not a conversion pair. The `serialNumber`s and
  `bom-ref`s differ on purpose so that diff tools do not read them as two versions of
  one artifact.
- `SM2` is recorded as `primitive: signature` (it is a signature / public-key
  encryption scheme, not a KEM).
- In 1.7, `algorithmFamily` is validated against
  `cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum`. Plain `RSA` and
  `DH` are absent from that enum — only `RSAES-OAEP`, `RSAES-PKCS1`, `RSASSA-PKCS1`,
  `RSASSA-PSS`, and `ECDH` / `FFDH` / `X3DH` exist. A family-level observation of RSA
  or DH therefore cannot use `algorithmFamily`; omit it and rely on `component.name`.
- The fixtures use `MD5`, `ML-KEM` and `SM2`, all present in that enum, so the family
  values stay inside the enumeration.

## Validating locally

Both files were validated with `ajv` 8 against the official schemas fetched from the
specification repository at the tags named above (`spdx.schema.json` and
`jsf-0.82.schema.json` as subschemas; `cryptography-defs.schema.json` for the 1.7 enum).
