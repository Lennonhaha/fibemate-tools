# cbom-tools

**Cryptographic Bill of Materials — scan, diff, report.**

Scan a directory tree for cryptographic assets, emit a
[CycloneDX 1.7](https://cyclonedx.org/specification/overview/) CBOM, and diff two
CBOMs to detect algorithm additions, removals, and metadata changes.
1.6 output is still available with `--spec 1.6` for consumers that have not
moved yet.

Zero external dependencies. Pure Node.js.

## What this tool does not do

Three things that are easy to misread:

- **It does not find vulnerabilities.** No CVE lookup, no taint analysis, no judgement about whether an algorithm choice is sound. It reports *where cryptographic APIs are called*, and says nothing about whether they are called well.
- **It does not guarantee a complete inventory.** Detection is pattern-based per language and library. A clean scan means "no match against the patterns this version knows" — not "there is no cryptography here". Dynamic loading, generated code, native bindings and vendored binaries can all be missed. The CBOM is evidence of what was found, not a certificate of what exists.
- **It does not execute the code it scans.** Files are read and parsed. Nothing in the scanned tree is run.

A CBOM is an inventory to review. It is not a compliance conclusion, and it cannot replace an audit.

## Try it without installing

```
npx cbom-tools scan --dir ./my-project --out cbom.json --spec 1.7
npx cbom-tools diff cbom-before.json cbom-after.json
```

Global install (optional):

```
npm install -g cbom-tools
```

## Usage

### 1. Scan a project

```
npx cbom-tools scan --dir ./my-project --out cbom.json --spec 1.7
```

`cbom-scan` is still installed as a standalone alias.

### Spec version

`--spec` accepts `1.7` (default) and `1.6`. Both forms work:
`--spec 1.7` and `--spec=1.7`. Anything else is a usage error (exit 2)
rather than a silent fallback — a BOM that claims a version it does not
conform to is worse than no BOM.

The schema is the contract, so CI validates the emitted document against the
official `bom-1.7.schema.json` (and, for `--spec 1.6`, against
`bom-1.6.schema.json`). The two differ in the declared version and in which
documented fields are permitted; the findings themselves are identical, and a
test asserts exactly that.

Scans:
- `package.json` dependencies (declarative rule table)
- Source files (`.js/.cjs/.mjs/.ts/.tsx/.jsx`) via regex patterns

Output: a CycloneDX 1.7 JSON with `cryptoProperties` (asset type,
primitive, quantum security level) and `evidence.occurrences` (file
paths + line numbers, capped at 50 per algorithm, deduplicated).
Pass `--spec 1.6` to emit the previous schema version instead.

### 2. Diff two CBOMs

```
npx cbom-tools diff cbom-before.json cbom-after.json
```

`cbom-diff` is still installed as a standalone alias.

Exit codes:
- `0` — no changes
- `1` — informational changes (algorithm properties moved)
- `2` — warnings (algorithm removed, new classical reference), or file/parse error
- `3` — a quantum-vulnerable algorithm was newly introduced (requires both CBOMs)

Exit 3 follows the definition agreed in [#43](https://github.com/Lennonhaha/fibemate-tools/issues/43):
an algorithm whose `fibemate:quantumSecurity:level` is `vulnerable` appears in the
after CBOM but not in the before CBOM. Two consequences are deliberate:

- An algorithm that was already vulnerable and stays vulnerable is not a
  regression, so it never turns the build red.
- A single-CBOM scan has no baseline to compare against, so it stays at exit 1.
  Otherwise the first scan of a legacy codebase would light up every historical
  finding at once.

The level is read from `component.properties` (`fibemate:quantumSecurity:level`),
which is where `cbom-scan` writes it; `cryptoProperties.quantumSecurity.level` is
accepted as a fallback for hand-written CBOMs. A missing or malformed level stays
unknown — it is never inferred from the algorithm name.

## Testing

```
npm test
```

76 tests (Node built-in `node:test`, zero dependencies). Both binaries are
spawned as child processes and checked against edge inputs — empty directory,
dependencies-only, source-only, an 800-file tree (occurrence cap,
`node_modules` / `.git` / dotfile skipping), unreachable directories, missing
argument values, and malformed JSON.

`test/spec-version.test.cjs` covers the `--spec` contract: the default is
1.7, both `--spec 1.7` and `--spec=1.7` are parsed, an unknown version exits
2 with the allowed list, the emitted document validates against the vendored
official schema for the version it claims, and switching versions does not
change the findings. Schemas are vendored under `test/fixtures`, so the suite
runs offline.

## Example (real output)

Scanning a repository before and after a PQC migration:

```
$ cbom-scan --dir ./repo-before --out before.json
cbom-scan: wrote 11 algorithms to before.json (CycloneDX 1.7)

$ cbom-scan --dir ./repo-after --out after.json --spec 1.6
cbom-scan: wrote 13 algorithms to after.json (CycloneDX 1.6)

$ cbom-diff before.json after.json
## CBOM Diff

Removed: none
Added: Keccak-256, SHA3-512

Exit code: 1
```

## Detected algorithms

Rule table covers 13 algorithms:

| Primitive | Algorithms |
|---|---|
| KEM | ML-KEM-768 (and aliases) |
| Signature | ML-DSA-65, SLH-DSA, SM2 |
| Hash | SHA-256, SHA3-256, SHA3-512, Keccak-256, SM3 |
| Symmetric | SM4 |
| Other | (extensible via source rules) |

Detection input:
- Package names (`@noble/post-quantum`, `sm-crypto`, etc.)
- API call patterns (`crypto.createHash('sha3-256')`, etc.)

## What this tool does NOT do

- ❌ Does NOT implement cryptographic algorithms
- ❌ Does NOT provide cryptographic operations (no keygen, encrypt, sign)
- ❌ Does NOT read or verify keys, certificates, or signatures
- ❌ Does NOT constitute a compliance certificate or audit

All cryptographic information is derived from CycloneDX SBOM
specification and public algorithm parameters. Static pattern matching
only — no cryptographic computation is performed.

## Standards

Emits the [CycloneDX 1.7](https://cyclonedx.org/specification/overview/) CBOM
format by default, with 1.6 available via `--spec 1.6`. The specification is
maintained by [OWASP](https://owasp.org/) under Apache-2.0.

## License

Apache-2.0