# cbom-tools

**Cryptographic Bill of Materials — scan, diff, report.**

Scan a directory tree for cryptographic assets, emit a
[CycloneDX 1.6](https://cyclonedx.org/) CBOM, and diff two CBOMs to
detect algorithm additions, removals, and metadata changes.

Zero external dependencies. Pure Node.js.

## Install

```
npm install -g cbom-tools
```

## Usage

### 1. Scan a project

```
cbom-scan --dir ./my-project --out cbom.json
```

Scans:
- `package.json` dependencies (declarative rule table)
- Source files (`.js/.cjs/.mjs/.ts/.tsx/.jsx`) via regex patterns

Output: a CycloneDX 1.6 JSON with `cryptoProperties` (asset type,
primitive, quantum security level) and `evidence.occurrences` (file
paths + line numbers, capped at 50 per algorithm, deduplicated).

### 2. Diff two CBOMs

```
cbom-diff cbom-before.json cbom-after.json
```

Exit codes:
- `0` — no changes
- `1` — changes detected
- `2` — file not found or parse error

## Example (real output)

Scanning a repository before and after a PQC migration:

```
$ cbom-scan --dir ./repo-before --out before.json
cbom-scan: wrote 11 algorithms to before.json

$ cbom-scan --dir ./repo-after --out after.json
cbom-scan: wrote 13 algorithms to after.json

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

Implements the [CycloneDX 1.6](https://cyclonedx.org/specification/overview/)
CBOM specification, maintained by [OWASP](https://owasp.org/) under
Apache-2.0.

## License

Apache-2.0