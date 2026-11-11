# cbom-tools

![coverage](https://img.shields.io/badge/coverage-96.5%25%20lines-brightgreen)
![gate](https://img.shields.io/badge/CI%20floor-90%25%20lines-blue)

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
- **It does not guarantee a complete inventory.** Detection is pattern-based per language and library. A clean scan means "no match against the patterns this version knows" — not "there is no cryptography here". Generated code, native bindings, vendored binaries, and names computed at runtime (`process.env`, a network response, a value assembled from variables) can all be missed. The CBOM is evidence of what was found, not a certificate of what exists.

  Names assembled from *literals* are resolved before matching — `'sha' + '256'`, `['sh','a256'].join('')`, `` `ml-kem-${'768'}` ``, base64 payloads, `\x` escapes. `test/fixtures/evasion/` holds one fixture per form, so this claim is executable rather than aspirational. See [Testing](#testing).
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

## Exit codes

A scan that cannot run must not look like a scan that found nothing.

| code | `cbom-tools scan` | `cbom-tools diff` |
|---|---|---|
| 0 | scan completed | no changes |
| 1 | — | changes found (see severity) |
| 2 | usage error, bad `--spec`, `--dir` missing or not a directory | missing file, invalid JSON, bad argument |
| 3 | — | critical change |
| 4 | — | CBOM could not be loaded |

Until 0.2.7 a missing `--dir` printed an empty CBOM and exited 0. In a pipeline that reads as "no cryptography in this tree", so a typo in the path produced a clean result. It now exits 2. Per-file problems (unreadable file, file over 8 MB, unparsable `package.json`) are warned on stderr and the rest of the tree is still scanned — a partial inventory is reported as partial, never as empty.

## Testing

```
npm test              # 122 tests, Node built-in node:test
npm run test:coverage # same suite, fails below the thresholds
```

**Coverage: 96.5% lines / 97.4% functions / 86.6% branches**, measured over the five published source files (`cli.cjs`, `cbom-scan.cjs`, `cbom-diff.js`, `cbom-csv.cjs`, `algorithm-hierarchy.cjs`). CI enforces a floor of **90% lines, 90% functions, 80% branches**; the badge at the top reports the measured value, the gate is what makes it true tomorrow.

What the suite covers:

- **Negative controls** (`test/fixtures/evasion/`): ten forms that make an algorithm name hard to see at the call site — constant alias, array join, template interpolation, base64, hex escapes, split `require`, destructured import, Python `getattr`, C macro, string split across lines. Each fixture asserts the algorithm is still reported. This is the anti-false-compliance line: code that uses a weak algorithm must not produce an empty CBOM.
- **Fault tolerance**: missing `--dir` (exit 2), `--dir` pointing at a file (exit 2), 8 MB+ file skipped with a warning, unreadable file skipped with a warning, malformed `package.json` warned and skipped. None of these crash, and none of them pretend to be a clean scan.
- **Dispatcher contract** (`cli.cjs`): `--help`, `--version`, unknown subcommand, and exit-code passthrough for both binaries — the entry point `npx cbom-tools` uses was previously untested.
- **Existing contract tests** unchanged: schema validation against the vendored official CycloneDX schemas, `--spec` behaviour, provenance merge, CSV input, omission semantics.

One caveat stated as a caveat: the unreadable-file case is skipped on Windows, where `chmod` only clears the read-only bit and does not deny reads. It runs on the Linux CI job.

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

**Our output aligns with the latest CycloneDX 1.7 clarification (#1175): an omitted
`nistQuantumSecurityLevel` means unknown/unassessed, never 0.** The scan is file-level,
so it never asserts a NIST category — not even 0, which would claim that none of the
categories is met. Every emitted BOM carries the same sentence as a machine-readable
property, `fibemate:nistQuantumSecurityLevel:semantics`, so a consumer does not have to
guess what the absence means. The clarification is issue
[#1175](https://github.com/CycloneDX/specification/issues/1175) with the wording in PR
[#1177](https://github.com/CycloneDX/specification/pull/1177); both were open at the time
of writing, so treat this as aligning with a proposed clarification rather than a released
one. `cbom-diff` keeps the distinction too: an omitted value and an explicit `0` are
reported as a change, not as equal.

### How that lines up in time

| Date | Event |
|---|---|
| 2026-09-26 | `cbom-scan` v0.1.0 (`55dffbc`) ships without ever emitting `nistQuantumSecurityLevel`. The field appears only in `cbom-diff`, which compares with `!==` — so an omitted value and `0` were already distinct in this tool. |
| 2026-10-25 | CycloneDX issue [#1175](https://github.com/CycloneDX/specification/issues/1175) raises the gap: `0` cannot express "not evaluated". |
| 2026-10-26 | PR [#1177](https://github.com/CycloneDX/specification/pull/1177) proposes the wording for 1.7; this repository adds explicit-zero / omitted / family-only fixtures (#89) and round-trip evidence (#114). |
| 2026-10-30 | CycloneDX merges [#1186](https://github.com/CycloneDX/specification/pull/1186), restricting the 2.0 range to 0-5 because `6` had no defined meaning (issue #1185, not ours). |
| 2026-11-11 | Every emitted BOM carries `fibemate:nistQuantumSecurityLevel:semantics`, and `test/omission-semantics.test.cjs` pins both halves: the scanner never emits the field, and the differ never folds absence into `0`. |

The first row is the part worth stating plainly: the omission predates the discussion by a
month. What the discussion added was not the behaviour but the *wording* that tells a
consumer what the absence means.

## License

Apache-2.0