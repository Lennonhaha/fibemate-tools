# Changelog

Entries start at 0.2.7; earlier releases predate this file. Versions follow
[Semantic Versioning](https://semver.org/), and this tool is pre-1.0, so the
minor number moves for behaviour changes.

## Unreleased

### Added

- `docs/compliance-methodology.md`: the rules behind the three judgements
  (bucket precedence, verdict table, the PEM-only scope, why block 3.3 is always
  `无法判定`), the four-value vocabulary, what part of GB/T 39786-2021 is used,
  and the change-control requirements for the decision table. Method only - no
  behaviour change, no version bump.
- `compliance` now opens with three judgements (算法强度 / 硬编码风险 / 加密存储边界)
  and a four-value vocabulary: 合规 / 建议整改 / 高风险 / 无法判定. The third
  judgement is always 无法判定: an algorithm inventory cannot see a data flow, and
  a made-up verdict there would be the first thing a reviewer catches.

### Added: a compliance view that refuses to grade

`cbom-tools compliance --bom cbom.json --dir ./project --out report.md` turns a
CBOM into a Markdown self-check report oriented at 密评 review. Five buckets
(approved / not approved / deprecated / construct / unknown), evidence locations
per algorithm, an explicit "not assessed" table, and no score.

Two failure modes this is written against:

- Reading `quantumSecurity.level` as a compliance verdict. SM3 and SM4 are
  `weak` on that axis (Grover) and approved on the other. The report states the
  two axes separately; `test/cbom-compliance.test.cjs` asserts the SM4 case
  specifically, and a mutant that treats quantum-weak as deprecated turns the
  suite red.
- Reporting an empty scan as a clean result. An empty CBOM says "not found",
  not "compliant", and the test asserts the wording.

PEM private-key blocks are counted when `--dir` is supplied. Key length,
key lifecycle (GB/T 39786-2021 Annex B), RNG quality, module certification,
protocol correctness and side channels are listed as not assessed instead of
being silently out of scope.

## 0.3.1 - 2026-11-18

### Fixed: compact liboqs / PQClean identifiers were still invisible

Issue #186 measured the dictionary gap on canonical names (`FrodoKEM-640-AES`). Those
are matched. The identifiers a vendored implementation directory actually contains are
not: liboqs and PQClean glue the family to its parameter set with an underscore or with
nothing at all.

| source line | before | after |
|---|---|---|
| `OQS_KEM_alg_frodokem_640_aes` | nothing | FrodoKEM |
| `pqclean_mceliece348864_clean` | nothing | Classic-McEliece |
| `OQS_KEM_alg_ntruprime_sntrup761` | nothing | NTRU-Prime |
| `crypto_kem_ntruhps2048509_keypair` | nothing | NTRU |

A word boundary cannot match these: `_` and digits are word characters, so
`\bfrodokem\b` sees `FrodoKEM-640-AES` and not `frodokem_640_aes`. The new rules take
the separator as part of the match and exclude `-`, so the canonical spelling is still
handled once, by the existing rule, instead of producing a second occurrence on the
same line.

Verification:

- `node --test test/legacy-recall.test.cjs`: 10 tests pass, including the two new ones
  (the compact fixture must yield exactly the four families; a prose fixture must yield
  none).
- The negative control is real, not asserted: the 0.3.0 scanner reports 0 components on
  `fixtures/liboqs-compact/`; the patched one reports the four families.
- `npm test`: 155 tests, 154 pass, 1 skip (the existing Windows chmod case).

## 0.3.0 — 2026-11-16

### Changed (output): source confidence no longer depends on `params`

`evidence.identity[].confidence` was computed as `params !== null ? 0.9 : 0.7`, so a
family-level name (`ML-KEM`, `SHA-256`, `Ed448`) scored 0.7 while its parameterised
sibling (`ML-KEM-768`) scored 0.9 — and a dependency that merely appears in
`package.json` scored 0.7 too. Three different statements, one number, and the one that
mattered most read backwards: the flagship post-quantum detections looked like the
weakest evidence in the document. The tutorial shipped that reading in its own example
(`ECDH`, seen in source, shown as 0.7).

Confidence now follows the technique that established the name, which is what the
CycloneDX field means:

| technique | confidence | why |
|---|---|---|
| `source-code-analysis` | 0.9 | a token in code: the algorithm is used at that site |
| `manifest-analysis` | 0.7 | a declared dependency: capability, usage unproven |

`identity.confidence` is still the maximum over its methods. `params` keeps its other
job — deciding which match may absorb a covered generic one — and no longer touches
scoring. Name specificity is carried by `name` and `cryptoProperties`, which is where a
consumer looks for it. Decision record: `docs/adr-0001-confidence-model.md`.

No schema change, no API change, no CLI change. Components previously at 0.7 because
their name had no parameter family now report 0.9 when seen in source; manifest-only
components stay at 0.7. A test asserts the invariant that matters: changing any
dictionary `params` value must not move a confidence value.

### Added: the sample BOM is regenerated from a pinned fixture, and CI proves it

`cbom-cyclonedx.json` was produced from a demo project that no longer exists and had
been frozen at 0.2.1 while the format changed under it — a checked-in artifact
describing behaviour the code no longer had. It is now generated from
`fixtures/sample-project/` with `SOURCE_DATE_EPOCH` pinned
(`scripts/gen-sample-cbom.cjs`), and `scripts/check-sample-cbom.cjs` fails CI when the
committed bytes differ from a fresh scan, naming the components that moved.

## 0.2.9 — 2026-11-16

### Added: the algorithm dictionary is complete and tested for drift

`algorithm-hierarchy.cjs` covered the NIST post-quantum families but not
most of what the legacy rules emit. A name with no entry still produced a
component, so the omission was invisible: it only lost generic/specific
absorption (`camellia-256-cbc` shipped as both `Camellia-256` and
`Camellia`) and dropped to 0.7 source confidence.

The dictionary now covers every name a rule can emit — classical hashes,
block ciphers, Poly1305, SM2/SM3/SM4, the classical public-key names and
the remaining PQC families — and `test/legacy-recall.test.cjs` asserts that
every rule resolves to both a metadata entry and a hierarchy entry. The
parameter values are read out of each rule's own capture group, so adding a
regex without a dictionary entry fails the gate instead of quietly weakening
the output.

### Fixed: `npm test` executed the fixtures instead of scanning them

`node --test` treats every file under `test/` as a test file, so
`test/fixtures/legacy/*.cjs` were run rather than scanned and threw on their
CBC initialization vectors. The fixtures a test needs to *scan* now live in
`fixtures/legacy/`, outside the directory the runner walks, and `npm test`
stays a plain `node --test`.

### Note: single-value algorithms keep a 0.7 source confidence

Source confidence is `params !== null ? 0.9 : 0.7`. MD5, RSA, DES and
friends have no parameter family, so they are dictionary entries with
`params: null` and stay at 0.7. That is the current model, not a
regression: 0.3.0 will decide whether such names deserve a non-null
marker or a separate rule.

## 0.2.8 — 2026-11-15

### Fixed: `exit 1` was unreachable for BOMs this tool produced

`classifyRisk()` decided how loud a new algorithm should be by reading
`cryptoProperties.assetType`. `cbom-scan` writes `"algorithm"` for every
component, that word matches no branch, and so every added algorithm fell
through to `warning`. `info` — and with it `exit 1` — could not be produced from
a CBOM this tool wrote itself (issue #183).

A gate written as "`1` passes, `2` blocks" therefore blocked the case it was
meant to allow: adopting a *new safe* algorithm looked identical to adopting a
weak one.

Grading now follows the algorithm, in this order:

1. `quantumSecurity:level = vulnerable` → `critical` (unchanged shortcut)
2. `quantumSecurity:level = weak` → `warning`
3. `algorithmProperties.primitive` — `kem`, `signature`, `hash`, `xof`,
   `block-cipher`, `aead`, `stream-cipher` → `info`; `key-agree`, `key-derive`,
   `key-wrap`, `other` → `warning`
4. fall back to `assetType`, then to the component name
5. anything unrecognised stays `warning`

`pke` is deliberately *not* an `info` primitive: RSA and ML-KEM-768 share it, and
the word alone cannot tell a safe addition from a vulnerable one. `vulnerable`
still short-circuits before any of this, so RSA cannot be graded quiet.

Tests: `test/classify-risk.test.cjs` (8 cases) covers each branch, including the
regression that `vulnerable` keeps winning over an `info`-looking primitive.

## 0.2.7 — 2026-11-11


### Breaking change: an invalid `--dir` is now an error

`cbom-scan --dir <path>` used to print an empty BOM and exit `0` when the path
did not exist or was not a directory. A pipeline reads an empty BOM as "this
tree contains no cryptography", so a typo in a path produced a clean, green
result — the exact false negative this tool exists to prevent.

It now exits `2` and writes `--dir not found` (or `not a directory`) to stderr.
Callers that relied on the old behaviour must either fix the path or treat `2`
as "the scan did not happen", not as "nothing found".

```diff
-  # exit 0, components: []
-  npx cbom-tools scan --dir ./typo-path --out cbom.json
+  # exit 2, stderr: --dir not found: ./typo-path
+  npx cbom-tools scan --dir ./typo-path --out cbom.json
```

### Added

- Names assembled out of literals are resolved before matching: adjacent
  concatenation (`'sha' + '256'`), array joins (`['ml','-kem'].join('')`),
  template interpolation (`` `ml-kem-${'768'}` ``), `Buffer.from(..., 'base64')`,
  `atob(...)`, and `\xNN` / `\uNNNN` escapes. Previously all of these were
  invisible, and an invisible algorithm still produces a clean-looking BOM.
- Receiver-agnostic patterns, so `createHash('sha-256')` and
  `createCipheriv('aes-256-gcm', ...)` are caught without hard-coding the API
  object name.
- Test suite: 83 → 122 tests. Ten evasion fixtures (one per hiding technique),
  one explicit negative control for names computed at runtime (asserted **not**
  detected — a static scan cannot see them, and the test says so), CLI
  dispatcher coverage for `cli.cjs`, and fault-tolerance cases.
- Coverage gate in CI: `npm run test:coverage` fails below 90% lines,
  90% functions, 80% branches. Measured: **96.5% lines, 97.4% functions,
  86.6% branches**.

### Changed

- Files larger than 8 MB are skipped with a warning instead of being read into
  memory.
- Unreadable files, unreadable directories and an unparsable `package.json`
  now warn on stderr and let the scan continue; previously the first two could
  abort the walk and the third threw.
- The literal resolver is a hand-written single-pass scanner rather than a set
  of regexes over raw source, so adversarial input cannot trigger backtracking.

### Fixed

- `cbom-diff --format markdown` printed `undefined` for a property absent on
  one side; it now prints `<absent>`.
